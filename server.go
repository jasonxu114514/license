//go:build server

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	_ "modernc.org/sqlite"
)

var (
	errInvalidLicense   = errors.New("invalid license key")
	errDeviceIDRequired = errors.New("device_id is required")
	errDeviceMismatch   = errors.New("device_id does not match bound device")
	errUnsupportedArch  = errors.New("unsupported arch")
	fileNameSanitizer   = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
)

const taskTTL = 5 * time.Minute
const userAgentPrivatePrefix = "LCPriv-7F3A9D2E"
const userAgentPrefix = "LicenseClient/1.0"
const transportMarker = "LCX1:"
const transportTimeLayout = "200601021504"

type licenseServer struct {
	db        *sql.DB
	outputDir string
	goBinary  string
	payloadGo string
	tasks     map[string]taskRecord
	mu        sync.Mutex
}

type licenseRecord struct {
	LicenseKey string
	DeviceID   sql.NullString
}

type taskRecord struct {
	TaskID     string
	LicenseKey string
	DeviceID   string
	Arch       string
	UserAgent  string
	FileName   string
	BinaryPath string
	SHA256     string
	ExpiresAt  time.Time
}

type verifyRequest struct {
	LicenseKey string `json:"license_key"`
	DeviceID   string `json:"device_id,omitempty"`
	Arch       string `json:"arch,omitempty"`
}

type verifyResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	TaskID  string `json:"task_id,omitempty"`
	Status  string `json:"status,omitempty"`
}

type taskResponse struct {
	OK          bool   `json:"ok"`
	Message     string `json:"message"`
	TaskID      string `json:"task_id,omitempty"`
	Status      string `json:"status,omitempty"`
	Arch        string `json:"arch,omitempty"`
	FileName    string `json:"file_name,omitempty"`
	DownloadURL string `json:"download_url,omitempty"`
}

type runtimeResponse struct {
	OK         bool   `json:"ok"`
	Message    string `json:"message"`
	TaskID     string `json:"task_id,omitempty"`
	LicenseKey string `json:"license_key,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	ServerTime int64  `json:"server_time,omitempty"`
	ExpiresAt  int64  `json:"expires_at,omitempty"`
}

func main() {
	runMain(os.Args[1:])
}

func runMain(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			runServer(args[1:])
			return
		case "add":
			runAddLicense(args[1:])
			return
		case "delete", "del", "remove":
			runDeleteLicense(args[1:])
			return
		case "list":
			runListLicenses(args[1:])
			return
		case "show":
			runShow(args[1:])
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}

	runServer(args)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  server [serve] [-listen :8080] [-db ./app.db] [-go go] [-payload ./payload.go]")
	fmt.Println("  server add <LICENSE_KEY> [-db ./app.db]")
	fmt.Println("  server add gen [-db ./app.db]")
	fmt.Println("  server del|delete <LICENSE_KEY> [-db ./app.db]")
	fmt.Println("  server list [-db ./app.db]")
	fmt.Println("  server show license <LICENSE_KEY> [-db ./app.db]")
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	listenAddr := fs.String("listen", ":8080", "listen address")
	dbPath := fs.String("db", "./app.db", "sqlite database path")
	goBinary := fs.String("go", "go", "go compiler path")
	payloadGo := fs.String("payload", "./payload.go", "payload Go template path")
	fs.Parse(args)

	db, absDBPath, err := openDatabase(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	absPayloadPath, err := filepath.Abs(*payloadGo)
	if err != nil {
		log.Fatalf("resolve payload path: %v", err)
	}

	s := &licenseServer{
		db:        db,
		outputDir: filepath.Dir(absDBPath),
		goBinary:  *goBinary,
		payloadGo: absPayloadPath,
		tasks:     make(map[string]taskRecord),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/verify", s.handleVerify)
	mux.HandleFunc("/task/", s.handleTask)
	mux.HandleFunc("/runtime/", s.handleRuntime)
	mux.HandleFunc("/download/", s.handleDownload)

	log.Printf("server listening on %s", *listenAddr)
	log.Printf("sqlite db: %s", absDBPath)
	log.Printf("payload template: %s", absPayloadPath)
	log.Printf("generated binaries will be placed in: %s", s.outputDir)

	handler := rejectDirectOrigin(logRequests(mux))
	if err := http.ListenAndServe(*listenAddr, handler); err != nil {
		log.Fatalf("listen and serve: %v", err)
	}
}

func runAddLicense(args []string) {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	dbPath := fs.String("db", "./app.db", "sqlite database path")
	licenseKey := fs.String("key", "", "license key")
	positionals := parseCLIArgs(fs, args)

	if strings.TrimSpace(*licenseKey) == "" && len(positionals) > 0 {
		*licenseKey = strings.TrimSpace(positionals[0])
	}

	generatedKey := false
	if strings.EqualFold(strings.TrimSpace(*licenseKey), "gen") {
		key, err := newLicenseKey()
		if err != nil {
			log.Fatalf("add license: generate key: %v", err)
		}
		*licenseKey = key
		generatedKey = true
	}

	if strings.TrimSpace(*licenseKey) == "" {
		log.Fatal("add license: license key is required")
	}

	db, absDBPath, err := openDatabase(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	_, err = db.Exec(
		`INSERT INTO licenses (license_key)
		 VALUES (?)
		 ON CONFLICT(license_key) DO NOTHING`,
		strings.TrimSpace(*licenseKey),
	)
	if err != nil {
		log.Fatalf("add license: %v", err)
	}

	log.Printf("license saved: key=%s db=%s",
		strings.TrimSpace(*licenseKey),
		absDBPath,
	)
	if generatedKey {
		fmt.Printf("generated_key: %s\n", strings.TrimSpace(*licenseKey))
	}
}

func runDeleteLicense(args []string) {
	fs := flag.NewFlagSet("delete", flag.ExitOnError)
	dbPath := fs.String("db", "./app.db", "sqlite database path")
	licenseKey := fs.String("key", "", "license key")
	positionals := parseCLIArgs(fs, args)

	if strings.TrimSpace(*licenseKey) == "" && len(positionals) > 0 {
		*licenseKey = strings.TrimSpace(positionals[0])
	}

	if strings.TrimSpace(*licenseKey) == "" {
		log.Fatal("delete license: license key is required")
	}

	db, absDBPath, err := openDatabase(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("delete license: begin transaction: %v", err)
	}
	defer tx.Rollback()

	result, err := tx.Exec(
		`DELETE FROM licenses WHERE license_key = ?`,
		strings.TrimSpace(*licenseKey),
	)
	if err != nil {
		log.Fatalf("delete license: %v", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.Fatalf("delete license rows affected: %v", err)
	}
	if rowsAffected == 0 {
		log.Fatalf("delete license: license key not found: %s", strings.TrimSpace(*licenseKey))
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("delete license: commit transaction: %v", err)
	}

	log.Printf("license deleted: key=%s db=%s", strings.TrimSpace(*licenseKey), absDBPath)
}

func runListLicenses(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dbPath := fs.String("db", "./app.db", "sqlite database path")
	fs.Parse(args)

	db, absDBPath, err := openDatabase(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(
		`SELECT license_key, last_seen_at, last_seen_ip, device_id
		 FROM licenses
		 ORDER BY license_key ASC`,
	)
	if err != nil {
		log.Fatalf("list licenses: %v", err)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LICENSE_KEY\tLAST_SEEN_AT\tLAST_SEEN_IP\tDEVICE_ID")

	found := false
	for rows.Next() {
		var licenseKey string
		var lastSeenAt sql.NullString
		var lastSeenIP sql.NullString
		var deviceID sql.NullString

		if err := rows.Scan(&licenseKey, &lastSeenAt, &lastSeenIP, &deviceID); err != nil {
			log.Fatalf("list licenses scan: %v", err)
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			licenseKey,
			nullableOrNone(lastSeenAt),
			nullableOrNone(lastSeenIP),
			nullableOrNone(deviceID),
		)
		found = true
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("list licenses rows: %v", err)
	}
	if err := w.Flush(); err != nil {
		log.Fatalf("list licenses flush: %v", err)
	}

	if !found {
		log.Printf("no licenses found: db=%s", absDBPath)
	}
}

func runShow(args []string) {
	if len(args) == 0 {
		log.Fatal("show: expected 'license'")
	}

	switch args[0] {
	case "license", "lic":
		runShowLicense(args[1:])
	default:
		log.Fatalf("show: unsupported target: %s", args[0])
	}
}

func runShowLicense(args []string) {
	fs := flag.NewFlagSet("show license", flag.ExitOnError)
	dbPath := fs.String("db", "./app.db", "sqlite database path")
	licenseKey := fs.String("key", "", "license key")
	positionals := parseCLIArgs(fs, args)

	if strings.TrimSpace(*licenseKey) == "" && len(positionals) > 0 {
		*licenseKey = strings.TrimSpace(positionals[0])
	}

	if strings.TrimSpace(*licenseKey) == "" {
		log.Fatal("show license: license key is required")
	}

	db, absDBPath, err := openDatabase(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	var lastSeenAt sql.NullString
	var lastSeenIP sql.NullString
	var deviceID sql.NullString

	err = db.QueryRow(
		`SELECT last_seen_at, last_seen_ip, device_id
		 FROM licenses
		 WHERE license_key = ?`,
		strings.TrimSpace(*licenseKey),
	).Scan(&lastSeenAt, &lastSeenIP, &deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		log.Fatalf("show license: license key not found: %s", strings.TrimSpace(*licenseKey))
	}
	if err != nil {
		log.Fatalf("show license: %v", err)
	}

	fmt.Printf("type: license\n")
	fmt.Printf("db: %s\n", absDBPath)
	fmt.Printf("license_key: %s\n", strings.TrimSpace(*licenseKey))
	fmt.Printf("last_seen_at: %s\n", nullableOrNone(lastSeenAt))
	fmt.Printf("last_seen_ip: %s\n", nullableOrNone(lastSeenIP))
	fmt.Printf("device_id: %s\n", nullableOrNone(deviceID))
}

func openDatabase(dbPath string) (*sql.DB, string, error) {
	absDBPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, "", fmt.Errorf("resolve db path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(absDBPath), 0o755); err != nil {
		return nil, "", fmt.Errorf("create db directory: %w", err)
	}

	db, err := sql.Open("sqlite", absDBPath)
	if err != nil {
		return nil, "", fmt.Errorf("open sqlite database: %w", err)
	}

	if err := initDB(db); err != nil {
		db.Close()
		return nil, "", fmt.Errorf("init database: %w", err)
	}

	if err := migrateLicensesTrackingColumns(db); err != nil {
		db.Close()
		return nil, "", fmt.Errorf("migrate licenses tracking: %w", err)
	}

	return db, absDBPath, nil
}

func parseCLIArgs(fs *flag.FlagSet, args []string) []string {
	leading, remaining := splitLeadingPositionals(args)
	fs.Parse(remaining)
	return append(leading, fs.Args()...)
}

func splitLeadingPositionals(args []string) ([]string, []string) {
	index := 0
	for index < len(args) {
		if strings.HasPrefix(args[index], "-") {
			break
		}
		index++
	}
	return args[:index], args[index:]
}

func normalizeArch(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "amd64", "x86_64":
		return "amd64", nil
	case "arm64", "aarch64":
		return "arm64", nil
	default:
		return "", fmt.Errorf("%w: %s", errUnsupportedArch, value)
	}
}

func nullableOrNone(value sql.NullString) string {
	if !value.Valid || strings.TrimSpace(value.String) == "" {
		return "none"
	}
	return value.String
}

func initDB(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS licenses (
			license_key TEXT PRIMARY KEY,
			last_seen_at TEXT,
			last_seen_ip TEXT,
			device_id TEXT
		);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}

	return nil
}

func migrateLicensesTrackingColumns(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(licenses)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	hasLastSeenAt := false
	hasLastSeenIP := false
	hasDeviceID := false
	hasLastDeviceID := false
	for rows.Next() {
		var cid int
		var name string
		var dataType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, "last_seen_at") {
			hasLastSeenAt = true
		}
		if strings.EqualFold(name, "last_seen_ip") {
			hasLastSeenIP = true
		}
		if strings.EqualFold(name, "device_id") {
			hasDeviceID = true
		}
		if strings.EqualFold(name, "last_device_id") {
			hasLastDeviceID = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasLastSeenAt {
		if _, err := db.Exec(`ALTER TABLE licenses ADD COLUMN last_seen_at TEXT`); err != nil {
			return err
		}
	}
	if !hasLastSeenIP {
		if _, err := db.Exec(`ALTER TABLE licenses ADD COLUMN last_seen_ip TEXT`); err != nil {
			return err
		}
	}
	if !hasDeviceID {
		if _, err := db.Exec(`ALTER TABLE licenses ADD COLUMN device_id TEXT`); err != nil {
			return err
		}
	}
	if hasLastDeviceID {
		if _, err := db.Exec(`UPDATE licenses SET device_id = COALESCE(device_id, last_device_id) WHERE device_id IS NULL AND last_device_id IS NOT NULL`); err != nil {
			return err
		}
	}
	return nil
}

func (s *licenseServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeEncryptedJSON(w, http.StatusMethodNotAllowed, verifyResponse{
			OK:      false,
			Message: "only POST is allowed",
		})
		return
	}

	var req verifyRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeEncryptedJSON(w, http.StatusBadRequest, verifyResponse{
			OK:      false,
			Message: "read request body failed",
		})
		return
	}

	decodedBody, err := decodeTransportPayload(body, time.Now().UTC())
	if err != nil {
		writeEncryptedJSON(w, http.StatusBadRequest, verifyResponse{
			OK:      false,
			Message: "invalid encrypted body",
		})
		return
	}

	if err := json.Unmarshal(decodedBody, &req); err != nil {
		writeEncryptedJSON(w, http.StatusBadRequest, verifyResponse{
			OK:      false,
			Message: "invalid JSON body",
		})
		return
	}

	req.LicenseKey = strings.TrimSpace(req.LicenseKey)
	req.DeviceID = strings.TrimSpace(req.DeviceID)

	if req.LicenseKey == "" {
		log.Printf("verify denied ip=%s path=%s reason=%q", valueOrDefault(requestIP(r), "-"), r.URL.Path, "license_key is required")
		writeEncryptedJSON(w, http.StatusBadRequest, verifyResponse{
			OK:      false,
			Message: "license_key is required",
		})
		return
	}

	s.mu.Lock()
	task, err := s.verifyAndCreateTask(r.Context(), req, requestIP(r), requestBaseURL(r))
	s.mu.Unlock()
	if err != nil {
		status := http.StatusInternalServerError
		message := err.Error()

		switch {
		case errors.Is(err, errInvalidLicense):
			status = http.StatusUnauthorized
			message = "license key is invalid"
		case errors.Is(err, errDeviceIDRequired):
			status = http.StatusBadRequest
			message = "device_id is required"
		case errors.Is(err, errDeviceMismatch):
			status = http.StatusForbidden
			message = "device_id mismatch"
		case errors.Is(err, errUnsupportedArch):
			status = http.StatusBadRequest
			message = "unsupported arch"
		}

		log.Printf("verify denied ip=%s path=%s reason=%q", valueOrDefault(requestIP(r), "-"), r.URL.Path, message)

		writeEncryptedJSON(w, status, verifyResponse{
			OK:      false,
			Message: message,
		})
		return
	}

	writeEncryptedJSON(w, http.StatusOK, verifyResponse{
		OK:      true,
		Message: "verification passed",
		TaskID:  task.TaskID,
		Status:  "ready",
	})
	log.Printf("verify ok ip=%s path=%s task_id=%s", valueOrDefault(requestIP(r), "-"), r.URL.Path, task.TaskID)
}

func (s *licenseServer) verifyAndCreateTask(ctx context.Context, req verifyRequest, ip string, baseURL string) (taskRecord, error) {
	license, err := s.getLicense(req.LicenseKey)
	if err != nil {
		return taskRecord{}, err
	}
	if strings.TrimSpace(req.DeviceID) == "" {
		return taskRecord{}, errDeviceIDRequired
	}
	if license.DeviceID.Valid && strings.TrimSpace(license.DeviceID.String) != "" && strings.TrimSpace(license.DeviceID.String) != strings.TrimSpace(req.DeviceID) {
		return taskRecord{}, errDeviceMismatch
	}

	arch, err := normalizeArch(req.Arch)
	if err != nil {
		return taskRecord{}, err
	}

	if err := s.updateTracking(ctx, license.LicenseKey, ip, req.DeviceID); err != nil {
		return taskRecord{}, fmt.Errorf("update tracking: %w", err)
	}

	expiresAt := time.Now().UTC().Add(taskTTL)
	userAgent := buildUserAgent(req.DeviceID, arch)
	taskID, fileName, binaryPath, err := s.generateTaskBinary(ctx, license, req.DeviceID, arch, userAgent, baseURL, expiresAt)
	if err != nil {
		return taskRecord{}, fmt.Errorf("generate task binary: %w", err)
	}
	binarySHA256, err := sha256File(binaryPath)
	if err != nil {
		return taskRecord{}, fmt.Errorf("sha256 binary: %w", err)
	}

	task := taskRecord{
		TaskID:     taskID,
		LicenseKey: license.LicenseKey,
		DeviceID:   req.DeviceID,
		Arch:       arch,
		UserAgent:  userAgent,
		FileName:   fileName,
		BinaryPath: binaryPath,
		SHA256:     binarySHA256,
		ExpiresAt:  expiresAt,
	}
	s.tasks[taskID] = task

	return task, nil
}

func (s *licenseServer) handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeEncryptedJSON(w, http.StatusMethodNotAllowed, taskResponse{
			OK:      false,
			Message: "only GET is allowed",
		})
		return
	}

	taskID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/task/"))
	if taskID == "" {
		writeEncryptedJSON(w, http.StatusNotFound, taskResponse{
			OK:      false,
			Message: "task not found",
		})
		return
	}

	s.mu.Lock()
	task, ok := s.tasks[taskID]
	s.mu.Unlock()
	if !ok {
		writeEncryptedJSON(w, http.StatusNotFound, taskResponse{
			OK:      false,
			Message: "task not found",
			TaskID:  taskID,
		})
		return
	}
	if s.expireTaskIfNeeded(taskID, task) {
		writeEncryptedJSON(w, http.StatusGone, taskResponse{
			OK:      false,
			Message: "task expired",
			TaskID:  taskID,
			Status:  "expired",
		})
		return
	}

	writeEncryptedJSON(w, http.StatusOK, taskResponse{
		OK:          true,
		Message:     "task is ready",
		TaskID:      taskID,
		Status:      "ready",
		Arch:        task.Arch,
		FileName:    task.FileName,
		DownloadURL: fmt.Sprintf("%s/download/%s", requestBaseURL(r), taskID),
	})
}

func (s *licenseServer) handleRuntime(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeEncryptedJSON(w, http.StatusMethodNotAllowed, runtimeResponse{
			OK:      false,
			Message: "only GET is allowed",
		})
		return
	}

	taskID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/runtime/"))
	if taskID == "" {
		writeEncryptedJSON(w, http.StatusNotFound, runtimeResponse{
			OK:      false,
			Message: "task not found",
		})
		return
	}

	s.mu.Lock()
	task, ok := s.tasks[taskID]
	s.mu.Unlock()
	if !ok {
		writeEncryptedJSON(w, http.StatusNotFound, runtimeResponse{
			OK:      false,
			Message: "task not found",
			TaskID:  taskID,
		})
		return
	}
	if s.expireTaskIfNeeded(taskID, task) {
		writeEncryptedJSON(w, http.StatusGone, runtimeResponse{
			OK:      false,
			Message: "task expired",
			TaskID:  taskID,
		})
		return
	}

	writeEncryptedJSON(w, http.StatusOK, runtimeResponse{
		OK:         true,
		Message:    "runtime validation data ready",
		TaskID:     task.TaskID,
		LicenseKey: task.LicenseKey,
		SHA256:     task.SHA256,
		ServerTime: time.Now().UTC().Unix(),
		ExpiresAt:  task.ExpiresAt.UTC().Unix(),
	})
}

func (s *licenseServer) getLicense(licenseKey string) (licenseRecord, error) {
	var rec licenseRecord

	err := s.db.QueryRow(
		`SELECT license_key, device_id
		 FROM licenses
		 WHERE license_key = ?`,
		licenseKey,
	).Scan(
		&rec.LicenseKey,
		&rec.DeviceID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return licenseRecord{}, errInvalidLicense
	}
	if err != nil {
		return licenseRecord{}, fmt.Errorf("query license: %w", err)
	}

	return rec, nil
}

func (s *licenseServer) updateTracking(ctx context.Context, licenseKey string, ip string, deviceID string) error {
	var ipValue any
	if strings.TrimSpace(ip) != "" {
		ipValue = strings.TrimSpace(ip)
	}

	deviceIDValue := strings.TrimSpace(deviceID)

	_, err := s.db.ExecContext(
		ctx,
		`UPDATE licenses
		 SET last_seen_at = CURRENT_TIMESTAMP,
		     last_seen_ip = ?,
		     device_id = CASE
		       WHEN device_id IS NULL OR TRIM(device_id) = '' THEN ?
		       ELSE device_id
		     END
		 WHERE license_key = ?`,
		ipValue,
		deviceIDValue,
		licenseKey,
	)
	return err
}

func (s *licenseServer) expireTaskIfNeeded(taskID string, task taskRecord) bool {
	if time.Now().UTC().Before(task.ExpiresAt) {
		return false
	}

	if strings.TrimSpace(task.BinaryPath) != "" {
		if err := os.Remove(task.BinaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("remove expired task binary failed: task_id=%s path=%s err=%v", taskID, task.BinaryPath, err)
		}
	}

	s.mu.Lock()
	delete(s.tasks, taskID)
	s.mu.Unlock()
	return true
}

func buildUserAgent(deviceID string, arch string) string {
	shortDeviceID := strings.TrimSpace(deviceID)
	if len(shortDeviceID) > 16 {
		shortDeviceID = shortDeviceID[:16]
	}

	return fmt.Sprintf("%s %s (linux; %s; did/%s)",
		userAgentPrivatePrefix,
		userAgentPrefix,
		valueOrDefault(strings.TrimSpace(arch), "unknown"),
		valueOrDefault(shortDeviceID, "unknown"),
	)
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func transportKey(now time.Time) []byte {
	sum := sha256.Sum256([]byte(now.UTC().Format(transportTimeLayout)))
	return sum[:]
}

func transportTimeString(now time.Time) string {
	return now.UTC().Format(transportTimeLayout)
}

func xorWithKey(data []byte, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func encodeTransportPayload(payload []byte, now time.Time) ([]byte, error) {
	minute := transportTimeString(now)
	inner := base64.StdEncoding.EncodeToString(payload)
	cipher := xorWithKey([]byte(inner), transportKey(now))
	outer := base64.StdEncoding.EncodeToString(cipher)
	return []byte(transportMarker + minute + ":" + outer), nil
}

func decodeTransportPayload(raw []byte, now time.Time) ([]byte, error) {
	text := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(text, transportMarker) {
		return nil, fmt.Errorf("transport marker mismatch")
	}

	rest := strings.TrimPrefix(text, transportMarker)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("transport format invalid")
	}

	minute := strings.TrimSpace(parts[0])
	if len(minute) != len(transportTimeLayout) {
		return nil, fmt.Errorf("transport minute invalid")
	}

	parsedMinute, err := time.ParseInLocation(transportTimeLayout, minute, time.UTC)
	if err != nil {
		return nil, fmt.Errorf("transport minute parse failed: %w", err)
	}
	if !transportTimeAllowed(parsedMinute, now.UTC()) {
		return nil, fmt.Errorf("transport minute out of window")
	}

	outer, err := base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
	if err != nil {
		return nil, err
	}

	plain := string(xorWithKey(outer, transportKey(parsedMinute)))
	return base64.StdEncoding.DecodeString(plain)
}

func transportTimeAllowed(messageTime time.Time, now time.Time) bool {
	diff := now.Sub(messageTime)
	if diff < 0 {
		diff = -diff
	}
	return diff <= time.Minute
}

func (s *licenseServer) renderPayloadSource(task taskRecord, serverURL string, expiresAt time.Time) ([]byte, error) {
	templateBytes, err := os.ReadFile(s.payloadGo)
	if err != nil {
		return nil, fmt.Errorf("read payload template: %w", err)
	}

	replacements := map[string]string{
		"__PAYLOAD_EXPIRES_AT_UNIX__": fmt.Sprintf("%d", expiresAt.UTC().Unix()),
		"__PAYLOAD_EXPIRED_MESSAGE__": fmt.Sprintf("%q", "expired: binary must be executed within 5 minutes after build"),
		"__PAYLOAD_LICENSE_KEY__":     fmt.Sprintf("%q", task.LicenseKey),
		"__PAYLOAD_ARCH__":            fmt.Sprintf("%q", task.Arch),
		"__PAYLOAD_DEVICE_ID__":       fmt.Sprintf("%q", task.DeviceID),
		"__PAYLOAD_SERVER_URL__":      fmt.Sprintf("%q", strings.TrimRight(serverURL, "/")),
		"__PAYLOAD_TASK_ID__":         fmt.Sprintf("%q", task.TaskID),
		"__PAYLOAD_USER_AGENT__":      fmt.Sprintf("%q", task.UserAgent),
	}

	source := string(templateBytes)
	for oldValue, newValue := range replacements {
		source = strings.ReplaceAll(source, oldValue, newValue)
	}

	return []byte(source), nil
}

func (s *licenseServer) generateTaskBinary(ctx context.Context, license licenseRecord, deviceID string, arch string, userAgent string, serverURL string, expiresAt time.Time) (taskID, fileName, binaryPath string, err error) {
	taskID, err = newTaskID()
	if err != nil {
		return "", "", "", err
	}

	tempDir, err := os.MkdirTemp("", "license-hello-task-*")
	if err != nil {
		return "", "", "", fmt.Errorf("create temp task dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	fileName = fmt.Sprintf("task_%s_%s_hello_%s", taskID, arch, sanitizeForFileName(license.LicenseKey))
	binaryPath = filepath.Join(s.outputDir, fileName)
	binaryPath, err = filepath.Abs(binaryPath)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve binary path: %w", err)
	}

	sourcePath := filepath.Join(tempDir, "main.go")
	task := taskRecord{
		TaskID:     taskID,
		LicenseKey: license.LicenseKey,
		DeviceID:   deviceID,
		Arch:       arch,
		UserAgent:  userAgent,
		FileName:   fileName,
		BinaryPath: binaryPath,
		ExpiresAt:  expiresAt,
	}
	source, err := s.renderPayloadSource(task, serverURL, expiresAt)
	if err != nil {
		return "", "", "", fmt.Errorf("render payload source: %w", err)
	}

	if err := os.WriteFile(sourcePath, source, 0o644); err != nil {
		return "", "", "", fmt.Errorf("write Go source: %w", err)
	}

	taskCmd := exec.CommandContext(
		ctx,
		s.goBinary,
		"build",
		"-trimpath",
		"-ldflags",
		"-s -w",
		"-o",
		binaryPath,
		sourcePath,
	)
	taskCmd.Env = append(os.Environ(),
		"GOOS=linux",
		"GOARCH="+arch,
		"CGO_ENABLED=0",
	)
	taskCmd.Dir = tempDir

	output, err := taskCmd.CombinedOutput()
	if err != nil {
		return "", "", "", fmt.Errorf("go build failed: %w, output: %s", err, strings.TrimSpace(string(output)))
	}

	if err := os.Chmod(binaryPath, 0o755); err != nil {
		return "", "", "", fmt.Errorf("chmod binary: %w", err)
	}

	return taskID, fileName, binaryPath, nil
}

func (s *licenseServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeEncryptedJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"ok":      false,
			"message": "only GET is allowed",
		})
		return
	}

	taskID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/download/"))
	if taskID == "" {
		writeEncryptedJSON(w, http.StatusNotFound, map[string]any{
			"ok":      false,
			"message": "task not found",
		})
		return
	}

	s.mu.Lock()
	task, ok := s.tasks[taskID]
	s.mu.Unlock()
	if !ok {
		writeEncryptedJSON(w, http.StatusNotFound, map[string]any{
			"ok":      false,
			"message": "task not found",
			"task_id": taskID,
		})
		return
	}
	if s.expireTaskIfNeeded(taskID, task) {
		writeEncryptedJSON(w, http.StatusGone, map[string]any{
			"ok":      false,
			"message": "task expired",
		})
		return
	}
	if strings.TrimSpace(task.BinaryPath) == "" {
		writeEncryptedJSON(w, http.StatusGone, map[string]any{
			"ok":      false,
			"message": "binary already downloaded",
		})
		return
	}

	file, err := os.Open(task.BinaryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.mu.Lock()
			delete(s.tasks, taskID)
			s.mu.Unlock()
			writeEncryptedJSON(w, http.StatusNotFound, map[string]any{
				"ok":      false,
				"message": "task not found",
				"task_id": taskID,
			})
			return
		}
		writeEncryptedJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":      false,
			"message": "open binary failed",
		})
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		writeEncryptedJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":      false,
			"message": "stat binary failed",
		})
		return
	}

	_ = info
	binaryData, err := io.ReadAll(file)
	if err != nil {
		writeEncryptedJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":      false,
			"message": "read binary failed",
		})
		return
	}

	writeEncryptedBytes(w, http.StatusOK, binaryData)

	if err := os.Remove(task.BinaryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("remove task binary failed: task_id=%s path=%s err=%v", taskID, task.BinaryPath, err)
	}

	task.BinaryPath = ""
	s.mu.Lock()
	s.tasks[taskID] = task
	s.mu.Unlock()
}

func newTaskID() (string, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405"), hex.EncodeToString(raw[:])), nil
}

func newLicenseKey() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	return fmt.Sprintf("LIC-%s-%s",
		time.Now().UTC().Format("20060102"),
		strings.ToUpper(hex.EncodeToString(raw[:])),
	), nil
}

func sanitizeForFileName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "user"
	}

	value = strings.ToLower(value)
	value = fileNameSanitizer.ReplaceAllString(value, "_")
	value = strings.Trim(value, "._-")
	if value == "" {
		return "user"
	}

	return value
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("write JSON response failed: %v", err)
	}
}

func writeEncryptedJSON(w http.ResponseWriter, status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":      false,
			"message": "marshal encrypted response failed",
		})
		return
	}
	writeEncryptedBytes(w, status, raw)
}

func writeEncryptedBytes(w http.ResponseWriter, status int, body []byte) {
	encoded, err := encodeTransportPayload(body, time.Now().UTC())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"ok":      false,
			"message": "encode encrypted response failed",
		})
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	if _, err := w.Write(encoded); err != nil {
		log.Printf("write encrypted response failed: %v", err)
	}
}

func requestBaseURL(r *http.Request) string {
	scheme := r.Header.Get("X-Forwarded-Proto")
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func requestIP(r *http.Request) string {
	if forwardedFor := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwardedFor != "" {
		parts := strings.Split(forwardedFor, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

func rejectDirectOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isLocalRequest(r) || strings.TrimSpace(requestIP(r)) != "" {
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("origin bypass rejected remote=%s host=%s method=%s path=%s", strings.TrimSpace(r.RemoteAddr), strings.TrimSpace(r.Host), r.Method, r.URL.Path)
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

func isLocalRequest(r *http.Request) bool {
	host := strings.ToLower(strings.TrimSpace(r.Host))
	switch {
	case host == "localhost",
		strings.HasPrefix(host, "localhost:"),
		host == "127.0.0.1",
		strings.HasPrefix(host, "127.0.0.1:"),
		host == "[::1]",
		strings.HasPrefix(host, "[::1]:"):
		return true
	default:
		return false
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		ip := requestIP(r)
		if strings.TrimSpace(ip) == "" {
			ip = strings.TrimSpace(r.RemoteAddr)
		}
		log.Printf("%s %s ip=%s status=%d dur=%s", r.Method, r.URL.Path, ip, rec.status, time.Since(start))
	})
}
