//go:build client && linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const DefaultServerURL = "http://127.0.0.1:8080"

var ipv4DNSServers = []string{
	"223.5.5.5:53",
	"1.1.1.1:53",
}

const userAgentPrivatePrefix = "LCPriv-7F3A9D2E"
const userAgentPrefix = "LicenseClient/1.0"
const transportMarker = "LCX1:"
const transportTimeLayout = "200601021504"

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

func main() {
	runClient(os.Args[1:])
}

func runClient(args []string) {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	serverURL := fs.String("server", DefaultServerURL, "server base url")
	licenseKeyFlag := fs.String("key", "", "license key")
	fs.Parse(args)

	reader := bufio.NewReader(os.Stdin)

	if strings.Contains(*serverURL, "YOUR_SERVER_URL_HERE") {
		inputServerURL, err := prompt(reader, "Enter server URL: ")
		if err != nil {
			exitWithError("failed to read server url", err)
		}
		*serverURL = strings.TrimSpace(inputServerURL)
	}
	if strings.TrimSpace(*serverURL) == "" {
		exitWithError("invalid server url", fmt.Errorf("server url is empty"))
	}

	licenseKey := strings.TrimSpace(*licenseKeyFlag)
	if licenseKey == "" {
		var err error
		licenseKey, err = prompt(reader, "Enter license key: ")
		if err != nil {
			exitWithError("failed to read license key", err)
		}
	}
	if strings.TrimSpace(licenseKey) == "" {
		exitWithError("invalid license key", fmt.Errorf("license key is empty"))
	}

	req := verifyRequest{
		LicenseKey: strings.TrimSpace(licenseKey),
		DeviceID:   getDeviceID(),
		Arch:       runtime.GOARCH,
	}
	userAgent := buildUserAgent(req.DeviceID, req.Arch)

	resp, err := verify(*serverURL, req, userAgent)
	if err != nil {
		exitWithError("verification request failed", err)
	}
	if !resp.OK {
		exitWithError("server returned failure", fmt.Errorf(resp.Message))
	}
	if strings.TrimSpace(resp.TaskID) == "" {
		exitWithError("server returned failure", fmt.Errorf("task_id is empty"))
	}

	task, err := queryTask(*serverURL, resp.TaskID, userAgent)
	if err != nil {
		exitWithError("task query failed", err)
	}
	if !task.OK {
		exitWithError("server returned failure", fmt.Errorf(task.Message))
	}
	if task.DownloadURL == "" {
		exitWithError("server returned failure", fmt.Errorf("download_url is empty"))
	}

	binaryData, err := downloadBinary(task.DownloadURL, userAgent)
	if err != nil {
		exitWithError("failed to download personalized binary", err)
	}

	fmt.Printf("Task ID: %s\n", task.TaskID)
	if strings.TrimSpace(task.Arch) != "" {
		fmt.Printf("Arch: %s\n", task.Arch)
	}
	fmt.Println("Launching from memfd...")

	if err := execFromMemfd(binaryData, task.FileName); err != nil {
		exitWithError("failed to execute downloaded binary from memfd", err)
	}
}

func verify(serverURL string, req verifyRequest, userAgent string) (*verifyResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}
	encodedBody, err := encodeTransportPayload(body, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	httpClient := newHTTPClient(2 * time.Minute)
	httpReq, err := http.NewRequest(
		http.MethodPost,
		strings.TrimRight(serverURL, "/")+"/verify",
		bytes.NewReader(encodedBody),
	)
	if err != nil {
		return nil, fmt.Errorf("build POST /verify request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "text/plain")
	httpReq.Header.Set("User-Agent", userAgent)

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST /verify: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	decodedBody, err := decodeTransportPayload(respBody, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("decode encrypted response: %w", err)
	}

	var resp verifyResponse
	if err := json.Unmarshal(decodedBody, &resp); err != nil {
		return nil, fmt.Errorf("decode response JSON: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return &resp, fmt.Errorf("server returned %s: %s", httpResp.Status, resp.Message)
	}

	return &resp, nil
}

func queryTask(serverURL string, taskID string, userAgent string) (*taskResponse, error) {
	httpClient := newHTTPClient(2 * time.Minute)
	httpReq, err := http.NewRequest(
		http.MethodGet,
		strings.TrimRight(serverURL, "/")+"/task/"+taskID,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build GET /task/%s request: %w", taskID, err)
	}
	httpReq.Header.Set("User-Agent", userAgent)
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GET /task/%s: %w", taskID, err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	decodedBody, err := decodeTransportPayload(respBody, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("decode encrypted response: %w", err)
	}

	var resp taskResponse
	if err := json.Unmarshal(decodedBody, &resp); err != nil {
		return nil, fmt.Errorf("decode response JSON: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return &resp, fmt.Errorf("server returned %s: %s", httpResp.Status, resp.Message)
	}

	return &resp, nil
}

func downloadBinary(url string, userAgent string) ([]byte, error) {
	httpClient := newHTTPClient(5 * time.Minute)
	httpReq, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build download request: %w", err)
	}
	httpReq.Header.Set("User-Agent", userAgent)

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GET download url: %w", err)
	}
	defer httpResp.Body.Close()

	data, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read downloaded binary: %w", err)
	}
	data, err = decodeTransportPayload(data, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("decode encrypted binary: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with %s: %s", httpResp.Status, strings.TrimSpace(string(data)))
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("downloaded binary is empty")
	}

	return data, nil
}

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           newIPv4DialContext(),
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func newIPv4DialContext() func(context.Context, string, string) (net.Conn, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			var lastErr error
			for _, server := range ipv4DNSServers {
				conn, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp4", server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no dns servers configured")
			}
			return nil, lastErr
		},
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}

	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
}

func execFromMemfd(binaryData []byte, fileName string) error {
	fd, err := memfdCreate(valueOrDefault(strings.TrimSpace(fileName), "license-task"))
	if err != nil {
		return err
	}

	file := os.NewFile(uintptr(fd), "memfd-exec")
	defer file.Close()

	if err := file.Chmod(0o700); err != nil {
		return fmt.Errorf("chmod memfd: %w", err)
	}

	if _, err := io.Copy(file, bytes.NewReader(binaryData)); err != nil {
		return fmt.Errorf("write memfd: %w", err)
	}

	path := fmt.Sprintf("/proc/self/fd/%d", fd)
	argv0 := valueOrDefault(strings.TrimSpace(fileName), "license-task")
	if err := syscall.Exec(path, []string{argv0}, os.Environ()); err != nil {
		return fmt.Errorf("exec memfd: %w", err)
	}

	return nil
}

func memfdCreate(name string) (int, error) {
	fd, err := memfdCreateWithFlags(name, unix.MFD_CLOEXEC|unix.MFD_EXEC)
	if err == nil {
		return fd, nil
	}

	if err == unix.EINVAL {
		fd, fallbackErr := memfdCreateWithFlags(name, unix.MFD_CLOEXEC)
		if fallbackErr == nil {
			return fd, nil
		}
		return -1, fmt.Errorf("memfd_create fallback: %w", fallbackErr)
	}

	return -1, fmt.Errorf("memfd_create: %w", err)
}

func memfdCreateWithFlags(name string, flags int) (int, error) {
	fd, err := unix.MemfdCreate(name, flags)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func prompt(reader *bufio.Reader, label string) (string, error) {
	fmt.Print(label)
	text, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func exitWithError(prefix string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
	os.Exit(1)
}

func valueOrDefault(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
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

func getDeviceID() string {
	const path = "/data/adb/.deviceid"

	if b, err := os.ReadFile(path); err == nil {
		id := strings.TrimSpace(string(b))
		if id != "" {
			return id
		}
	}

	props := []string{
		"ro.serialno",
		"ro.boot.serialno",
		"ro.product.brand",
		"ro.product.model",
		"ro.product.board",
		"ro.product.cpu.abi",
	}

	var parts []string

	for _, p := range props {
		out, err := exec.Command("getprop", p).Output()
		if err != nil {
			continue
		}

		v := strings.TrimSpace(string(out))
		if v != "" && v != "unknown" {
			parts = append(parts, v)
		}
	}

	if h, err := os.Hostname(); err == nil {
		parts = append(parts, h)
	}

	if len(parts) == 0 {
		parts = append(parts, uuid.New().String())
	}

	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	id := hex.EncodeToString(sum[:])

	_ = os.WriteFile(path, []byte(id), 0o600)

	return id
}
