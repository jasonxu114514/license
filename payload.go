//go:build ignore

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

const expiresAtUnix int64 = __PAYLOAD_EXPIRES_AT_UNIX__
const expiredMessage = __PAYLOAD_EXPIRED_MESSAGE__
const payloadLicenseKey = __PAYLOAD_LICENSE_KEY__
const payloadArch = __PAYLOAD_ARCH__
const payloadDeviceID = __PAYLOAD_DEVICE_ID__
const payloadServerURL = __PAYLOAD_SERVER_URL__
const payloadTaskID = __PAYLOAD_TASK_ID__
const payloadUserAgent = __PAYLOAD_USER_AGENT__
const transportMarker = "LCX1:"
const transportTimeLayout = "200601021504"

var ipv4DNSServers = []string{
	"223.5.5.5:53",
	"1.1.1.1:53",
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
	if time.Now().UTC().Unix() >= expiresAtUnix {
		fmt.Fprintln(os.Stderr, expiredMessage)
		os.Exit(1)
	}

	deviceID := getDeviceID()
	if deviceID != payloadDeviceID {
		fmt.Fprintln(os.Stderr, "device_id mismatch")
		os.Exit(1)
	}

	runtimeInfo, err := fetchRuntimeValidation()
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime validation request failed: %v\n", err)
		os.Exit(1)
	}
	if runtimeInfo.LicenseKey != payloadLicenseKey {
		fmt.Fprintln(os.Stderr, "license key mismatch")
		os.Exit(1)
	}
	if runtimeInfo.ServerTime >= runtimeInfo.ExpiresAt || runtimeInfo.ServerTime >= expiresAtUnix {
		fmt.Fprintln(os.Stderr, expiredMessage)
		os.Exit(1)
	}

	selfSHA256, err := executableSHA256()
	if err != nil {
		fmt.Fprintf(os.Stderr, "self sha256 failed: %v\n", err)
		os.Exit(1)
	}
	if selfSHA256 != runtimeInfo.SHA256 {
		fmt.Fprintln(os.Stderr, "sha256 mismatch")
		os.Exit(1)
	}

	fmt.Println("Hello, world!")
	fmt.Println("License: " + payloadLicenseKey)
	fmt.Println("Arch: " + payloadArch)
	fmt.Println("DeviceID: " + payloadDeviceID)
}

func fetchRuntimeValidation() (*runtimeResponse, error) {
	httpClient := newHTTPClient(30 * time.Second)
	httpReq, err := http.NewRequest(
		http.MethodGet,
		strings.TrimRight(payloadServerURL, "/")+"/runtime/"+payloadTaskID,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build runtime request: %w", err)
	}
	httpReq.Header.Set("User-Agent", payloadUserAgent)

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("GET /runtime/%s: %w", payloadTaskID, err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("read runtime response body: %w", err)
	}
	decodedBody, err := decodeTransportPayload(respBody, time.Now().UTC())
	if err != nil {
		return nil, fmt.Errorf("decode encrypted runtime response: %w", err)
	}

	var resp runtimeResponse
	if err := json.Unmarshal(decodedBody, &resp); err != nil {
		return nil, fmt.Errorf("decode runtime response JSON: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return &resp, fmt.Errorf("server returned %s: %s", httpResp.Status, resp.Message)
	}
	if !resp.OK {
		return &resp, fmt.Errorf("%s", resp.Message)
	}

	return &resp, nil
}

func executableSHA256() (string, error) {
	exeProcPath := fmt.Sprintf("/proc/%d/exe", os.Getpid())

	file, err := os.Open(exeProcPath)
	if err != nil {
		file, err = os.Open("/proc/self/exe")
		if err != nil {
			exePath, pathErr := os.Executable()
			if pathErr != nil {
				return "", fmt.Errorf("os.Executable: %w", pathErr)
			}

			file, err = os.Open(exePath)
			if err != nil {
				return "", fmt.Errorf("open executable: %w", err)
			}
		}
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash executable: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
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

func newHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           newIPv4DialContext(),
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          8,
			IdleConnTimeout:       30 * time.Second,
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
		Timeout:   15 * time.Second,
		KeepAlive: 15 * time.Second,
		Resolver:  resolver,
	}

	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
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
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err == nil {
			parts = append(parts, hex.EncodeToString(randomBytes))
		} else {
			parts = append(parts, "fallback-device-id")
		}
	}

	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	id := hex.EncodeToString(sum[:])

	_ = os.WriteFile(path, []byte(id), 0o600)

	return id
}
