package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/betterleaks/betterleaks/report"
)

// testSecret is assembled at runtime so no literal token sits in the repo.
var testSecret = "ghp_" + "x9Kd2LmQ7vRt4Yp8" + "Zs1Wn6Bc3Hf5Jg0Aa2Ee"

var (
	realScannerOnce sync.Once
	realScanner     *BetterleaksScanner
	realScannerErr  error
)

func newRealHandler(t *testing.T, opts Options) http.Handler {
	t.Helper()
	realScannerOnce.Do(func() {
		realScanner, realScannerErr = NewBetterleaksScanner(context.Background())
	})
	if realScannerErr != nil {
		t.Fatalf("NewBetterleaksScanner: %v", realScannerErr)
	}
	opts.Logger = discardLogger()
	return New(realScanner, opts)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeScanner struct {
	findings []report.Finding
	err      error
	// scan, when set, replaces the canned result.
	scan func(ctx context.Context) ([]report.Finding, error)
}

func (f fakeScanner) Scan(ctx context.Context, _, _ string) ([]report.Finding, error) {
	if f.scan != nil {
		return f.scan(ctx)
	}
	return f.findings, f.err
}

func (f fakeScanner) Rules() []Rule { return nil }

func scanBody(t *testing.T, req scanRequest) string {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func do(h http.Handler, method, target, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1:8080"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestHealthz(t *testing.T) {
	rec := do(newRealHandler(t, Options{}), http.MethodGet, "/healthz", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := decode[map[string]string](t, rec)["status"]; got != "ok" {
		t.Fatalf("status field = %q, want ok", got)
	}
}

func TestRules(t *testing.T) {
	rec := do(newRealHandler(t, Options{}), http.MethodGet, "/v1/rules", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	resp := decode[rulesResponse](t, rec)
	if resp.Count == 0 || resp.Count != len(resp.Rules) {
		t.Fatalf("count = %d, len(rules) = %d", resp.Count, len(resp.Rules))
	}
	for i := 1; i < len(resp.Rules); i++ {
		if resp.Rules[i-1].ID >= resp.Rules[i].ID {
			t.Fatalf("rules not sorted: %q before %q", resp.Rules[i-1].ID, resp.Rules[i].ID)
		}
	}
	if strings.Contains(rec.Body.String(), `"tags":null`) {
		t.Fatal("tags must be [] rather than null")
	}
}

func TestRulesNilIsEmptyArray(t *testing.T) {
	rec := do(New(fakeScanner{}, Options{Logger: discardLogger()}), http.MethodGet, "/v1/rules", "", "")
	if !strings.Contains(rec.Body.String(), `"rules":[]`) {
		t.Fatalf("body = %s, want empty rules array", rec.Body.String())
	}
}

func TestScanFindsSecret(t *testing.T) {
	body := scanBody(t, scanRequest{Content: "line one\ntoken = \"" + testSecret + "\"\n", Path: "conf/app.env"})
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resp := decode[scanResponse](t, rec)
	if resp.Count != 1 || len(resp.Findings) != 1 {
		t.Fatalf("count = %d, findings = %d, want 1", resp.Count, len(resp.Findings))
	}
	f := resp.Findings[0]
	if f.RuleID != "github-pat" {
		t.Errorf("rule_id = %q, want github-pat", f.RuleID)
	}
	if f.Secret != testSecret {
		t.Errorf("secret not returned verbatim when redact is false")
	}
	if f.StartLine != 2 {
		t.Errorf("start_line = %d, want 2", f.StartLine)
	}
	if f.File != "conf/app.env" {
		t.Errorf("file = %q, want conf/app.env", f.File)
	}
	if f.Fingerprint != "conf/app.env:github-pat:2" {
		t.Errorf("fingerprint = %q", f.Fingerprint)
	}
	if strings.Contains(rec.Body.String(), "line one") {
		t.Error("response must not echo unrelated input content")
	}
}

func TestScanRedact(t *testing.T) {
	body := scanBody(t, scanRequest{Content: "token = \"" + testSecret + "\"", Redact: true})
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json; charset=utf-8", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	resp := decode[scanResponse](t, rec)
	if resp.Count != 1 {
		t.Fatalf("count = %d, want 1", resp.Count)
	}
	if strings.Contains(rec.Body.String(), testSecret) {
		t.Fatal("redacted response still contains the secret")
	}
	if resp.Findings[0].Secret != "REDACTED" {
		t.Errorf("secret = %q, want REDACTED", resp.Findings[0].Secret)
	}
}

// The match of a URI rule spans the whole URI, which can carry credentials
// other than the finding's own secret.
func TestScanRedactMasksWholeMatch(t *testing.T) {
	other := "OTHER" + "SECRETVALUE123"
	uri := "https://deploy:" + "Xk9vQ2mLp7Rt4Zs8" + "@git.acme-corp.io/repo?token=" + other
	body := scanBody(t, scanRequest{Content: "DATABASE_URL=" + uri, Redact: true})
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json", body)
	resp := decode[scanResponse](t, rec)
	if resp.Count == 0 {
		t.Fatalf("expected a finding, body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), other) {
		t.Fatalf("redacted response leaks a credential from the match: %s", rec.Body.String())
	}
	for _, f := range resp.Findings {
		if f.Match != "REDACTED" {
			t.Errorf("match = %q, want REDACTED", f.Match)
		}
	}
}

func TestScanLineLimitBoundary(t *testing.T) {
	h := newRealHandler(t, Options{MaxLineBytes: 16})
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"at limit", "short\n" + strings.Repeat("a", 16) + "\nend", http.StatusOK},
		{"over limit", "short\n" + strings.Repeat("a", 17) + "\nend", http.StatusRequestEntityTooLarge},
		{"crlf counts the cr", strings.Repeat("a", 16) + "\r\n", http.StatusRequestEntityTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(h, http.MethodPost, "/v1/scan", "application/json", scanBody(t, scanRequest{Content: tt.content}))
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

// The caller-supplied path is echoed in file and fingerprint, so a secret in
// the path must be masked there as well.
func TestScanRedactMasksSecretInPath(t *testing.T) {
	body := scanBody(t, scanRequest{
		Content: "token = \"" + testSecret + "\"",
		Path:    "credentials/" + testSecret + ".env",
		Redact:  true,
	})
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json", body)
	if resp := decode[scanResponse](t, rec); resp.Count == 0 {
		t.Fatalf("expected a finding, body = %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), testSecret) {
		t.Fatalf("redacted response still contains the secret: %s", rec.Body.String())
	}
}

// Paths that clean to "." equal the default config path inside betterleaks and
// would turn detection off.
func TestScanRejectsDotPath(t *testing.T) {
	for _, p := range []string{".", "./", "a/..", "./."} {
		t.Run(p, func(t *testing.T) {
			body := scanBody(t, scanRequest{Content: "token = \"" + testSecret + "\"", Path: p})
			rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHostAndOriginGuard(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		origin  string
		allowed []string
		want    int
	}{
		{"loopback ip", "127.0.0.1:8080", "", nil, http.StatusOK},
		{"localhost", "localhost:8080", "", nil, http.StatusOK},
		{"localhost mixed case no port", "LocalHost", "", nil, http.StatusOK},
		{"ipv6 loopback", "[::1]:8080", "", nil, http.StatusOK},
		{"rebound name", "attacker.example:8080", "", nil, http.StatusForbidden},
		{"loopback lookalike", "127.0.0.1.attacker.example", "", nil, http.StatusForbidden},
		{"empty host", "", "", nil, http.StatusForbidden},
		{"lan ip not allowed", "192.168.1.10:8080", "", nil, http.StatusForbidden},
		{"configured host", "scanner.internal:8080", "", []string{"Scanner.Internal"}, http.StatusOK},
		{"local origin", "127.0.0.1:8080", "http://localhost:3000", nil, http.StatusOK},
		{"foreign origin", "127.0.0.1:8080", "https://attacker.example", nil, http.StatusForbidden},
		{"null origin", "127.0.0.1:8080", "null", nil, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(fakeScanner{}, Options{AllowedHosts: tt.allowed, Logger: discardLogger()})
			req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
			req.Host = tt.host
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

func TestScanConcurrencyLimit(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	scanner := fakeScanner{scan: func(context.Context) ([]report.Finding, error) {
		started <- struct{}{}
		<-release
		return nil, nil
	}}
	h := New(scanner, Options{MaxConcurrentScans: 1, Logger: discardLogger()})

	done := make(chan int)
	go func() {
		done <- do(h, http.MethodPost, "/v1/scan", "application/json", `{"content":"x"}`).Code
	}()
	<-started

	rec := do(h, http.MethodPost, "/v1/scan", "application/json", `{"content":"x"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status while busy = %d, want 503", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
	// Invalid requests are rejected on their own merits without needing a
	// slot, which shows the body is read before a slot is taken.
	if code := do(h, http.MethodPost, "/v1/scan", "application/json", `{"content":`).Code; code != http.StatusBadRequest {
		t.Errorf("malformed request while busy = %d, want 400", code)
	}

	close(release)
	if code := <-done; code != http.StatusOK {
		t.Errorf("first request status = %d, want 200", code)
	}

	// The slot is released once the first scan finishes.
	go func() { <-started }()
	if code := do(h, http.MethodPost, "/v1/scan", "application/json", `{"content":"x"}`).Code; code != http.StatusOK {
		t.Errorf("status after release = %d, want 200", code)
	}
}

func TestScanTimeout(t *testing.T) {
	scanner := fakeScanner{scan: func(ctx context.Context) ([]report.Finding, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	h := New(scanner, Options{ScanTimeout: time.Millisecond, Logger: discardLogger()})
	rec := do(h, http.MethodPost, "/v1/scan", "application/json", `{"content":"x"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if msg := decode[errorResponse](t, rec).Error; msg != "scan timed out" {
		t.Fatalf("error = %q, want scan timed out", msg)
	}
}

func TestLongestLine(t *testing.T) {
	tests := map[string]int{"": 0, "abc": 3, "abc\n": 3, "a\nbcd\ne": 3, "\n\n": 0, "ab\ncdef": 4}
	for in, want := range tests {
		if got := longestLine(in); got != want {
			t.Errorf("longestLine(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestScanNoFindingsIsEmptyArray(t *testing.T) {
	body := scanBody(t, scanRequest{Content: "nothing to see here"})
	rec := do(newRealHandler(t, Options{}), http.MethodPost, "/v1/scan", "application/json", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != `{"findings":[],"count":0}` {
		t.Fatalf("body = %s", got)
	}
}

func TestScanErrors(t *testing.T) {
	const jsonType = "application/json"
	tests := []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
		maxBody     int64
		wantStatus  int
		wantJSONErr bool
	}{
		{"missing content type", http.MethodPost, "/v1/scan", "", `{"content":"x"}`, 0, http.StatusUnsupportedMediaType, true},
		{"wrong content type", http.MethodPost, "/v1/scan", "text/plain", `{"content":"x"}`, 0, http.StatusUnsupportedMediaType, true},
		{"malformed json", http.MethodPost, "/v1/scan", jsonType, `{"content":`, 0, http.StatusBadRequest, true},
		{"wrong field type", http.MethodPost, "/v1/scan", jsonType, `{"content":1}`, 0, http.StatusBadRequest, true},
		{"unknown field", http.MethodPost, "/v1/scan", jsonType, `{"content":"x","extra":true}`, 0, http.StatusBadRequest, true},
		{"trailing data", http.MethodPost, "/v1/scan", jsonType, `{"content":"x"}{"content":"y"}`, 0, http.StatusBadRequest, true},
		{"missing content", http.MethodPost, "/v1/scan", jsonType, `{"path":"a.txt"}`, 0, http.StatusBadRequest, true},
		{"empty content", http.MethodPost, "/v1/scan", jsonType, `{"content":""}`, 0, http.StatusBadRequest, true},
		{"empty body", http.MethodPost, "/v1/scan", jsonType, ``, 0, http.StatusBadRequest, true},
		{"line too long", http.MethodPost, "/v1/scan", jsonType, `{"content":"ok\n` + strings.Repeat("a", 129) + `"}`, 0, http.StatusRequestEntityTooLarge, true},
		{"body too large", http.MethodPost, "/v1/scan", jsonType, `{"content":"` + strings.Repeat("a", 64) + `"}`, 32, http.StatusRequestEntityTooLarge, true},
		{"get on scan", http.MethodGet, "/v1/scan", "", "", 0, http.StatusMethodNotAllowed, false},
		{"post on rules", http.MethodPost, "/v1/rules", jsonType, `{}`, 0, http.StatusMethodNotAllowed, false},
		{"unknown route", http.MethodGet, "/nope", "", "", 0, http.StatusNotFound, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(newRealHandler(t, Options{MaxBodyBytes: tt.maxBody, MaxLineBytes: 128}), tt.method, tt.target, tt.contentType, tt.body)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantJSONErr {
				if msg := decode[errorResponse](t, rec).Error; msg == "" {
					t.Fatalf("missing error message in %s", rec.Body.String())
				}
			}
		})
	}
}

func TestScanScannerError(t *testing.T) {
	h := New(fakeScanner{err: errors.New("boom")}, Options{Logger: discardLogger()})
	rec := do(h, http.MethodPost, "/v1/scan", "application/json", `{"content":"x"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "boom") {
		t.Fatal("internal error detail leaked to the client")
	}
}

func TestScanCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/scan",
		strings.NewReader(scanBody(t, scanRequest{Content: "token = \"" + testSecret + "\""}))).WithContext(ctx)
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	newRealHandler(t, Options{}).ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestScanConcurrent exercises the shared detector from many goroutines; run
// with -race.
func TestScanConcurrent(t *testing.T) {
	h := newRealHandler(t, Options{MaxConcurrentScans: 32})
	withSecret := scanBody(t, scanRequest{Content: "token = \"" + testSecret + "\"", Path: "a.env"})
	clean := scanBody(t, scanRequest{Content: "nothing to see here"})

	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, want := withSecret, 1
			if i%2 == 1 {
				body, want = clean, 0
			}
			rec := do(h, http.MethodPost, "/v1/scan", "application/json", body)
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d", rec.Code)
				return
			}
			var resp scanResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Errorf("decode: %v", err)
				return
			}
			if resp.Count != want {
				t.Errorf("count = %d, want %d", resp.Count, want)
			}
		}()
	}
	wg.Wait()
}
