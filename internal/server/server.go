// Package server implements the HTTP API on top of a secret Scanner.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/betterleaks/betterleaks/report"
)

// Default limits for POST /v1/scan. Scan cost grows with the square of the
// number of findings and with findings-per-line times line length, and the
// library cannot be interrupted mid-rule, so the input itself has to be bounded.
const (
	DefaultMaxBodyBytes       int64 = 256 << 10
	DefaultMaxLineBytes             = 4 << 10
	DefaultMaxConcurrentScans       = 2
	DefaultScanTimeout              = 30 * time.Second
)

const (
	// redactPercent fully masks secrets when redaction is requested.
	redactPercent = 100
	redacted      = "REDACTED"
)

// Rule is the public view of a detection rule.
type Rule struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
}

// Finding is the public view of a detected secret. It deliberately omits the
// scanned fragment so responses never echo the whole input back.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	StartColumn int      `json:"start_column"`
	EndColumn   int      `json:"end_column"`
	Match       string   `json:"match"`
	Secret      string   `json:"secret"`
	File        string   `json:"file"`
	Entropy     float32  `json:"entropy"`
	Tags        []string `json:"tags"`
	Fingerprint string   `json:"fingerprint"`
}

type scanRequest struct {
	Content string `json:"content"`
	Path    string `json:"path"`
	Redact  bool   `json:"redact"`
}

type scanResponse struct {
	Findings []Finding `json:"findings"`
	Count    int       `json:"count"`
}

type rulesResponse struct {
	Rules []Rule `json:"rules"`
	Count int    `json:"count"`
}

type errorResponse struct {
	Error string `json:"error"`
}

// Options configures the handler returned by New.
type Options struct {
	// MaxBodyBytes limits the scan request body. Zero or negative means
	// DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// MaxLineBytes limits the length of a single line of content. Zero or
	// negative means DefaultMaxLineBytes.
	MaxLineBytes int
	// MaxConcurrentScans limits scans running at once; further requests are
	// rejected with 503. Zero or negative means DefaultMaxConcurrentScans.
	MaxConcurrentScans int
	// ScanTimeout bounds a single scan. Zero or negative means
	// DefaultScanTimeout.
	ScanTimeout time.Duration
	// AllowedHosts lists host names or IPs accepted in the Host and Origin
	// headers in addition to localhost and loopback IPs.
	AllowedHosts []string
	// Logger receives access logs. Nil means slog.Default().
	Logger *slog.Logger
}

type handler struct {
	scanner      Scanner
	maxBodyBytes int64
	maxLineBytes int
	scanTimeout  time.Duration
	scanSlots    chan struct{}
	allowedHosts map[string]struct{}
	logger       *slog.Logger
}

// New returns the API handler.
func New(scanner Scanner, opts Options) http.Handler {
	h := &handler{
		scanner:      scanner,
		maxBodyBytes: opts.MaxBodyBytes,
		maxLineBytes: opts.MaxLineBytes,
		scanTimeout:  opts.ScanTimeout,
		allowedHosts: make(map[string]struct{}, len(opts.AllowedHosts)),
		logger:       opts.Logger,
	}
	if h.maxBodyBytes <= 0 {
		h.maxBodyBytes = DefaultMaxBodyBytes
	}
	if h.maxLineBytes <= 0 {
		h.maxLineBytes = DefaultMaxLineBytes
	}
	if h.scanTimeout <= 0 {
		h.scanTimeout = DefaultScanTimeout
	}
	slots := opts.MaxConcurrentScans
	if slots <= 0 {
		slots = DefaultMaxConcurrentScans
	}
	h.scanSlots = make(chan struct{}, slots)
	for _, host := range opts.AllowedHosts {
		if host = normalizeHost(host); host != "" {
			h.allowedHosts[host] = struct{}{}
		}
	}
	if h.logger == nil {
		h.logger = slog.Default()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /v1/rules", h.rules)
	mux.HandleFunc("POST /v1/scan", h.scan)
	return h.accessLog(h.guardOrigin(mux))
}

// guardOrigin rejects requests whose Host or Origin is not an expected local
// name. A page on another site that rebinds its DNS name to 127.0.0.1 still
// sends its own name in both headers, so this stops DNS rebinding and other
// browser-driven access. Clients that send no Origin (curl, scripts) pass.
func (h *handler) guardOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.hostAllowed(hostOnly(r.Host)) {
			writeError(w, http.StatusForbidden, "host not allowed")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || !h.hostAllowed(u.Hostname()) {
				writeError(w, http.StatusForbidden, "origin not allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) hostAllowed(host string) bool {
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	_, ok := h.allowedHosts[host]
	return ok
}

// hostOnly strips an optional port from a Host header value.
func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func normalizeHost(host string) string {
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(host), "["), "]")
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (h *handler) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *handler) rules(w http.ResponseWriter, _ *http.Request) {
	rules := h.scanner.Rules()
	if rules == nil {
		rules = []Rule{}
	}
	writeJSON(w, http.StatusOK, rulesResponse{Rules: rules, Count: len(rules)})
}

func (h *handler) scan(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}

	var req scanRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, h.maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeDecodeError(w, err)
		return
	}
	// Reject trailing data after the JSON object.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err != nil {
			writeDecodeError(w, err)
			return
		}
		writeError(w, http.StatusBadRequest, "request body must contain a single JSON object")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}

	if longestLine(req.Content) > h.maxLineBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "content has a line longer than the configured limit")
		return
	}
	// betterleaks skips fragments whose path equals its config path, and the
	// default config has an empty path, which cleans to ".". Such a path would
	// silently disable detection.
	if req.Path != "" && filepath.ToSlash(filepath.Clean(req.Path)) == "." {
		writeError(w, http.StatusBadRequest, "path must name a file")
		return
	}

	// Take a slot only once the request is fully read and validated: a client
	// that sends its body slowly must not be able to hold a slot. The body is
	// small (MaxBodyBytes), so buffering it for rejected requests is cheap.
	select {
	case h.scanSlots <- struct{}{}:
		defer func() { <-h.scanSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusServiceUnavailable, "too many concurrent scans")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), h.scanTimeout)
	defer cancel()

	found, err := h.scanner.Scan(ctx, req.Content, req.Path)
	if err != nil {
		if r.Context().Err() != nil {
			writeError(w, http.StatusServiceUnavailable, "scan canceled")
			return
		}
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusServiceUnavailable, "scan timed out")
			return
		}
		// The error text is not returned or logged with details beyond its
		// message; scanners must not put request content in errors.
		h.logger.Error("scan failed", "error", err)
		writeError(w, http.StatusInternalServerError, "scan failed")
		return
	}

	findings := make([]Finding, 0, len(found))
	for _, f := range found {
		findings = append(findings, toFinding(f, req.Redact))
	}
	writeJSON(w, http.StatusOK, scanResponse{Findings: findings, Count: len(findings)})
}

func toFinding(f report.Finding, redact bool) Finding {
	if redact {
		// The caller-supplied path is echoed in file and fingerprint; mask the
		// secret there too in case the path itself contains it.
		if f.Secret != "" {
			f.File = strings.ReplaceAll(f.File, f.Secret, redacted)
			f.Fingerprint = strings.ReplaceAll(f.Fingerprint, f.Secret, redacted)
		}
		f.Redact(redactPercent)
		// Redact only masks this finding's secret inside the match; the match
		// can span other credentials (e.g. a whole connection URI).
		f.Match = redacted
	}
	tags := f.Tags
	if tags == nil {
		tags = []string{}
	}
	return Finding{
		RuleID:      f.RuleID,
		Description: f.Description,
		StartLine:   f.StartLine,
		EndLine:     f.EndLine,
		StartColumn: f.StartColumn,
		EndColumn:   f.EndColumn,
		Match:       f.Match,
		Secret:      f.Secret,
		File:        f.File,
		Entropy:     f.Entropy,
		Tags:        tags,
		Fingerprint: f.Fingerprint,
	}
}

// longestLine returns the byte length of the longest line in s.
func longestLine(s string) int {
	longest := 0
	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			i = len(s)
			s = ""
		} else {
			s = s[i+1:]
		}
		longest = max(longest, i)
	}
	return longest
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	// Decoder errors can quote parts of the input, so keep the message generic.
	writeError(w, http.StatusBadRequest, "invalid JSON request body")
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// accessLog logs method, path, status and duration. It never logs bodies.
func (h *handler) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		h.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start),
		)
	})
}
