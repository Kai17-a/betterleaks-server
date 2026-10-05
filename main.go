// Command betterleaks-server exposes betterleaks secret scanning over a local
// HTTP API.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"betterleaks-server/internal/server"
)

const (
	defaultAddr     = "127.0.0.1:8080"
	addrEnv         = "BETTERLEAKS_SERVER_ADDR"
	shutdownTimeout = 10 * time.Second
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	addrDefault := defaultAddr
	if v := os.Getenv(addrEnv); v != "" {
		addrDefault = v
	}
	addr := flag.String("addr", addrDefault, "listen address (env "+addrEnv+")")
	maxBodyBytes := flag.Int64("max-body-bytes", server.DefaultMaxBodyBytes, "maximum scan request body size in bytes")
	maxConcurrentScans := flag.Int("max-concurrent-scans", server.DefaultMaxConcurrentScans, "maximum number of scans running at once")
	maxQueuedScans := flag.Int("max-queued-scans", server.DefaultMaxQueuedScans, "maximum number of requests waiting for a scan slot (negative disables queueing)")
	scanTimeout := flag.Duration("scan-timeout", server.DefaultScanTimeout, "time limit for a single scan, including time spent waiting for a slot")
	allowedHostsFlag := flag.String("allowed-hosts", "", "comma-separated extra host names or IPs accepted in the Host and Origin headers (localhost and loopback IPs are always accepted)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	scanner, err := server.NewBetterleaksScanner(ctx)
	if err != nil {
		return err
	}

	var allowedHosts []string
	for h := range strings.SplitSeq(*allowedHostsFlag, ",") {
		if h = strings.TrimSpace(h); h != "" {
			allowedHosts = append(allowedHosts, h)
		}
	}
	if !isLoopback(*addr) {
		logger.Warn("listening on a non-loopback address; the API has no authentication", "addr", *addr)
		// A specific bind address is reachable under that name; a wildcard
		// address is not a name clients use, so it needs -allowed-hosts.
		if host, _, err := net.SplitHostPort(*addr); err == nil {
			if ip := net.ParseIP(host); host != "" && (ip == nil || !ip.IsUnspecified()) {
				allowedHosts = append(allowedHosts, host)
			} else if len(allowedHosts) == 0 {
				logger.Warn("only requests addressed to localhost or a loopback IP are accepted; set -allowed-hosts to accept other host names")
			}
		}
	}

	srv := &http.Server{
		Addr: *addr,
		Handler: server.New(scanner, server.Options{
			MaxBodyBytes:       *maxBodyBytes,
			MaxConcurrentScans: *maxConcurrentScans,
			MaxQueuedScans:     *maxQueuedScans,
			ScanTimeout:        *scanTimeout,
			AllowedHosts:       allowedHosts,
			Logger:             logger,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *addr, "rules", len(scanner.Rules()))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
