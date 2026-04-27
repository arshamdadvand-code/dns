package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"masterdnsvpn-go/internal/scanner"
)

func main() {
	var listen string
	var storePath string
	var manifestPath string
	var feedPath string
	var keysPath string
	var concBaseProbe int
	var concOverlayValidate int
	var concReplenish int
	var concExpand int
	var concMaintenance int

	flag.StringVar(&listen, "listen", "127.0.0.1:18777", "scanner listen address (local only)")
	flag.StringVar(&storePath, "store", "scanner_store.json", "scanner store path")
	flag.StringVar(&manifestPath, "manifest", "scanner_instances.json", "desired instance manifest path")
	flag.StringVar(&feedPath, "feed", "scanner_feed.txt", "candidate source feed path")
	flag.StringVar(&keysPath, "keys", "scanner_keys.json", "local keyring (instance_id -> raw key)")
	flag.IntVar(&concBaseProbe, "conc-base", 100, "scanner concurrency: base/stage0 probe")
	flag.IntVar(&concOverlayValidate, "conc-overlay", 32, "scanner concurrency: overlay validation")
	flag.IntVar(&concReplenish, "conc-replenish", 64, "scanner concurrency: replenish from cold-known")
	flag.IntVar(&concExpand, "conc-expand", 100, "scanner concurrency: expand/world scan from feed")
	flag.IntVar(&concMaintenance, "conc-maint", 16, "scanner concurrency: maintenance refresh")
	flag.Parse()

	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -listen: %v\n", err)
		os.Exit(2)
	}
	if host != "127.0.0.1" && host != "localhost" {
		fmt.Fprintf(os.Stderr, "refusing to bind scanner on non-local host: %s\n", host)
		os.Exit(2)
	}

	cfg := scanner.Config{
		ListenAddr:   listen,
		StorePath:    storePath,
		ManifestPath: manifestPath,
		FeedPath:     feedPath,
		KeysPath:     keysPath,
		ConcurrencyBaseProbe:       concBaseProbe,
		ConcurrencyOverlayValidate: concOverlayValidate,
		ConcurrencyReplenish:       concReplenish,
		ConcurrencyExpand:          concExpand,
		ConcurrencyMaintenance:     concMaintenance,
	}

	svc, err := scanner.NewService(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scanner init failed: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ch := make(chan os.Signal, 2)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		<-ch
		cancel()
	}()

	if err := svc.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "scanner start failed: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "scanner listen failed: %v\n", err)
		os.Exit(1)
	}
}
