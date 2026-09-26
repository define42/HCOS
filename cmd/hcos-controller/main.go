package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/define42/HCOS/internal/controller"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hcos-controller: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var configPath string
	flag.StringVar(&configPath, "config", "/etc/hcos-controller/config.json", "controller JSON configuration path")
	flag.Parse()

	config, err := controller.LoadConfig(configPath)
	if err != nil {
		return err
	}
	store, err := controller.OpenStore(config.StateDir)
	if err != nil {
		return err
	}
	handler, err := controller.NewHandler(config, store)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              config.APIAddress(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	listener, err := net.Listen("tcp4", config.APIAddress())
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if config.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			listener.Close()
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		listener = tls.NewListener(listener, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
		})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	var pxeErr chan error
	if pxe := config.RuntimePXE(); pxe != nil {
		pxeErr = make(chan error, 1)
		go func() { pxeErr <- runPXE(ctx, *pxe) }()
	}
	var firstErr error
	adminDone, pxeDone := false, false
	select {
	case err := <-serveErr:
		adminDone = true
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			firstErr = fmt.Errorf("serve controller API: %w", err)
		} else {
			firstErr = errors.New("controller API stopped unexpectedly")
		}
	case err := <-pxeErr:
		pxeDone = true
		if err != nil {
			firstErr = err
		} else {
			firstErr = errors.New("PXE services stopped unexpectedly")
		}
	case <-ctx.Done():
	}
	stop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = server.Close()
		if firstErr == nil {
			firstErr = fmt.Errorf("shutdown controller API: %w", err)
		}
	}
	if !adminDone {
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) && firstErr == nil {
			firstErr = fmt.Errorf("serve controller API: %w", err)
		}
	}
	if pxeErr != nil && !pxeDone {
		if err := <-pxeErr; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
