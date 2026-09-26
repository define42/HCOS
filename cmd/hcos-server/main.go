// hcos-server assembles node-specific, optionally signed HCOS EFI boot images.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/define42/HCOS/internal/bootserver"
)

func main() {
	configPath := flag.String("config", "/etc/hcos-server/server.json", "server configuration JSON")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	config, err := bootserver.LoadConfig(*configPath)
	if err != nil {
		logger.Error("load configuration", "error", err)
		os.Exit(1)
	}
	server, err := bootserver.New(config, logger)
	if err != nil {
		logger.Error("initialize boot server", "error", err)
		os.Exit(1)
	}
	httpServer := bootserver.NewHTTPServer(config, server.Handler())
	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-signals.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("shutdown boot server", "error", err)
		}
	}()
	logger.Info("HCOS boot server listening", "address", config.Listen, "tls", config.TLSCert != "")
	if config.TLSCert != "" {
		err = httpServer.ListenAndServeTLS(config.TLSCert, config.TLSKey)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("boot server stopped", "error", err)
		os.Exit(1)
	}
}
