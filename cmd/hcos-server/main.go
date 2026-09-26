// hcos-server assembles node-specific, optionally signed HCOS EFI boot images.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

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
	signals, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := server.Run(signals); err != nil {
		logger.Error("boot server stopped", "error", err)
		os.Exit(1)
	}
}
