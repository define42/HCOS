package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/define42/HCOS/internal/agent"
)

func main() {
	var options agent.Options
	var once bool
	flag.StringVar(&options.ConfigPath, "config", "/etc/hcos/config.json", "injected node configuration")
	flag.StringVar(&options.CAPath, "ca", "/etc/hcos/root-ca.crt", "injected controller CA certificate")
	flag.DurationVar(&options.PollInterval, "poll-interval", 15*time.Second, "desired-state polling interval")
	flag.StringVar(&options.VirshPath, "virsh", "/usr/bin/virsh", "virsh executable")
	flag.BoolVar(&once, "once", false, "run one reconciliation cycle and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "hcos-agent: unexpected positional arguments")
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	a, err := agent.New(options, logger)
	if err != nil {
		logger.Error("agent initialization failed", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if once {
		if err := a.Sync(ctx); err != nil {
			logger.Error("reconciliation failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := a.Run(ctx); err != nil {
		logger.Error("agent stopped", "error", err)
		os.Exit(1)
	}
}
