package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/define42/HCOS/internal/protocol"
)

// Agent polls the controller and applies its desired libvirt QEMU domains.
type Agent struct {
	config      protocol.AgentConfig
	controller  *url.URL
	client      *http.Client
	options     Options
	logger      *slog.Logger
	lastDefined map[string][32]byte
}

// New validates the injected config and CA before any domain operation occurs.
func New(options Options, logger *slog.Logger) (*Agent, error) {
	if options.ConfigPath == "" || options.CAPath == "" || options.VirshPath == "" {
		return nil, errors.New("config, CA, and virsh paths are required")
	}
	if options.PollInterval <= 0 {
		return nil, errors.New("poll interval must be positive")
	}
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	cfg, controller, err := loadConfig(options.ConfigPath)
	if err != nil {
		return nil, err
	}
	client, err := newHTTPClient(options.CAPath)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Agent{
		config: cfg, controller: controller, client: client, options: options,
		logger: logger, lastDefined: make(map[string][32]byte),
	}, nil
}

// Run continues polling until its context is canceled. A failed poll is logged
// and retried; OpenRC should only restart the process after an actual exit.
func (a *Agent) Run(ctx context.Context) error {
	for {
		if err := a.Sync(ctx); err != nil && ctx.Err() == nil {
			a.logger.Error("reconciliation failed", "node", a.config.NodeID, "error", err)
		}
		timer := time.NewTimer(a.options.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// Sync runs one controller fetch, domain reconciliation, and status report.
func (a *Agent) Sync(ctx context.Context) error {
	desired, err := a.desired(ctx)
	if err != nil {
		return err
	}
	report := protocol.Report{
		APIVersion: protocol.APIVersion,
		NodeID:     a.config.NodeID,
		Revision:   desired.Revision,
		Domains:    make([]protocol.DomainStatus, 0, len(desired.Domains)),
	}
	if err := validateDesired(desired); err != nil {
		report.Error = err.Error()
		return errors.Join(err, a.report(ctx, report))
	}

	var problems []error
	for _, domain := range desired.Domains {
		state, err := a.reconcileDomain(ctx, domain)
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", domain.Name, err))
		}
		report.Domains = append(report.Domains, protocol.DomainStatus{Name: domain.Name, State: state})
	}
	if len(problems) != 0 {
		report.Error = errors.Join(problems...).Error()
		if len(report.Error) > 2048 {
			report.Error = strings.ToValidUTF8(report.Error[:2048], "")
		}
	}
	return errors.Join(errors.Join(problems...), a.report(ctx, report))
}
