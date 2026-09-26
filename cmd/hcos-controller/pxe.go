package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/define42/HCOS/internal/controller"
)

type pxeService struct {
	name  string
	serve func(context.Context) error
	close func() error
}

// runPXE binds both listeners before serving so a partial PXE stack is never
// advertised. The main controller cancels this context on shutdown.
func runPXE(ctx context.Context, config controller.PXEConfig) error {
	if config.DHCP.IPXEBootFile == "" {
		config.DHCP.IPXEBootFile = "tftp://" + config.DHCP.ServerIP + "/boot.ipxe"
	}
	if err := config.DHCP.Validate(); err != nil {
		return err
	}
	tftp, err := controller.NewTFTPServer(config.TFTP)
	if err != nil {
		return fmt.Errorf("initialize TFTP: %w", err)
	}
	tftpAddress, err := net.ResolveUDPAddr("udp4", config.TFTP.ListenAddress)
	if err != nil {
		return fmt.Errorf("resolve TFTP listener: %w", err)
	}
	tftpListener, err := net.ListenUDP("udp4", tftpAddress)
	if err != nil {
		return fmt.Errorf("listen TFTP: %w", err)
	}
	defer tftpListener.Close()
	dhcp, err := controller.ListenDHCP(config.DHCP)
	if err != nil {
		return err
	}
	defer dhcp.Close()

	return servePXE(ctx, [2]pxeService{
		{name: "DHCP", serve: dhcp.Serve, close: dhcp.Close},
		{
			name: "TFTP",
			serve: func(ctx context.Context) error {
				return tftp.Serve(ctx, tftpListener)
			},
			close: tftpListener.Close,
		},
	})
}

// servePXE waits for both services to exit, retaining errors from either one
// even when a service failure races with cancellation.
func servePXE(parent context.Context, services [2]pxeService) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	results := make(chan error, len(services))
	for _, service := range services {
		go func() {
			err := service.serve(ctx)
			if err != nil {
				err = fmt.Errorf("PXE %s: %w", service.name, err)
			} else if ctx.Err() == nil {
				err = fmt.Errorf("PXE %s stopped unexpectedly", service.name)
			}
			results <- err
		}()
	}

	var result error
	completed := 0
	select {
	case result = <-results:
		completed++
	case <-ctx.Done():
	}
	cancel()
	for _, service := range services {
		if err := service.close(); err != nil && !errors.Is(err, net.ErrClosed) {
			result = errors.Join(result, fmt.Errorf("close PXE %s: %w", service.name, err))
		}
	}
	for completed < len(services) {
		result = errors.Join(result, <-results)
		completed++
	}
	return result
}
