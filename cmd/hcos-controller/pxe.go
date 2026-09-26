package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/define42/HCOS/internal/controller"
)

type pxeResult struct {
	service string
	err     error
}

// runPXE binds all three listeners before serving so a partial PXE stack is
// never advertised. The main controller cancels this context on shutdown.
func runPXE(ctx context.Context, config controller.PXEConfig) error {
	if config.DHCP.IPXEBootFile == "" {
		config.DHCP.IPXEBootFile = "http://" + config.HTTPListenAddress + "/boot/boot.ipxe"
	}
	if err := config.DHCP.Validate(); err != nil {
		return err
	}
	handler, err := controller.NewPXEHandler(config)
	if err != nil {
		return fmt.Errorf("initialize PXE HTTP: %w", err)
	}
	tftp, err := controller.NewTFTPServer(config.TFTP)
	if err != nil {
		return fmt.Errorf("initialize TFTP: %w", err)
	}
	httpListener, err := net.Listen("tcp4", config.HTTPListenAddress)
	if err != nil {
		return fmt.Errorf("listen PXE HTTP: %w", err)
	}
	defer httpListener.Close()
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

	parentCtx := ctx
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	web := controller.PXEHTTPServer(config, handler)
	results := make(chan pxeResult, 3)
	go func() { results <- pxeResult{"HTTP", web.Serve(httpListener)} }()
	go func() { results <- pxeResult{"TFTP", tftp.Serve(ctx, tftpListener)} }()
	go func() { results <- pxeResult{"DHCP", dhcp.Serve(ctx)} }()

	var first pxeResult
	select {
	case first = <-results:
	case <-ctx.Done():
	}
	cancel()
	_ = dhcp.Close()
	_ = tftpListener.Close()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
	shutdownErr := web.Shutdown(shutdownCtx)
	stop()
	if shutdownErr != nil {
		_ = web.Close()
	}

	// Drain the remaining service results. All listeners have been closed.
	count := 3
	if first.service != "" {
		count--
	}
	for range count {
		<-results
	}
	if first.service != "" && first.err != nil && !errors.Is(first.err, http.ErrServerClosed) {
		return fmt.Errorf("PXE %s: %w", first.service, first.err)
	}
	if shutdownErr != nil {
		return fmt.Errorf("PXE HTTP shutdown: %w", shutdownErr)
	}
	if first.service != "" && parentCtx.Err() == nil {
		return fmt.Errorf("PXE %s stopped unexpectedly", first.service)
	}
	return nil
}
