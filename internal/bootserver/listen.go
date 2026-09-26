package bootserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// Run serves boot images until ctx is canceled or a listener fails. Both the TLS
// listener and optional PXE HTTP listener share authentication, cache and limits.
func (s *Server) Run(ctx context.Context) error {
	var listenerConfig net.ListenConfig
	return s.run(ctx, listenerConfig.Listen)
}

type listenFunc func(context.Context, string, string) (net.Listener, error)

type bootListener struct {
	server   *http.Server
	listener net.Listener
	tls      bool
}

func (s *Server) run(ctx context.Context, listen listenFunc) error {
	handler := s.Handler()
	main := NewHTTPServer(s.config, handler)
	if s.config.TLSCert != "" {
		certificate, err := tls.LoadX509KeyPair(s.config.TLSCert, s.config.TLSKey)
		if err != nil {
			return fmt.Errorf("load boot server TLS certificate: %w", err)
		}
		main.TLSConfig = &tls.Config{Certificates: []tls.Certificate{certificate}}
	}
	servers := []*http.Server{main}
	if s.config.PXEHTTP {
		host, _, _ := net.SplitHostPort(s.config.Listen) // Validated by New.
		pxe := NewHTTPServer(s.config, handler)
		pxe.Addr = net.JoinHostPort(host, "80")
		servers = append(servers, pxe)
	}

	listeners := make([]bootListener, 0, len(servers))
	defer func() {
		for _, endpoint := range listeners {
			_ = endpoint.listener.Close()
		}
	}()
	// Bind every address before accepting requests, so a port conflict cannot
	// leave the server running with only half of its configured boot services.
	for i, server := range servers {
		listener, err := listen(ctx, "tcp", server.Addr)
		if err != nil {
			return fmt.Errorf("listen for boot requests on %s: %w", server.Addr, err)
		}
		listeners = append(listeners, bootListener{
			server: server, listener: listener, tls: i == 0 && s.config.TLSCert != "",
		})
	}

	results := make(chan error, len(listeners))
	for _, endpoint := range listeners {
		go func() {
			s.logger.Info("HCOS boot server listening", "address", endpoint.listener.Addr().String(), "tls", endpoint.tls)
			var err error
			if endpoint.tls {
				err = endpoint.server.ServeTLS(endpoint.listener, "", "")
			} else {
				err = endpoint.server.Serve(endpoint.listener)
			}
			if !errors.Is(err, http.ErrServerClosed) {
				err = fmt.Errorf("serve boot requests on %s: %w", endpoint.server.Addr, err)
			} else {
				err = nil
			}
			results <- err
		}()
	}

	var runErr error
	remaining := len(listeners)
	select {
	case <-ctx.Done():
	case runErr = <-results:
		remaining--
	}

	shutdownContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var shutdown sync.WaitGroup
	shutdownErrors := make(chan error, len(listeners))
	for _, endpoint := range listeners {
		shutdown.Go(func() {
			if err := endpoint.server.Shutdown(shutdownContext); err != nil {
				_ = endpoint.server.Close()
				shutdownErrors <- fmt.Errorf("shut down boot listener %s: %w", endpoint.server.Addr, err)
			}
		})
	}
	shutdown.Wait()
	close(shutdownErrors)
	for err := range shutdownErrors {
		runErr = errors.Join(runErr, err)
	}
	for range remaining {
		runErr = errors.Join(runErr, <-results)
	}
	return runErr
}
