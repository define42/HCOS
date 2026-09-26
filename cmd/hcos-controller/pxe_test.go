package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServePXECancellationClosesAndWaitsForBothServices(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{}, 2)
	stopped := make(chan struct{}, 2)
	services := [2]pxeService{}
	for i, name := range []string{"DHCP", "TFTP"} {
		closed := make(chan struct{})
		services[i] = pxeService{
			name: name,
			serve: func(ctx context.Context) error {
				started <- struct{}{}
				<-ctx.Done()
				<-closed
				stopped <- struct{}{}
				return nil
			},
			close: func() error {
				close(closed)
				return net.ErrClosed // Cancellation may already have closed a listener.
			},
		}
	}
	done := make(chan error, 1)
	go func() { done <- servePXE(ctx, services) }()
	for range services {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("PXE services did not start")
		}
	}
	cancel()
	if err := waitPXE(t, done); err != nil {
		t.Fatalf("cancellation returned %v", err)
	}
	if len(stopped) != len(services) {
		t.Fatal("shutdown returned before both services exited")
	}
}

func TestServePXERetainsBothServiceErrors(t *testing.T) {
	t.Parallel()
	first := errors.New("DHCP receive failed")
	second := errors.New("TFTP receive failed during shutdown")
	services := [2]pxeService{
		{
			name: "DHCP", serve: func(context.Context) error { return first },
			close: func() error { return nil },
		},
		{
			name: "TFTP",
			serve: func(ctx context.Context) error {
				<-ctx.Done()
				return second
			},
			close: func() error { return nil },
		},
	}
	done := make(chan error, 1)
	go func() { done <- servePXE(t.Context(), services) }()
	err := waitPXE(t, done)
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("shutdown lost a service error: %v", err)
	}
}

func TestServePXEUnexpectedExitStopsOtherService(t *testing.T) {
	t.Parallel()
	services := [2]pxeService{
		{
			name: "DHCP", serve: func(context.Context) error { return nil },
			close: func() error { return nil },
		},
		{
			name: "TFTP",
			serve: func(ctx context.Context) error {
				<-ctx.Done()
				return nil
			},
			close: func() error { return nil },
		},
	}
	done := make(chan error, 1)
	go func() { done <- servePXE(t.Context(), services) }()
	if err := waitPXE(t, done); err == nil || !strings.Contains(err.Error(), "DHCP stopped unexpectedly") {
		t.Fatalf("unexpected exit was not reported: %v", err)
	}
}

func waitPXE(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("PXE services did not stop")
		return nil
	}
}
