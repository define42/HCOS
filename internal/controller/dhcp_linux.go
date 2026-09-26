//go:build linux

package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ListenDHCP binds the provisioning socket to the named Linux interface. The
// interface must own server_ip; this check avoids accidentally serving a LAN
// when a machine's interface names or addresses change.
func ListenDHCP(config DHCPConfig) (*DHCPServer, error) {
	server, err := NewDHCPServer(config)
	if err != nil {
		return nil, err
	}
	iface, err := net.InterfaceByName(server.config.Interface)
	if err != nil {
		return nil, fmt.Errorf("dhcp interface: %w", err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("dhcp interface %q is down", iface.Name)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("dhcp interface addresses: %w", err)
	}
	hasServerIP := false
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && ipNet.IP.To4() != nil && ipNet.IP.Equal(net.IP(server.serverIP[:])) {
			hasServerIP = true
			break
		}
	}
	if !hasServerIP {
		return nil, fmt.Errorf("dhcp interface %q does not own server_ip %s", iface.Name, server.config.ServerIP)
	}
	listener := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		if err := raw.Control(func(fd uintptr) {
			if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface.Name); err != nil {
				controlErr = fmt.Errorf("bind DHCP socket to interface %q: %w", iface.Name, err)
				return
			}
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
				controlErr = fmt.Errorf("enable DHCP broadcast replies: %w", err)
			}
		}); err != nil {
			return err
		}
		return controlErr
	}}
	conn, err := listener.ListenPacket(context.Background(), "udp4", server.config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen DHCP on %q: %w", server.config.ListenAddress, err)
	}
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("dhcp listener is not a UDP socket")
	}
	server.conn = udp
	return server, nil
}
