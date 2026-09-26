package controller

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// PXEConfig enables DHCP and TFTP for the isolated IPv4 provisioning network.
// Node-specific scripts direct iPXE to the boot server's HTTP listener.
type PXEConfig struct {
	DHCP DHCPConfig `json:"dhcp"`
	TFTP TFTPConfig `json:"tftp"`
}

// Validate keeps DHCP, TFTP, and generated scripts tied to the same node data.
func (p PXEConfig) Validate(nodes []NodeCredential) error {
	if err := p.DHCP.Validate(); err != nil {
		return fmt.Errorf("pxe.dhcp: %w", err)
	}
	if err := p.TFTP.Validate(); err != nil {
		return fmt.Errorf("pxe.tftp: %w", err)
	}
	serverIP, err := netip.ParseAddr(p.DHCP.ServerIP)
	if err != nil {
		return fmt.Errorf("PXE server IP: %w", err)
	}
	tftpAddress, err := netip.ParseAddrPort(p.TFTP.ListenAddress)
	if err != nil || tftpAddress.Addr() != serverIP {
		return errors.New("PXE TFTP must listen on the configured server IP")
	}
	if !serverIP.IsLoopback() && tftpAddress.Port() != 69 {
		return errors.New("PXE TFTP must use port 69 for firmware PXE clients")
	}
	if p.DHCP.NextServerIP != "" && p.DHCP.NextServerIP != p.DHCP.ServerIP {
		return errors.New("PXE next_server_ip must point to this TFTP server")
	}
	if p.DHCP.BootFile != "" && p.DHCP.BootFile != "bootx64.efi" {
		return errors.New("PXE boot_file must be bootx64.efi")
	}
	expectedScript := tftpScriptURL(p.DHCP.ServerIP)
	if p.DHCP.IPXEBootFile != expectedScript {
		return errors.New("PXE ipxe_boot_file must point to this controller's TFTP boot script")
	}
	byID := make(map[string]NodeCredential, len(nodes))
	for _, node := range nodes {
		if node.hasPXE() {
			byID[node.ID] = node
		}
	}
	if len(byID) != len(p.DHCP.Leases) || len(p.TFTP.scripts) != len(p.DHCP.Leases) {
		return errors.New("PXE requires one DHCP lease and TFTP script for each provisioned node")
	}
	for _, lease := range p.DHCP.Leases {
		if lease.BootFile != "" && lease.BootFile != "bootx64.efi" {
			return fmt.Errorf("PXE node %q boot_file must be bootx64.efi", lease.NodeID)
		}
		if lease.IPXEBootFile != "" && lease.IPXEBootFile != expectedScript {
			return fmt.Errorf("PXE node %q iPXE URL must point to this controller's TFTP boot script", lease.NodeID)
		}
		node, found := byID[lease.NodeID]
		if !found {
			return fmt.Errorf("PXE lease references unknown provisioning node %q", lease.NodeID)
		}
		if !validBearerToken(node.Token) {
			return fmt.Errorf("PXE node %q needs a 32-512 character node token", lease.NodeID)
		}
		nodeMAC, err := net.ParseMAC(node.MAC)
		leaseMAC, _ := net.ParseMAC(lease.MAC) // DHCP validation already checked the lease MAC.
		if err != nil || !bytes.Equal(nodeMAC, leaseMAC) || node.IP != lease.IP {
			return fmt.Errorf("PXE lease for node %q must match its configured MAC and IP", lease.NodeID)
		}
		if !bytes.Equal(p.TFTP.scripts[lease.IP], pxeBootScript(p.DHCP.ServerIP, node.ID, node.Token)) {
			return fmt.Errorf("PXE script for node %q must match its configured identity and token", lease.NodeID)
		}
	}
	return nil
}
