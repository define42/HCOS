package controller

import "testing"

func TestPXERejectsMismatchedBootAssets(t *testing.T) {
	cases := []struct {
		name string
		edit func(*PXEConfig)
	}{
		{"wrong TFTP IP", func(p *PXEConfig) { p.TFTP.ListenAddress = "127.0.0.4:69" }},
		{"wrong next server", func(p *PXEConfig) { p.DHCP.NextServerIP = "127.0.0.4" }},
		{"wrong firmware boot file", func(p *PXEConfig) { p.DHCP.BootFile = "other.efi" }},
		{"HTTP iPXE target", func(p *PXEConfig) { p.DHCP.IPXEBootFile = "http://127.0.0.1/boot/boot.ipxe" }},
		{"missing iPXE target", func(p *PXEConfig) { p.DHCP.IPXEBootFile = "" }},
		{"wrong node boot file", func(p *PXEConfig) { p.DHCP.Leases[0].BootFile = "other.efi" }},
		{"wrong node iPXE target", func(p *PXEConfig) { p.DHCP.Leases[0].IPXEBootFile = "tftp://127.0.0.1/other.ipxe" }},
		{"unknown node", func(p *PXEConfig) { p.DHCP.Leases[0].NodeID = "unknown-node" }},
		{"wrong node MAC", func(p *PXEConfig) { p.DHCP.Leases[0].MAC = "52:54:00:12:34:57" }},
		{"wrong node IP", func(p *PXEConfig) { p.DHCP.Leases[0].IP = "127.0.0.4" }},
		{"missing node script", func(p *PXEConfig) { delete(p.TFTP.scripts, "127.0.0.2") }},
		{"extra node script", func(p *PXEConfig) { p.TFTP.scripts["127.0.0.4"] = p.TFTP.scripts["127.0.0.2"] }},
		{"wrong node script", func(p *PXEConfig) {
			p.TFTP.scripts["127.0.0.2"] = pxeBootScript("127.0.0.1", "other-node", "wrong-token")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := testConfigWithPXE(t)
			pxe := config.RuntimePXE()
			if err := pxe.Validate(config.Nodes); err != nil {
				t.Fatalf("valid PXE configuration rejected: %v", err)
			}
			tc.edit(pxe)
			if err := pxe.Validate(config.Nodes); err == nil {
				t.Fatal("mismatched PXE configuration accepted")
			}
		})
	}
}

func TestPXERequiresFirmwareTFTPPort(t *testing.T) {
	config := testConfigWithPXE(t)
	config.ServerIP = "192.0.2.1"
	config.Nodes[0].IP = "192.0.2.2"
	config.PXE.DHCP.SubnetMask = "255.255.255.0"
	pxe := config.RuntimePXE()
	if err := pxe.Validate(config.Nodes); err != nil {
		t.Fatalf("valid provisioning configuration rejected: %v", err)
	}
	pxe.TFTP.ListenAddress = "192.0.2.1:1069"
	if err := pxe.Validate(config.Nodes); err == nil {
		t.Fatal("firmware TFTP service on a nonstandard port accepted")
	}
}
