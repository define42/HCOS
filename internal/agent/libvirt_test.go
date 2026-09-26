package agent

import (
	"strings"
	"testing"

	"github.com/define42/HCOS/internal/protocol"
)

func TestValidateDesired(t *testing.T) {
	valid := `<domain type='kvm'><name>guest-1</name><os><type arch='x86_64'>hvm</type></os><devices><emulator>/usr/bin/qemu-system-x86_64</emulator></devices></domain>`
	tests := []struct {
		name      string
		domains   []protocol.Domain
		wantError string
	}{
		{name: "valid x86_64 guest", domains: []protocol.Domain{{Name: "guest-1", XML: valid}}},
		{name: "name mismatch", domains: []protocol.Domain{{Name: "other", XML: valid}}, wantError: "name does not match"},
		{name: "shell-like name", domains: []protocol.Domain{{Name: "guest;rm", XML: valid}}, wantError: "invalid domain name"},
		{name: "ARM guest", domains: []protocol.Domain{{Name: "guest-1", XML: strings.Replace(valid, "x86_64'>", "aarch64'>", 1)}}, wantError: "x86_64"},
		{name: "QEMU extension", domains: []protocol.Domain{{Name: "guest-1", XML: strings.Replace(valid, "</domain>", `<qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu'/></domain>`, 1)}}, wantError: "extension namespaces"},
		{name: "duplicate name", domains: []protocol.Domain{{Name: "guest-1", XML: valid}, {Name: "guest-1", XML: valid}}, wantError: "duplicate domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: tt.domains}
			err := validateDesired(desired)
			if tt.wantError == "" && err != nil {
				t.Fatalf("validateDesired: %v", err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("validateDesired error = %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestMountedPath(t *testing.T) {
	const table = "36 25 0:32 / / rw,relatime - tmpfs tmpfs rw\n37 36 8:1 / /vm-storage rw,relatime - ext4 /dev/sda1 rw\n38 36 8:2 / /space\\040mount rw,relatime - ext4 /dev/sda2 rw\n"
	for _, tt := range []struct {
		name string
		path string
		want bool
	}{
		{name: "mounted storage", path: "/vm-storage", want: true},
		{name: "missing storage", path: "/other", want: false},
		{name: "escaped space", path: "/space mount", want: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := mountedPath(strings.NewReader(table), tt.path); got != tt.want {
				t.Fatalf("mountedPath(%q) = %t, want %t", tt.path, got, tt.want)
			}
		})
	}
}
