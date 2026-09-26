//go:build !linux

package controller

import "errors"

// ListenDHCP is available only on Linux, where SO_BINDTODEVICE confines the
// socket to the provisioned interface.
func ListenDHCP(DHCPConfig) (*DHCPServer, error) {
	return nil, errors.New("DHCP serving requires Linux")
}
