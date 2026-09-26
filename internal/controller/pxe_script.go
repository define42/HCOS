package controller

import "net/url"

func tftpScriptURL(serverIP string) string {
	return "tftp://" + serverIP + "/boot.ipxe"
}

// pxeBootScript grants the configured node direct access to its boot image.
// Credentials are URL-encoded so they cannot change the iPXE command.
func pxeBootScript(serverIP, nodeID, token string) []byte {
	target := url.URL{Scheme: "http", Host: serverIP, Path: "/boot/hcos.efi"}
	query := url.Values{"node": {nodeID}, "token": {token}}
	target.RawQuery = query.Encode()
	return []byte("#!ipxe\nchain " + target.String() + "\n")
}
