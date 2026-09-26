package controller

import _ "embed"

// embeddedIPXELoader is the x86_64 UEFI iPXE image built from the pinned source.
//
//go:embed bootx64.efi
var embeddedIPXELoader []byte
