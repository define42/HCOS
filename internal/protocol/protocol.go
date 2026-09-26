// Package protocol defines the versioned JSON exchanged by HCOS components.
package protocol

const APIVersion = "hcos/v1"

// AgentConfig is injected into a node's initramfs by the boot server.
type AgentConfig struct {
	APIVersion      string  `json:"api_version"`
	NodeID          string  `json:"node_id"`
	Hostname        string  `json:"hostname"`
	Controller      string  `json:"controller"`
	ControllerToken string  `json:"controller_token"`
	Registry        string  `json:"registry,omitempty"`
	Storage         Storage `json:"storage"`
	Network         Network `json:"network"`
}

type Storage struct {
	Path string `json:"path"`
}

type Network struct {
	ManagementInterface string `json:"management_interface"`
	VMBridge            string `json:"vm_bridge"`
}

// Domain describes a persistent libvirt QEMU guest requested by the controller.
type Domain struct {
	Name    string `json:"name"`
	XML     string `json:"xml"`
	Running bool   `json:"running"`
}

// DesiredState is the controller's revisioned target for one node.
type DesiredState struct {
	APIVersion string   `json:"api_version"`
	Revision   string   `json:"revision"`
	Domains    []Domain `json:"domains"`
}

// DomainStatus is one domain observed by the agent.
type DomainStatus struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// Report is the node status posted by the agent after reconciliation.
type Report struct {
	APIVersion string         `json:"api_version"`
	NodeID     string         `json:"node_id"`
	Revision   string         `json:"revision"`
	Domains    []DomainStatus `json:"domains"`
	Error      string         `json:"error,omitempty"`
}
