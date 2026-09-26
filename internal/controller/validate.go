package controller

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/define42/HCOS/internal/protocol"
)

const (
	maxDomains   = 32
	maxDomainXML = 256 << 10
)

func validNodeID(id string) bool {
	return validDomainName(id)
}

func validDomainName(name string) bool {
	if len(name) == 0 || len(name) > 63 {
		return false
	}
	for index := 0; index < len(name); index++ {
		ch := name[index]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' {
			continue
		}
		if index == 0 || ch != '-' && ch != '_' && ch != '.' {
			return false
		}
	}
	return true
}

func validRevision(revision string) bool {
	if len(revision) == 0 || len(revision) > 128 {
		return false
	}
	for index := 0; index < len(revision); index++ {
		ch := revision[index]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' ||
			ch == '-' || ch == '_' || ch == '.' {
			continue
		}
		return false
	}
	return true
}

func validateDesired(desired protocol.DesiredState) error {
	if desired.APIVersion != protocol.APIVersion {
		return errors.New("unsupported api_version")
	}
	if !validRevision(desired.Revision) {
		return errors.New("invalid revision")
	}
	if len(desired.Domains) > maxDomains {
		return errors.New("too many domains")
	}
	names := make(map[string]struct{}, len(desired.Domains))
	for index, domain := range desired.Domains {
		if !validDomainName(domain.Name) {
			return fmt.Errorf("domain %d has invalid name", index)
		}
		if _, exists := names[domain.Name]; exists {
			return fmt.Errorf("duplicate domain %q", domain.Name)
		}
		names[domain.Name] = struct{}{}
		if err := validateDomainXML(domain.Name, domain.XML); err != nil {
			return fmt.Errorf("domain %q: %w", domain.Name, err)
		}
	}
	return nil
}

// validateDomainXML checks the identity and x86_64 QEMU target before an agent
// receives the libvirt document. The agent still owns local resource policy.
func validateDomainXML(name, data string) error {
	if len(data) == 0 || len(data) > maxDomainXML {
		return fmt.Errorf("XML must be 1 to %d bytes", maxDomainXML)
	}
	decoder := xml.NewDecoder(strings.NewReader(data))
	var path []xml.Name
	var rootSeen bool
	var rootType string
	var xmlName strings.Builder
	var guestType strings.Builder
	var emulator strings.Builder
	var nameCount, guestTypeCount, emulatorCount int
	var architecture string

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("malformed XML: %w", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != "" {
				return errors.New("XML extension namespaces are unsupported")
			}
			if len(path) == 0 {
				if rootSeen || value.Name.Local != "domain" || value.Name.Space != "" {
					return errors.New("XML must have one domain root")
				}
				rootSeen = true
				for _, attr := range value.Attr {
					if attr.Name.Local == "type" && attr.Name.Space == "" {
						rootType = attr.Value
					}
				}
			} else if len(path) == 2 && plainXMLName(path[0], "domain") &&
				plainXMLName(path[1], "name") {
				return errors.New("domain name must contain only text")
			}
			if len(path) == 3 && plainXMLName(path[1], "devices") && plainXMLName(path[2], "emulator") {
				return errors.New("emulator must contain only text")
			}
			if len(path) == 1 && value.Name.Local == "name" && value.Name.Space == "" {
				nameCount++
			}
			if len(path) == 2 && plainXMLName(path[1], "devices") && plainXMLName(value.Name, "emulator") {
				emulatorCount++
			}
			if len(path) == 2 && plainXMLName(path[1], "os") && plainXMLName(value.Name, "type") {
				guestTypeCount++
				for _, attr := range value.Attr {
					if attr.Name.Local == "arch" && attr.Name.Space == "" {
						architecture = attr.Value
					}
				}
			}
			path = append(path, value.Name)
		case xml.EndElement:
			if len(path) == 0 {
				return errors.New("unexpected XML close tag")
			}
			path = path[:len(path)-1]
		case xml.CharData:
			if len(path) == 0 && len(strings.TrimSpace(string(value))) != 0 {
				return errors.New("unexpected text outside domain root")
			}
			if len(path) == 2 && plainXMLName(path[0], "domain") && plainXMLName(path[1], "name") {
				xmlName.Write(value)
			}
			if len(path) == 3 && plainXMLName(path[0], "domain") && plainXMLName(path[1], "os") && plainXMLName(path[2], "type") {
				guestType.Write(value)
			}
			if len(path) == 3 && plainXMLName(path[0], "domain") && plainXMLName(path[1], "devices") && plainXMLName(path[2], "emulator") {
				emulator.Write(value)
			}
		case xml.Directive:
			return errors.New("XML directives are not allowed")
		case xml.ProcInst:
			if rootSeen || value.Target != "xml" {
				return errors.New("XML processing instructions are not allowed")
			}
		}
	}
	if !rootSeen || len(path) != 0 {
		return errors.New("incomplete domain XML")
	}
	if rootType != "kvm" {
		return errors.New("domain type must be kvm")
	}
	if nameCount != 1 || strings.TrimSpace(xmlName.String()) != name {
		return errors.New("XML domain name does not match desired name")
	}
	if guestTypeCount != 1 || architecture != "x86_64" || strings.TrimSpace(guestType.String()) != "hvm" {
		return errors.New("domain must target x86_64 hvm")
	}
	if emulatorCount > 1 || emulatorCount == 1 && strings.TrimSpace(emulator.String()) != "/usr/bin/qemu-system-x86_64" {
		return errors.New("domain emulator must be /usr/bin/qemu-system-x86_64")
	}
	return nil
}

func validateReport(nodeID string, report protocol.Report) error {
	if report.APIVersion != protocol.APIVersion {
		return errors.New("unsupported api_version")
	}
	if report.NodeID != nodeID {
		return errors.New("report node_id does not match URL")
	}
	if !validRevision(report.Revision) {
		return errors.New("invalid revision")
	}
	if len(report.Domains) > maxDomains {
		return errors.New("too many domain statuses")
	}
	if !printableString(report.Error, 4096) {
		return errors.New("invalid report error")
	}
	names := make(map[string]struct{}, len(report.Domains))
	for _, domain := range report.Domains {
		if !validDomainName(domain.Name) || !printableString(domain.State, 64) || domain.State == "" {
			return errors.New("invalid domain status")
		}
		if _, exists := names[domain.Name]; exists {
			return fmt.Errorf("duplicate domain status %q", domain.Name)
		}
		names[domain.Name] = struct{}{}
	}
	return nil
}

func printableString(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, ch := range value {
		if unicode.IsControl(ch) {
			return false
		}
	}
	return true
}

func plainXMLName(name xml.Name, want string) bool {
	return name.Local == want && name.Space == ""
}
