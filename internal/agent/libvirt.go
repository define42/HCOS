package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/define42/HCOS/internal/protocol"
)

const (
	maxDomains   = 32
	maxDomainXML = 256 << 10
)

type domainDefinition struct {
	XMLName xml.Name `xml:"domain"`
	Type    string   `xml:"type,attr"`
	Name    string   `xml:"name"`
	OS      struct {
		Type struct {
			Arch string `xml:"arch,attr"`
			Text string `xml:",chardata"`
		} `xml:"type"`
	} `xml:"os"`
	Devices struct {
		Emulator string `xml:"emulator"`
	} `xml:"devices"`
}

func validateDesired(desired protocol.DesiredState) error {
	if desired.APIVersion != protocol.APIVersion {
		return fmt.Errorf("unsupported desired-state API version %q", desired.APIVersion)
	}
	if desired.Revision == "" || len(desired.Revision) > 128 || strings.ContainsAny(desired.Revision, "\r\n") {
		return errors.New("invalid desired-state revision")
	}
	if len(desired.Domains) > maxDomains {
		return fmt.Errorf("desired state exceeds %d domains", maxDomains)
	}
	seen := make(map[string]struct{}, len(desired.Domains))
	for _, domain := range desired.Domains {
		if !identifierRE.MatchString(domain.Name) {
			return errors.New("invalid domain name")
		}
		if _, exists := seen[domain.Name]; exists {
			return fmt.Errorf("duplicate domain %q", domain.Name)
		}
		seen[domain.Name] = struct{}{}
		if err := validateDomainXML(domain); err != nil {
			return fmt.Errorf("domain %q: %w", domain.Name, err)
		}
	}
	return nil
}

func validateDomainXML(domain protocol.Domain) error {
	if len(domain.XML) == 0 || len(domain.XML) > maxDomainXML {
		return fmt.Errorf("XML must be between 1 and %d bytes", maxDomainXML)
	}
	decoder := xml.NewDecoder(strings.NewReader(domain.XML))
	var definition domainDefinition
	if err := decoder.Decode(&definition); err != nil {
		return fmt.Errorf("parse XML: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("XML must contain one domain element")
	}
	if definition.XMLName.Local != "domain" || definition.XMLName.Space != "" || definition.Type != "kvm" {
		return errors.New("XML must define a KVM domain")
	}
	if definition.Name != domain.Name {
		return errors.New("XML name does not match desired domain name")
	}
	if definition.OS.Type.Arch != "x86_64" || strings.TrimSpace(definition.OS.Type.Text) != "hvm" {
		return errors.New("XML must target an x86_64 HVM guest")
	}
	emulator := strings.TrimSpace(definition.Devices.Emulator)
	if emulator != "" && emulator != "/usr/bin/qemu-system-x86_64" {
		return errors.New("XML emulator must be /usr/bin/qemu-system-x86_64")
	}
	// Reject extension namespaces such as qemu:commandline. These can change
	// QEMU arguments outside the small XML contract understood by HCOS.
	decoder = xml.NewDecoder(strings.NewReader(domain.XML))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("parse XML: %w", err)
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != "" {
				return errors.New("XML extension namespaces are unsupported")
			}
		case xml.Directive:
			return errors.New("XML directives are unsupported")
		}
	}
	return nil
}

func (a *Agent) reconcileDomain(ctx context.Context, domain protocol.Domain) (string, error) {
	hash := sha256.Sum256([]byte(domain.XML))
	if a.lastDefined[domain.Name] != hash {
		if err := a.defineDomain(ctx, domain.XML); err != nil {
			return "unknown", err
		}
		a.lastDefined[domain.Name] = hash
	}
	state, err := a.domainState(ctx, domain.Name)
	if err != nil {
		// A locally removed domain is restored even when the desired revision
		// has not changed. A libvirt outage still surfaces as a report error.
		if defineErr := a.defineDomain(ctx, domain.XML); defineErr != nil {
			return "unknown", errors.Join(err, defineErr)
		}
		state, err = a.domainState(ctx, domain.Name)
		if err != nil {
			return "unknown", err
		}
	}

	var action string
	if domain.Running {
		switch state {
		case "running", "blocked", "in shutdown":
			return state, nil
		case "paused":
			action = "resume"
		case "shut off", "crashed":
			action = "start"
		default:
			return state, fmt.Errorf("unsupported domain state %q", state)
		}
	} else {
		switch state {
		case "shut off", "crashed", "in shutdown":
			return state, nil
		case "running", "blocked", "paused":
			action = "shutdown"
		default:
			return state, fmt.Errorf("unsupported domain state %q", state)
		}
	}
	if action == "start" || action == "resume" {
		if err := a.storageReady(); err != nil {
			return state, err
		}
	}
	if _, err := a.virsh(ctx, action, domain.Name); err != nil {
		return state, err
	}
	return a.domainState(ctx, domain.Name)
}

func (a *Agent) storageReady() error {
	path := a.config.Storage.Path
	if path == "" {
		return nil
	}
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return fmt.Errorf("read mount table: %w", err)
	}
	defer file.Close()
	if !mountedPath(file, path) {
		return fmt.Errorf("storage path %q is not mounted", path)
	}
	return nil
}

func mountedPath(mountInfo io.Reader, path string) bool {
	scanner := bufio.NewScanner(mountInfo)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && decodeMountPath(fields[4]) == path {
			return true
		}
	}
	return false
}

func decodeMountPath(path string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(path)
}

func (a *Agent) defineDomain(ctx context.Context, document string) error {
	file, err := os.CreateTemp("", "hcos-domain-*.xml")
	if err != nil {
		return fmt.Errorf("create domain XML file: %w", err)
	}
	defer os.Remove(file.Name())
	if _, err := io.WriteString(file, document); err != nil {
		file.Close()
		return fmt.Errorf("write domain XML file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close domain XML file: %w", err)
	}
	_, err = a.virsh(ctx, "define", file.Name())
	return err
}

func (a *Agent) domainState(ctx context.Context, name string) (string, error) {
	state, err := a.virsh(ctx, "domstate", name)
	if err != nil {
		return "unknown", err
	}
	return strings.ToLower(strings.TrimSpace(state)), nil
}

func (a *Agent) virsh(ctx context.Context, args ...string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	command := exec.CommandContext(commandCtx, a.options.VirshPath, append([]string{"-c", "qemu:///system"}, args...)...)
	command.Env = append(os.Environ(), "LC_ALL=C")
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(stderr.String())
		if len(message) > 512 {
			message = message[:512]
		}
		if message != "" {
			return "", fmt.Errorf("virsh %s: %w: %s", args[0], err, message)
		}
		return "", fmt.Errorf("virsh %s: %w", args[0], err)
	}
	return strings.TrimSpace(stdout.String()), nil
}
