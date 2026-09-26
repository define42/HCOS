package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/define42/HCOS/internal/protocol"
)

const validDomainXML = "<domain type='kvm'><name>vm-01</name><os><type arch='x86_64'>hvm</type></os><memory unit='MiB'>512</memory></domain>"

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		ServerIP:   "127.0.0.1",
		StateDir:   filepath.Join(t.TempDir(), "state"),
		AdminToken: strings.Repeat("a", 40),
		Nodes: []NodeCredential{
			{ID: "compute-01", Token: strings.Repeat("b", 40)},
			{ID: "compute-02", Token: strings.Repeat("c", 40)},
		},
	}
}

func testHandler(t *testing.T, config Config) *Handler {
	t.Helper()
	store, err := OpenStore(config.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(config, store)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func request(handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	var payload []byte
	if body != nil {
		switch value := body.(type) {
		case []byte:
			payload = value
		default:
			payload, _ = json.Marshal(value)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(payload))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func TestHandlerRoundTripAndPersistence(t *testing.T) {
	config := testConfig(t)
	handler := testHandler(t, config)
	path := "/v1/nodes/compute-01"
	nodeToken := config.Nodes[0].Token

	initial := request(handler, http.MethodGet, path+"/desired", nodeToken, nil)
	if initial.Code != http.StatusOK {
		t.Fatalf("initial desired status = %d, want 200", initial.Code)
	}
	var desired protocol.DesiredState
	if err := json.Unmarshal(initial.Body.Bytes(), &desired); err != nil {
		t.Fatal(err)
	}
	if desired.APIVersion != protocol.APIVersion || desired.Revision != "0" || desired.Domains == nil || len(desired.Domains) != 0 {
		t.Fatalf("unexpected initial desired state: %+v", desired)
	}

	target := protocol.DesiredState{
		APIVersion: protocol.APIVersion,
		Revision:   "release-1",
		Domains: []protocol.Domain{{
			Name: "vm-01", XML: validDomainXML, Running: true,
		}},
	}
	if got := request(handler, http.MethodPut, path+"/desired", config.AdminToken, target).Code; got != http.StatusNoContent {
		t.Fatalf("PUT desired status = %d, want 204", got)
	}
	changedWithoutRevision := target
	changedWithoutRevision.Domains = []protocol.Domain{{Name: "vm-01", XML: validDomainXML, Running: false}}
	if got := request(handler, http.MethodPut, path+"/desired", config.AdminToken, changedWithoutRevision).Code; got != http.StatusConflict {
		t.Fatalf("changed content with reused revision status = %d, want 409", got)
	}
	if got := request(handler, http.MethodPut, path+"/desired", config.AdminToken, target).Code; got != http.StatusNoContent {
		t.Fatalf("idempotent PUT status = %d, want 204", got)
	}
	fetched := request(handler, http.MethodGet, path+"/desired", nodeToken, nil)
	if err := json.Unmarshal(fetched.Body.Bytes(), &desired); err != nil {
		t.Fatal(err)
	}
	if fetched.Code != http.StatusOK || desired.Revision != target.Revision || len(desired.Domains) != 1 {
		t.Fatalf("unexpected desired response: status=%d state=%+v", fetched.Code, desired)
	}

	report := protocol.Report{
		APIVersion: protocol.APIVersion,
		NodeID:     "compute-01",
		Revision:   "release-1",
		Domains:    []protocol.DomainStatus{{Name: "vm-01", State: "running"}},
	}
	if got := request(handler, http.MethodPost, path+"/report", nodeToken, report).Code; got != http.StatusNoContent {
		t.Fatalf("POST report status = %d, want 204", got)
	}
	restarted := testHandler(t, config)
	fetched = request(restarted, http.MethodGet, path+"/desired", nodeToken, nil)
	if err := json.Unmarshal(fetched.Body.Bytes(), &desired); err != nil {
		t.Fatal(err)
	}
	if fetched.Code != http.StatusOK || desired.Revision != target.Revision {
		t.Fatalf("desired state did not survive restart: status=%d state=%+v", fetched.Code, desired)
	}
	observed := request(restarted, http.MethodGet, path+"/report", config.AdminToken, nil)
	var persisted protocol.Report
	if err := json.Unmarshal(observed.Body.Bytes(), &persisted); err != nil {
		t.Fatal(err)
	}
	if observed.Code != http.StatusOK || persisted.NodeID != report.NodeID || persisted.Revision != report.Revision {
		t.Fatalf("report did not survive restart: status=%d report=%+v", observed.Code, persisted)
	}
}

func TestHandlerAuthorization(t *testing.T) {
	config := testConfig(t)
	handler := testHandler(t, config)
	path := "/v1/nodes/compute-01"
	target := protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1"}
	report := protocol.Report{APIVersion: protocol.APIVersion, NodeID: "compute-01", Revision: "1"}
	cases := []struct {
		name   string
		method string
		path   string
		token  string
		body   any
		want   int
	}{
		{name: "missing token", method: http.MethodGet, path: path + "/desired", want: http.StatusUnauthorized},
		{name: "wrong node token", method: http.MethodGet, path: path + "/desired", token: config.Nodes[1].Token, want: http.StatusUnauthorized},
		{name: "node cannot write desired", method: http.MethodPut, path: path + "/desired", token: config.Nodes[0].Token, body: target, want: http.StatusForbidden},
		{name: "admin cannot claim node report", method: http.MethodPost, path: path + "/report", token: config.AdminToken, body: report, want: http.StatusForbidden},
		{name: "node cannot read report", method: http.MethodGet, path: path + "/report", token: config.Nodes[0].Token, want: http.StatusForbidden},
		{name: "unknown node for admin", method: http.MethodGet, path: "/v1/nodes/unknown/desired", token: config.AdminToken, want: http.StatusNotFound},
		{name: "unconfigured token", method: http.MethodGet, path: path + "/desired", token: strings.Repeat("x", 40), want: http.StatusUnauthorized},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			response := request(handler, test.method, test.path, test.token, test.body)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response must disable caching")
			}
		})
	}
}

func TestHandlerValidationAndLimits(t *testing.T) {
	config := testConfig(t)
	handler := testHandler(t, config)
	path := "/v1/nodes/compute-01/desired"
	cases := []struct {
		name    string
		desired protocol.DesiredState
	}{
		{name: "unsupported version", desired: protocol.DesiredState{APIVersion: "hcos/v2", Revision: "1"}},
		{name: "invalid revision", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "../1"}},
		{name: "XML name mismatch", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "another", XML: validDomainXML}}}},
		{name: "non x86 architecture", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "vm-01", XML: strings.Replace(validDomainXML, "x86_64", "aarch64", 1)}}}},
		{name: "non KVM driver", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "vm-01", XML: strings.Replace(validDomainXML, "kvm", "qemu", 1)}}}},
		{name: "XML extension namespace", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "vm-01", XML: strings.Replace(validDomainXML, "</domain>", "<qemu:commandline xmlns:qemu='http://libvirt.org/schemas/domain/qemu'/></domain>", 1)}}}},
		{name: "other emulator", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "vm-01", XML: strings.Replace(validDomainXML, "</domain>", "<devices><emulator>/tmp/qemu</emulator></devices></domain>", 1)}}}},
		{name: "too many domains", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: make([]protocol.Domain, maxDomains+1)}},
		{name: "oversized domain XML", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "vm-01", XML: strings.Repeat("x", maxDomainXML+1)}}}},
		{name: "XML directive", desired: protocol.DesiredState{APIVersion: protocol.APIVersion, Revision: "1", Domains: []protocol.Domain{{Name: "vm-01", XML: "<!DOCTYPE domain>" + validDomainXML}}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := request(handler, http.MethodPut, path, config.AdminToken, test.desired).Code; got != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", got)
			}
		})
	}
	tooLarge := request(handler, http.MethodPut, path, config.AdminToken, []byte(strings.Repeat(" ", maxDesiredBytes+1)))
	if tooLarge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want 413", tooLarge.Code)
	}
	untouched := request(handler, http.MethodGet, path, config.Nodes[0].Token, nil)
	var desired protocol.DesiredState
	if err := json.Unmarshal(untouched.Body.Bytes(), &desired); err != nil {
		t.Fatal(err)
	}
	if desired.Revision != "0" {
		t.Fatalf("rejected updates changed desired revision to %q", desired.Revision)
	}
	badReport := protocol.Report{APIVersion: protocol.APIVersion, NodeID: "compute-02", Revision: "1"}
	if got := request(handler, http.MethodPost, "/v1/nodes/compute-01/report", config.Nodes[0].Token, badReport).Code; got != http.StatusBadRequest {
		t.Fatalf("mismatched report status = %d, want 400", got)
	}
}

func TestHandlerHealthAndReady(t *testing.T) {
	config := testConfig(t)
	handler := testHandler(t, config)
	if got := request(handler, http.MethodGet, "/healthz", "", nil).Code; got != http.StatusOK {
		t.Fatalf("health status = %d", got)
	}
	if got := request(handler, http.MethodGet, "/readyz", "", nil).Code; got != http.StatusOK {
		t.Fatalf("ready status = %d", got)
	}
}

func TestHandlerConcurrentAgents(t *testing.T) {
	config := testConfig(t)
	handler := testHandler(t, config)
	var workers sync.WaitGroup
	failures := make(chan int, 32)
	for _, node := range config.Nodes {
		for index := 0; index < 16; index++ {
			workers.Add(1)
			go func(node NodeCredential, index int) {
				defer workers.Done()
				report := protocol.Report{
					APIVersion: protocol.APIVersion,
					NodeID:     node.ID,
					Revision:   strconv.Itoa(index),
				}
				path := "/v1/nodes/" + node.ID + "/report"
				if status := request(handler, http.MethodPost, path, node.Token, report).Code; status != http.StatusNoContent {
					failures <- status
				}
			}(node, index)
		}
	}
	workers.Wait()
	close(failures)
	for status := range failures {
		t.Fatalf("concurrent report status = %d, want 204", status)
	}
	for _, node := range config.Nodes {
		path := "/v1/nodes/" + node.ID + "/report"
		response := request(handler, http.MethodGet, path, config.AdminToken, nil)
		var report protocol.Report
		if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if response.Code != http.StatusOK || report.NodeID != node.ID {
			t.Fatalf("concurrent report for %s: status=%d report=%+v", node.ID, response.Code, report)
		}
	}
}
