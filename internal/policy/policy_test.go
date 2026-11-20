package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		in   string
		want []string // nil means rejected
	}{
		{"/api2/json/version", []string{"version"}},
		{"/api2/json/nodes/pve1/qemu/100/status/current", []string{"nodes", "pve1", "qemu", "100", "status", "current"}},
		{"/api2/json/nodes/pve-1.lan/tasks/UPID:pve1:0001:00AB:6560F00D:qmstart:100:root@pam!tok:/status",
			[]string{"nodes", "pve-1.lan", "tasks", "UPID:pve1:0001:00AB:6560F00D:qmstart:100:root@pam!tok:", "status"}},
		{"/api2/json/nodes/pve%31", []string{"nodes", "pve1"}},
		{"/api2/json/nodes/a%3Ab", []string{"nodes", "a:b"}},
		{"/api2/json/storage/local_lvm~x", []string{"storage", "local_lvm~x"}},
		{"/api2/json/a.b", []string{"a.b"}},

		// Outside /api2/json/.
		{"", nil},
		{"/", nil},
		{"/api2/json", nil},
		{"/api2/json/", nil},
		{"/api2/extjs/version", nil},
		{"/api2/JSON/version", nil},
		{"/API2/json/version", nil},
		{"//api2/json/version", nil},
		{"/x/api2/json/version", nil},
		{"/api2/json%2Fversion", nil},

		// Dot segments, literal and encoded.
		{"/api2/json/..", nil},
		{"/api2/json/.", nil},
		{"/api2/json/nodes/../access/users", nil},
		{"/api2/json/nodes/./pve1", nil},
		{"/api2/json/nodes/%2e%2e/access", nil},
		{"/api2/json/nodes/%2E%2E/access", nil},
		{"/api2/json/nodes/.%2e/access", nil},
		{"/api2/json/nodes/%2e/pve1", nil},
		{"/api2/json/nodes/a%2eb", nil},
		{"/api2/json/nodes/%252e%252e/access", nil},
		{"/api2/json/nodes/%25", nil},

		// Empty segments.
		{"/api2/json//version", nil},
		{"/api2/json/nodes//pve1", nil},
		{"/api2/json/nodes/", nil},
		{"/api2/json/version/", nil},

		// Encoded separators and other bytes.
		{"/api2/json/nodes/pve1%2Fqemu", nil},
		{"/api2/json/nodes/pve1%2fqemu", nil},
		{"/api2/json/nodes/pve1%5Cqemu", nil},
		{"/api2/json/nodes/pve1\\qemu", nil},
		{"/api2/json/nodes/pve1\\..\\access", nil},
		{"/api2/json/nodes/pve1%00", nil},
		{"/api2/json/nodes/pve1\x00", nil},
		{"/api2/json/nodes/pve1%0a", nil},
		{"/api2/json/nodes/pve1%20", nil},
		{"/api2/json/nodes/pve1 x", nil},
		{"/api2/json/nodes/p%C3%A9", nil},
		{"/api2/json/nodes/pé", nil},
		{"/api2/json/nodes/pve1;x", nil},
		{"/api2/json/nodes/pve1?x", nil},
		{"/api2/json/nodes/pve1#x", nil},
		{"/api2/json/nodes/%", nil},
		{"/api2/json/nodes/%2", nil},
		{"/api2/json/nodes/%zz", nil},
		{"/api2/json/" + strings.Repeat("a", MaxPathLen), nil},
	}
	for _, tt := range tests {
		got, err := Normalize(tt.in)
		if tt.want == nil {
			if err == nil {
				t.Errorf("Normalize(%q) = %v, want rejection", tt.in, got.Segments)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got.Segments, tt.want) {
			t.Errorf("Normalize(%q) = %v, %v; want %v", tt.in, got.Segments, err, tt.want)
		}
	}
}

func TestPathString(t *testing.T) {
	p, err := Normalize("/api2/json/nodes/pve%31/status")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.String(); got != "/api2/json/nodes/pve1/status" {
		t.Fatalf("String() = %q", got)
	}
}

func TestProfiles(t *testing.T) {
	type check struct {
		method, path string
		readOnly     bool
		operator     bool
	}
	tests := []check{
		// Reads.
		{"GET", "/api2/json/version", true, true},
		{"HEAD", "/api2/json/version", true, true},
		{"GET", "/api2/json/cluster/resources", true, true},
		{"GET", "/api2/json/cluster/status", true, true},
		{"GET", "/api2/json/nodes", true, true},
		{"GET", "/api2/json/nodes/pve1/status", true, true},
		{"GET", "/api2/json/nodes/pve1/qemu", true, true},
		{"GET", "/api2/json/nodes/pve1/qemu/100/status/current", true, true},
		{"GET", "/api2/json/nodes/pve1/lxc/101/status/current", true, true},
		{"GET", "/api2/json/nodes/pve1/storage/local/status", true, true},
		{"GET", "/api2/json/nodes/pve1/tasks/UPID:pve1:1:2:3:qmstart:100:root@pam:/status", true, true},

		// Operator only.
		{"POST", "/api2/json/nodes/pve1/qemu/100/status/start", false, true},
		{"POST", "/api2/json/nodes/pve1/qemu/100/status/shutdown", false, true},
		{"POST", "/api2/json/nodes/pve1/lxc/101/status/reboot", false, true},
		{"POST", "/api2/json/nodes/pve1/qemu/100/vncproxy", false, true},
		{"POST", "/api2/json/nodes/pve1/lxc/101/termproxy", false, true},
		{"GET", "/api2/json/nodes/pve1/qemu/100/vncwebsocket", false, true},
		{"GET", "/api2/json/nodes/pve1/tasks/UPID:x/log", false, true},

		// Wrong method or shape.
		{"GET", "/api2/json/nodes/pve1/qemu/100/status/start", false, false},
		{"PUT", "/api2/json/nodes/pve1/qemu/100/status/start", false, false},
		{"DELETE", "/api2/json/nodes/pve1/qemu/100", false, false},
		{"POST", "/api2/json/nodes/pve1/qemu/100/status/current", false, false},
		{"POST", "/api2/json/nodes/pve1/lxc/101/status/reset", false, false},
		{"OPTIONS", "/api2/json/version", false, false},
		{"GET", "/api2/json/nodes/pve1/qemu/100/status/current/extra", false, false},
		{"GET", "/api2/json/nodes/pve1/qemu/100/status", false, false},

		// Root-equivalent endpoints stay blocked in every profile.
		{"POST", "/api2/json/nodes/pve1/termproxy", false, false},
		{"POST", "/api2/json/nodes/pve1/vncshell", false, false},
		{"POST", "/api2/json/nodes/pve1/spiceshell", false, false},
		{"GET", "/api2/json/nodes/pve1/vncwebsocket", false, false},
		{"POST", "/api2/json/nodes/pve1/execute", false, false},
		{"GET", "/api2/json/access/users", false, false},
		{"POST", "/api2/json/access/users", false, false},
		{"PUT", "/api2/json/access/acl", false, false},
		{"POST", "/api2/json/access/ticket", false, false},
		{"PUT", "/api2/json/access/password", false, false},
		{"POST", "/api2/json/access/users/root@pam/token/x", false, false},
		{"GET", "/api2/json/nodes/pve1/apt/update", false, false},
		{"POST", "/api2/json/nodes/pve1/apt/update", false, false},
		{"POST", "/api2/json/nodes/pve1/ceph/osd", false, false},
		{"POST", "/api2/json/nodes/pve1/ceph/init", false, false},
		{"POST", "/api2/json/storage", false, false},
		{"PUT", "/api2/json/storage/local", false, false},
		{"DELETE", "/api2/json/storage/local", false, false},
		{"POST", "/api2/json/nodes/pve1/network", false, false},
		{"PUT", "/api2/json/nodes/pve1/network", false, false},
		{"PUT", "/api2/json/nodes/pve1/network/vmbr0", false, false},
		{"POST", "/api2/json/nodes/pve1/storage/local/upload", false, false},
		{"PUT", "/api2/json/nodes/pve1/qemu/100/config", false, false},
		{"POST", "/api2/json/nodes/pve1/qemu/100/config", false, false},
		{"POST", "/api2/json/cluster/config", false, false},
		{"PUT", "/api2/json/cluster/firewall/options", false, false},
		{"POST", "/api2/json/nodes/pve1/certificates/custom", false, false},
	}
	ro, err := ForProfile("read-only")
	if err != nil {
		t.Fatal(err)
	}
	op, err := ForProfile("operator")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		p, err := Normalize(tt.path)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", tt.path, err)
		}
		if got := ro.Allow(tt.method, p); got != tt.readOnly {
			t.Errorf("read-only %s %s = %v, want %v", tt.method, tt.path, got, tt.readOnly)
		}
		if got := op.Allow(tt.method, p); got != tt.operator {
			t.Errorf("operator %s %s = %v, want %v", tt.method, tt.path, got, tt.operator)
		}
	}
}

func TestUnknownProfile(t *testing.T) {
	if _, err := ForProfile("admin"); err == nil {
		t.Fatal("expected error")
	}
}

func TestEmptyPolicyDeniesEverything(t *testing.T) {
	p, _ := New("empty", nil)
	path, _ := Normalize("/api2/json/version")
	if p.Allow("GET", path) {
		t.Fatal("empty policy allowed a request")
	}
}
