package state

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadMissingReturnsDefault(t *testing.T) {
	s, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s, Default()) {
		t.Fatalf("got %+v, want default", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir() + "/nested"
	s := Default()
	s.Profile = "operator"
	s.Nodes = append(s.Nodes, Node{
		Name:         "pve1",
		URL:          "https://10.0.0.1:8006",
		Fingerprints: []string{strings.TrimSuffix(strings.Repeat("AB:", 32), ":")},
		AddedAt:      time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	})
	if err := s.Save(dir); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(Path(dir))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	got, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatalf("round trip: got %+v, want %+v", got, s)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftover temp files: %v", entries)
	}
}

func TestLoadRejectsBadNode(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(Path(dir), []byte(`{"nodes":[{"name":"x","url":"http://h:8006","fingerprints":["AA"]}]}`), 0o600)
	if _, err := Load(dir); err == nil {
		t.Fatal("expected error")
	}
}

func TestNormalizeNodeURL(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"https://pve1:8006", "https://pve1:8006", false},
		{"https://pve1", "https://pve1:8006", false},
		{"https://10.0.0.1:443/", "https://10.0.0.1:443", false},
		{"https://[fd00::1]:8006", "https://[fd00::1]:8006", false},
		{"http://pve1:8006", "", true},
		{"https://pve1:8006/api2", "", true},
		{"https://user@pve1:8006", "", true},
		{"https://pve1:8006?x=1", "", true},
		{"pve1:8006", "", true},
		{"https://", "", true},
	}
	for _, tt := range tests {
		got, err := NormalizeNodeURL(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("NormalizeNodeURL(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}
