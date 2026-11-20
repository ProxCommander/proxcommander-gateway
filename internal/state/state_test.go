package state

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
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

func TestUpdateConcurrent(t *testing.T) {
	dir := t.TempDir()
	fp := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	const n = 20
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- Update(dir, func(s *State) error {
				s.Nodes = append(s.Nodes, Node{Name: fmt.Sprintf("n%d", i), URL: "https://h:8006", Fingerprints: []string{fp}})
				return nil
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	s, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes) != n {
		t.Fatalf("got %d nodes, want %d: lost updates", len(s.Nodes), n)
	}
}

func TestUpdateErrorDoesNotSave(t *testing.T) {
	dir := t.TempDir()
	err := Update(dir, func(s *State) error {
		s.Profile = "operator"
		return errors.New("stop")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(Path(dir)); !os.IsNotExist(err) {
		t.Fatalf("state saved despite error: %v", err)
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
