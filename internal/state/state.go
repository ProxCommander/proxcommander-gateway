// Package state loads and saves the gateway's persistent state: one JSON
// file, mode 0600, replaced atomically on every write.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProxCommander/proxcommander-gateway/internal/pin"
)

// FileName is the state file's name inside the state directory.
const FileName = "state.json"

// LockName is the lock file that serialises writers.
const LockName = "state.lock"

// DefaultCORSOrigins are allowed when the state does not list any: the
// hosted web app only. Development origins are opt-in (--cors-origins).
var DefaultCORSOrigins = []string{"https://proxcommander.app"}

// DefaultProfile is the least-privileged built-in profile.
const DefaultProfile = "read-only"

// State is the persisted gateway configuration.
type State struct {
	Version     int      `json:"version"`
	Nodes       []Node   `json:"nodes"`
	CORSOrigins []string `json:"cors_origins"`
	Profile     string   `json:"profile"`
}

// Node is one Proxmox node and the certificate fingerprints pinned for it.
type Node struct {
	Name         string    `json:"name"`
	URL          string    `json:"url"`
	Fingerprints []string  `json:"fingerprints"`
	AddedAt      time.Time `json:"added_at"`
}

// Default returns the state used when no file exists yet.
func Default() *State {
	return &State{
		Version:     1,
		Nodes:       []Node{},
		CORSOrigins: append([]string(nil), DefaultCORSOrigins...),
		Profile:     DefaultProfile,
	}
}

// Path returns the state file path inside dir.
func Path(dir string) string { return filepath.Join(dir, FileName) }

// Load reads the state from dir, returning Default() if the file is missing.
func Load(dir string) (*State, error) {
	b, err := os.ReadFile(Path(dir))
	if errors.Is(err, fs.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	s := Default()
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("state: parse %s: %w", Path(dir), err)
	}
	if s.Nodes == nil {
		s.Nodes = []Node{}
	}
	if s.Profile == "" {
		s.Profile = DefaultProfile
	}
	for _, n := range s.Nodes {
		if err := n.Validate(); err != nil {
			return nil, fmt.Errorf("state: node %q: %w", n.Name, err)
		}
	}
	return s, nil
}

// Update loads the state under an exclusive lock, applies fn and saves the
// result, so concurrent writers (for example two "nodes add" runs) cannot
// lose each other's changes. Nothing is saved if fn returns an error.
func Update(dir string, fn func(*State) error) error {
	unlock, err := lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	s, err := Load(dir)
	if err != nil {
		return err
	}
	if err := fn(s); err != nil {
		return err
	}
	return s.Save(dir)
}

// Save writes the state to dir atomically with mode 0600.
func (s *State) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), Path(dir)); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// FindNode returns the index of the node whose name or URL matches key, or -1.
func (s *State) FindNode(key string) int {
	for i, n := range s.Nodes {
		if n.Name == key || n.URL == key {
			return i
		}
	}
	return -1
}

// Validate checks a node's URL and pins.
func (n Node) Validate() error {
	if n.Name == "" {
		return errors.New("empty name")
	}
	if _, err := NormalizeNodeURL(n.URL); err != nil {
		return err
	}
	if len(n.Fingerprints) == 0 {
		return errors.New("no pinned fingerprints")
	}
	for _, fp := range n.Fingerprints {
		if _, err := pin.ParseFingerprint(fp); err != nil {
			return err
		}
	}
	return nil
}

// NormalizeNodeURL validates https://host[:port] and returns it with the
// port made explicit (8006 by default) and no path.
func NormalizeNodeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid node URL %q: %w", raw, err)
	}
	if u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("invalid node URL %q: want https://host:port", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("invalid node URL %q: must not have a path", raw)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return "", fmt.Errorf("invalid node URL %q: missing host", raw)
	}
	if port == "" {
		port = "8006"
	}
	return "https://" + net.JoinHostPort(host, port), nil
}
