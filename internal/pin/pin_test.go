package pin

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/ProxCommander/proxcommander-gateway/internal/testpki"
)

func TestParseFingerprint(t *testing.T) {
	canon := strings.TrimSuffix(strings.Repeat("AB:", 32), ":")
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{canon, canon, false},
		{strings.ToLower(canon), canon, false},
		{strings.Repeat("ab", 32), canon, false},
		{"  " + canon + "\n", canon, false},
		{strings.Repeat("ab", 31), "", true},
		{strings.Repeat("zz", 32), "", true},
		{"", "", true},
	}
	for _, tt := range tests {
		got, err := ParseFingerprint(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseFingerprint(%q) = %q, %v; want %q, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestVerify(t *testing.T) {
	withPublicRoots(t)
	ca := testpki.CA(t, "cluster CA")
	leaf := testpki.Leaf(t, "node1", ca)
	otherCA := testpki.CA(t, "attacker CA")
	evil := testpki.Leaf(t, "node1", otherCA)
	selfLeaf := testpki.CA(t, "self-signed node")

	fp := func(c testpki.Cert) string { return Fingerprint(c.Cert.Raw) }
	chain := func(cs ...testpki.Cert) []*x509.Certificate {
		var out []*x509.Certificate
		for _, c := range cs {
			out = append(out, c.Cert)
		}
		return out
	}

	tests := []struct {
		name  string
		pins  []string
		chain []*x509.Certificate
		ok    bool
	}{
		{"leaf pin", []string{fp(leaf)}, chain(leaf, ca), true},
		{"leaf pin, leaf only", []string{fp(leaf)}, chain(leaf), true},
		{"self-signed leaf pin", []string{fp(selfLeaf)}, chain(selfLeaf), true},
		{"ca pin", []string{fp(ca)}, chain(leaf, ca), true},
		{"one of several pins", []string{fp(otherCA), fp(ca)}, chain(leaf, ca), true},
		{"lower-case pin", []string{strings.ToLower(fp(leaf))}, chain(leaf), true},
		{"wrong pin", []string{fp(otherCA)}, chain(leaf, ca), false},
		{"ca pin but ca not presented", []string{fp(ca)}, chain(leaf), false},
		{"attacker leaf with genuine ca appended", []string{fp(ca)}, chain(evil, ca), false},
		{"attacker leaf with both cas appended", []string{fp(ca)}, chain(evil, otherCA, ca), false},
		{"pinned ca presented as leaf only matches itself", []string{fp(ca)}, chain(ca), true},
		{"no pins", nil, chain(leaf, ca), false},
		{"no chain", []string{fp(leaf)}, nil, false},
		{"bad pin", []string{"nope"}, chain(leaf), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify(tt.pins, tt.chain, "127.0.0.1")
			if (err == nil) != tt.ok {
				t.Fatalf("Verify() error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestTLSConfigRequiresPins(t *testing.T) {
	if _, err := TLSConfig(nil, "h"); err == nil {
		t.Fatal("TLSConfig without pins succeeded")
	}
	if _, err := TLSConfig([]string{"bad"}, "h"); err == nil {
		t.Fatal("TLSConfig with a malformed pin succeeded")
	}
	cfg, err := TLSConfig([]string{Fingerprint([]byte("x"))}, "h")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("VerifyConnection not set")
	}
}

func TestAutoPin(t *testing.T) {
	withPublicRoots(t)
	ca := testpki.CA(t, "cluster CA")
	leaf := testpki.Leaf(t, "node1", ca)
	inter := testpki.Leaf(t, "not a CA", ca)

	if got := AutoPin([]*x509.Certificate{leaf.Cert, ca.Cert}); got != 1 {
		t.Errorf("leaf+CA: got %d, want 1", got)
	}
	if got := AutoPin([]*x509.Certificate{leaf.Cert}); got != 0 {
		t.Errorf("leaf only: got %d, want 0", got)
	}
	if got := AutoPin([]*x509.Certificate{leaf.Cert, inter.Cert}); got != 0 {
		t.Errorf("leaf+non-self-signed: got %d, want 0", got)
	}
}

// withPublicRoots makes the given CAs the system trust store for one test.
func withPublicRoots(t *testing.T, cas ...testpki.Cert) {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range cas {
		pool.AddCert(c.Cert)
	}
	old := systemRoots
	systemRoots = func() (*x509.CertPool, error) { return pool, nil }
	t.Cleanup(func() { systemRoots = old })
}

func TestPublicCAPinsRequireHostname(t *testing.T) {
	publicRoot := testpki.CA(t, "public root")
	inter := testpki.Intermediate(t, "public intermediate", publicRoot)
	node := testpki.LeafFor(t, "pve1.example.com", inter)
	other := testpki.LeafFor(t, "attacker.example.net", inter)
	withPublicRoots(t, publicRoot)

	fp := func(c testpki.Cert) string { return Fingerprint(c.Cert.Raw) }
	chain := func(cs ...testpki.Cert) []*x509.Certificate {
		var out []*x509.Certificate
		for _, c := range cs {
			out = append(out, c.Cert)
		}
		return out
	}
	tests := []struct {
		name   string
		pin    testpki.Cert
		chain  []*x509.Certificate
		server string
		ok     bool
	}{
		{"intermediate pin, right host", inter, chain(node, inter), "pve1.example.com", true},
		{"intermediate pin, other host's cert", inter, chain(other, inter), "pve1.example.com", false},
		{"intermediate pin, no server name", inter, chain(node, inter), "", false},
		{"public root pin, right host", publicRoot, chain(node, inter, publicRoot), "pve1.example.com", true},
		{"public root pin, other host's cert", publicRoot, chain(other, inter, publicRoot), "pve1.example.com", false},
		{"leaf pin needs no hostname", node, chain(node, inter), "10.0.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Verify([]string{fp(tt.pin)}, tt.chain, tt.server)
			if (err == nil) != tt.ok {
				t.Fatalf("Verify() error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestClusterCA(t *testing.T) {
	cluster := testpki.CA(t, "cluster CA")
	publicRoot := testpki.CA(t, "public root")
	inter := testpki.Intermediate(t, "intermediate", cluster)
	withPublicRoots(t, publicRoot)

	if !ClusterCA(cluster.Cert) {
		t.Error("private self-signed CA should qualify")
	}
	if ClusterCA(publicRoot.Cert) {
		t.Error("publicly trusted root must not qualify")
	}
	if ClusterCA(inter.Cert) {
		t.Error("intermediate must not qualify")
	}

	// Cluster CA pins skip the hostname check: nodes are often reached by IP.
	leaf := testpki.LeafFor(t, "pve1", cluster)
	if err := Verify([]string{Fingerprint(cluster.Cert.Raw)}, []*x509.Certificate{leaf.Cert, cluster.Cert}, "10.0.0.1"); err != nil {
		t.Errorf("cluster CA pin by IP: %v", err)
	}

	systemRoots = func() (*x509.CertPool, error) { return nil, errors.New("no trust store") }
	if ClusterCA(cluster.Cert) {
		t.Error("must fail closed without a trust store")
	}
}

func TestAutoPinNeverPicksPublicCA(t *testing.T) {
	publicRoot := testpki.CA(t, "public root")
	inter := testpki.Intermediate(t, "public intermediate", publicRoot)
	leaf := testpki.LeafFor(t, "pve1.example.com", inter)
	withPublicRoots(t, publicRoot)
	if got := AutoPin([]*x509.Certificate{leaf.Cert, inter.Cert, publicRoot.Cert}); got != 0 {
		t.Fatalf("AutoPin = %d, want the leaf", got)
	}
}
