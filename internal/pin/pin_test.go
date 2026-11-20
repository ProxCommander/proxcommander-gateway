package pin

import (
	"crypto/x509"
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
			err := Verify(tt.pins, tt.chain)
			if (err == nil) != tt.ok {
				t.Fatalf("Verify() error = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestTLSConfigRequiresPins(t *testing.T) {
	if _, err := TLSConfig(nil); err == nil {
		t.Fatal("TLSConfig(nil) succeeded")
	}
	if _, err := TLSConfig([]string{"bad"}); err == nil {
		t.Fatal("TLSConfig with a malformed pin succeeded")
	}
	cfg, err := TLSConfig([]string{Fingerprint([]byte("x"))})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("VerifyConnection not set")
	}
}

func TestAutoPin(t *testing.T) {
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
