// Package pin verifies upstream TLS certificates against pinned SHA-256
// fingerprints instead of the system trust store.
//
// A pin is either the node's leaf certificate or a CA that the node presents
// in its chain. A CA pin only matches when the leaf cryptographically chains
// to that CA, so an attacker cannot pass by appending the CA certificate to
// their own chain. A CA pin skips the hostname check only when the CA is a
// private cluster CA (self-signed and not publicly trusted); any other CA
// issues for many hosts, so the leaf must also be valid for the node's host.
package pin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Fingerprint returns the SHA-256 fingerprint of a DER certificate in the
// colon-separated upper-case form that Proxmox shows (AB:CD:...).
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return format(sum[:])
}

func format(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// ParseFingerprint accepts a SHA-256 fingerprint with or without colons, in
// any case, and returns it in canonical form.
func ParseFingerprint(s string) (string, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("invalid SHA-256 fingerprint %q", s)
	}
	return format(b), nil
}

// ErrNoPins is returned when a TLS config is requested without any pins.
var ErrNoPins = errors.New("pin: no pinned fingerprints")

// Verify checks a presented chain (leaf first) against the pins. serverName
// is the node's host name or IP, used when a CA pin needs a hostname check.
func Verify(pins []string, chain []*x509.Certificate, serverName string) error {
	if len(pins) == 0 {
		return ErrNoPins
	}
	if len(chain) == 0 {
		return errors.New("pin: no certificate presented")
	}
	want := make(map[string]bool, len(pins))
	for _, p := range pins {
		fp, err := ParseFingerprint(p)
		if err != nil {
			return err
		}
		want[fp] = true
	}
	leaf := chain[0]
	if want[Fingerprint(leaf.Raw)] {
		return nil
	}
	for i, c := range chain[1:] {
		if !want[Fingerprint(c.Raw)] {
			continue
		}
		roots := x509.NewCertPool()
		roots.AddCert(c)
		inter := x509.NewCertPool()
		for j, o := range chain[1:] {
			if j != i {
				inter.AddCert(o)
			}
		}
		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: inter,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}
		if !ClusterCA(c) {
			if serverName == "" {
				continue
			}
			opts.DNSName = serverName
		}
		// Validity periods and signatures are always checked.
		if _, err := leaf.Verify(opts); err == nil {
			return nil
		}
	}
	return fmt.Errorf("pin: certificate %s does not match any pinned fingerprint", Fingerprint(leaf.Raw))
}

// TLSConfig returns the only TLS client configuration used for upstream
// nodes. Go's standard verifier is replaced (InsecureSkipVerify) because
// Proxmox certificates are not publicly trusted; VerifyConnection always
// enforces the pins in its place, and there is no way to turn it off.
// serverName is the node's host name or IP address.
func TLSConfig(pins []string, serverName string) (*tls.Config, error) {
	if len(pins) == 0 {
		return nil, ErrNoPins
	}
	for _, p := range pins {
		if _, err := ParseFingerprint(p); err != nil {
			return nil, err
		}
	}
	pinned := append([]string(nil), pins...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: true, // replaced by VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			return Verify(pinned, cs.PeerCertificates, serverName)
		},
	}, nil
}

// FetchChain performs a TLS handshake with addr (host:port) only to read the
// certificate chain for display before pinning. It accepts any certificate,
// sends no application data, and closes the connection immediately.
func FetchChain(ctx context.Context, addr string) ([]*x509.Certificate, error) {
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second},
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // display only; nothing is trusted or sent
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.(*tls.Conn).ConnectionState().PeerCertificates, nil
}

// AutoPin chooses which presented certificate to pin: the top-most private
// cluster CA if the node sends one, otherwise the leaf. A public or
// intermediate CA is never chosen.
func AutoPin(chain []*x509.Certificate) int {
	for i := len(chain) - 1; i > 0; i-- {
		if ClusterCA(chain[i]) {
			return i
		}
	}
	return 0
}

// SelfSigned reports whether c is a CA whose signature verifies with its own key.
func SelfSigned(c *x509.Certificate) bool {
	return c.IsCA && c.CheckSignatureFrom(c) == nil
}

// systemRoots loads the public trust store; tests replace it.
var systemRoots = x509.SystemCertPool

// ClusterCA reports whether c may be pinned as a CA without a hostname
// check: a self-signed CA that does not chain to a publicly trusted root,
// such as the Proxmox cluster CA. If the system trust store cannot be
// loaded, no CA qualifies.
func ClusterCA(c *x509.Certificate) bool {
	if !SelfSigned(c) {
		return false
	}
	roots, err := systemRoots()
	if err != nil || roots == nil {
		return false
	}
	_, err = c.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err != nil
}
