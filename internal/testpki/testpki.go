// Package testpki creates throwaway certificates for tests.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// Cert is a generated certificate with its key.
type Cert struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// CA creates a self-signed CA.
func CA(t testing.TB, name string) Cert {
	t.Helper()
	return issue(t, name, true, nil, "")
}

// Intermediate creates a CA signed by parent.
func Intermediate(t testing.TB, name string, parent Cert) Cert {
	t.Helper()
	return issue(t, name, true, &parent, "")
}

// Leaf creates a server certificate for 127.0.0.1 signed by parent.
func Leaf(t testing.TB, name string, parent Cert) Cert {
	t.Helper()
	return issue(t, name, false, &parent, "")
}

// LeafFor creates a server certificate for the DNS name host signed by parent.
func LeafFor(t testing.TB, host string, parent Cert) Cert {
	t.Helper()
	return issue(t, host, false, &parent, host)
}

func issue(t testing.TB, name string, isCA bool, parent *Cert, dnsName string) Cert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if dnsName != "" {
			tmpl.DNSNames = []string{dnsName}
		} else {
			tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.Cert, parent.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Cert{Cert: c, Key: key}
}

// TLSCert builds a tls.Certificate presenting leaf followed by chain.
func TLSCert(leaf Cert, chain ...Cert) tls.Certificate {
	tc := tls.Certificate{Certificate: [][]byte{leaf.Cert.Raw}, PrivateKey: leaf.Key, Leaf: leaf.Cert}
	for _, c := range chain {
		tc.Certificate = append(tc.Certificate, c.Cert.Raw)
	}
	return tc
}
