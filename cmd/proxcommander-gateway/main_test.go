package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProxCommander/proxcommander-gateway/internal/pin"
	"github.com/ProxCommander/proxcommander-gateway/internal/state"
	"github.com/ProxCommander/proxcommander-gateway/internal/testpki"
)

func newCLI(t *testing.T, stdin string, interactive bool) (*cli, *bytes.Buffer, string) {
	t.Helper()
	dir := t.TempDir()
	out := &bytes.Buffer{}
	return &cli{
		stdin:       bufio.NewReader(strings.NewReader(stdin)),
		stdout:      out,
		stderr:      out,
		getenv:      func(k string) string { return map[string]string{"PCG_STATE_DIR": dir}[k] },
		interactive: interactive,
	}, out, dir
}

func tlsNode(t *testing.T) (string, testpki.Cert, testpki.Cert) {
	t.Helper()
	ca := testpki.CA(t, "Proxmox Virtual Environment")
	leaf := testpki.Leaf(t, "pve1", ca)
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{testpki.TLSCert(leaf, ca)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.URL, ca, leaf
}

func TestNodesAddListRemove(t *testing.T) {
	url, ca, _ := tlsNode(t)
	c, out, dir := newCLI(t, "", false)

	if code := c.run([]string{"nodes", "add", url}); code == 0 {
		t.Fatalf("non-interactive add without --yes succeeded:\n%s", out)
	}
	if code := c.run([]string{"nodes", "add", url, "--yes", "--name", "pve1"}); code != 0 {
		t.Fatalf("add: %d\n%s", code, out)
	}
	st, err := state.Load(dir)
	if err != nil || len(st.Nodes) != 1 {
		t.Fatalf("state: %v %+v", err, st)
	}
	if got := st.Nodes[0].Fingerprints; len(got) != 1 || got[0] != pin.Fingerprint(ca.Cert.Raw) {
		t.Fatalf("pinned %v, want the cluster CA", got)
	}
	if code := c.run([]string{"nodes", "add", url, "--yes"}); code == 0 {
		t.Fatal("duplicate add succeeded")
	}

	out.Reset()
	if code := c.run([]string{"nodes", "list"}); code != 0 || !strings.Contains(out.String(), "pve1") {
		t.Fatalf("list: %d\n%s", code, out)
	}
	if code := c.run([]string{"nodes", "remove", "pve1"}); code != 0 {
		t.Fatalf("remove: %d\n%s", code, out)
	}
	st, _ = state.Load(dir)
	if len(st.Nodes) != 0 {
		t.Fatalf("node not removed: %+v", st.Nodes)
	}
}

func TestNodesAddInteractiveAndFingerprint(t *testing.T) {
	url, _, leaf := tlsNode(t)

	c, out, dir := newCLI(t, "n\n", true)
	if code := c.run([]string{"nodes", "add", url}); code == 0 {
		t.Fatalf("declined prompt still pinned:\n%s", out)
	}
	c, out, dir = newCLI(t, "y\n", true)
	if code := c.run([]string{"nodes", "add", "--pin-leaf", url}); code != 0 {
		t.Fatalf("add: %d\n%s", code, out)
	}
	st, _ := state.Load(dir)
	if st.Nodes[0].Fingerprints[0] != pin.Fingerprint(leaf.Cert.Raw) {
		t.Fatal("--pin-leaf did not pin the leaf")
	}

	c, out, _ = newCLI(t, "", false)
	wrong := pin.Fingerprint([]byte("other"))
	if code := c.run([]string{"nodes", "add", url, "--fingerprint", wrong}); code == 0 {
		t.Fatalf("mismatched --fingerprint pinned:\n%s", out)
	}
	c, out, _ = newCLI(t, "", false)
	if code := c.run([]string{"nodes", "add", url, "--fingerprint", strings.ToLower(pin.Fingerprint(leaf.Cert.Raw))}); code != 0 {
		t.Fatalf("matching --fingerprint: %d\n%s", code, out)
	}
}

func TestVersionAndUnknown(t *testing.T) {
	c, out, _ := newCLI(t, "", false)
	if code := c.run([]string{"version"}); code != 0 || !strings.HasPrefix(out.String(), "proxcommander-gateway ") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code := c.run([]string{"bogus"}); code != 2 {
		t.Fatalf("unknown command: %d", code)
	}
}

func TestNodesAddRefusesIntermediatePin(t *testing.T) {
	root := testpki.CA(t, "root")
	inter := testpki.Intermediate(t, "intermediate", root)
	leaf := testpki.Leaf(t, "pve1", inter)
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{testpki.TLSCert(leaf, inter)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	c, out, dir := newCLI(t, "", false)
	if code := c.run([]string{"nodes", "add", srv.URL, "--fingerprint", pin.Fingerprint(inter.Cert.Raw)}); code == 0 {
		t.Fatalf("intermediate CA pinned:\n%s", out)
	}
	// With no cluster CA presented, the default is the leaf.
	if code := c.run([]string{"nodes", "add", srv.URL, "--yes"}); code != 0 {
		t.Fatalf("add: %d\n%s", code, out)
	}
	st, _ := state.Load(dir)
	if st.Nodes[0].Fingerprints[0] != pin.Fingerprint(leaf.Cert.Raw) {
		t.Fatal("expected the leaf to be pinned")
	}
}
