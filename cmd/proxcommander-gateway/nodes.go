package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ProxCommander/proxcommander-gateway/internal/config"
	"github.com/ProxCommander/proxcommander-gateway/internal/pin"
	"github.com/ProxCommander/proxcommander-gateway/internal/state"
)

func (c *cli) nodes(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.stderr, "usage: proxcommander-gateway nodes add|list|remove\n")
		return 2
	}
	switch args[0] {
	case "add":
		return c.nodesAdd(args[1:])
	case "list", "ls":
		return c.nodesList(args[1:])
	case "remove", "rm":
		return c.nodesRemove(args[1:])
	}
	fmt.Fprintf(c.stderr, "unknown nodes command %q\n", args[0])
	return 2
}

func (c *cli) nodesAdd(args []string) int {
	fs := flag.NewFlagSet("nodes add", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	fs.Usage = func() {
		fmt.Fprintln(c.stderr, "usage: proxcommander-gateway nodes add [flags] https://host:port")
		fs.PrintDefaults()
	}
	var common config.Common
	config.CommonFlags(fs, c.getenv, &common)
	name := fs.String("name", "", "node name (default: the URL's host)")
	yes := fs.Bool("yes", false, "pin without asking")
	want := fs.String("fingerprint", "", "expected SHA-256 fingerprint of the leaf or cluster CA; pins it without asking if presented")
	leaf := fs.Bool("pin-leaf", false, "pin the node's own certificate even if it presents a cluster CA")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fs.Usage()
		return 2
	}
	nodeURL, err := state.NormalizeNodeURL(pos[0])
	if err != nil {
		return c.fail(err)
	}
	if *name == "" {
		u, _ := url.Parse(nodeURL)
		*name = u.Hostname()
	}

	st, err := state.Load(common.StateDir)
	if err != nil {
		return c.fail(err)
	}
	if st.FindNode(*name) >= 0 || st.FindNode(nodeURL) >= 0 {
		return c.fail(fmt.Errorf("node %s (%s) already exists; remove it first", *name, nodeURL))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	chain, err := pin.FetchChain(ctx, strings.TrimPrefix(nodeURL, "https://"))
	if err != nil {
		return c.fail(fmt.Errorf("connect to %s: %w", nodeURL, err))
	}
	if len(chain) == 0 {
		return c.fail(errors.New("node presented no certificate"))
	}

	fmt.Fprintf(c.stdout, "Certificate chain presented by %s:\n", nodeURL)
	for i, cert := range chain {
		fmt.Fprintf(c.stdout, "  [%d] subject: %s\n      issuer:  %s\n      expires: %s\n      SHA-256: %s\n",
			i, cert.Subject, cert.Issuer, cert.NotAfter.UTC().Format("2006-01-02"), pin.Fingerprint(cert.Raw))
	}

	idx := pin.AutoPin(chain)
	if *leaf {
		idx = 0
	}
	if *want != "" {
		fp, err := pin.ParseFingerprint(*want)
		if err != nil {
			return c.fail(err)
		}
		idx = -1
		for i, cert := range chain {
			if pin.Fingerprint(cert.Raw) == fp {
				idx = i
			}
		}
		if idx < 0 {
			return c.fail(fmt.Errorf("fingerprint %s was not presented by %s; not pinning", fp, nodeURL))
		}
	}
	fp := pin.Fingerprint(chain[idx].Raw)
	// The pin must verify the chain the node presents right now.
	if err := pin.Verify([]string{fp}, chain); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "\nWill pin [%d] %s: %s\n", idx, describe(chain[idx], idx), fp)

	if *want == "" && !*yes {
		if !c.interactive {
			return c.fail(errors.New("not pinning without confirmation; re-run with --yes or --fingerprint"))
		}
		fmt.Fprint(c.stdout, "Compare it with the node (pvenode cert info). Pin this certificate? [y/N] ")
		line, _ := c.stdin.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(c.stdout, "Not pinned.")
			return 1
		}
	}

	st.Nodes = append(st.Nodes, state.Node{Name: *name, URL: nodeURL, Fingerprints: []string{fp}, AddedAt: time.Now().UTC()})
	if err := st.Save(common.StateDir); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "Added node %s (%s). Restart the gateway to apply.\n", *name, nodeURL)
	return 0
}

func describe(cert *x509.Certificate, idx int) string {
	switch {
	case idx == 0:
		return "the node's own certificate"
	case pin.SelfSigned(cert):
		return "the cluster CA"
	}
	return "an intermediate CA"
}

func (c *cli) nodesList(args []string) int {
	fs := flag.NewFlagSet("nodes list", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	var common config.Common
	config.CommonFlags(fs, c.getenv, &common)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := state.Load(common.StateDir)
	if err != nil {
		return c.fail(err)
	}
	if len(st.Nodes) == 0 {
		fmt.Fprintln(c.stdout, "No nodes configured.")
		return 0
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tURL\tPINNED SHA-256\tADDED")
	for _, n := range st.Nodes {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", n.Name, n.URL, strings.Join(n.Fingerprints, ","), n.AddedAt.Format(time.RFC3339))
	}
	tw.Flush()
	return 0
}

func (c *cli) nodesRemove(args []string) int {
	fs := flag.NewFlagSet("nodes remove", flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	var common config.Common
	config.CommonFlags(fs, c.getenv, &common)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintln(c.stderr, "usage: proxcommander-gateway nodes remove <name|url>")
		return 2
	}
	st, err := state.Load(common.StateDir)
	if err != nil {
		return c.fail(err)
	}
	key := pos[0]
	if u, err := state.NormalizeNodeURL(key); err == nil {
		key = u
	}
	i := st.FindNode(key)
	if i < 0 {
		return c.fail(fmt.Errorf("no node %q", pos[0]))
	}
	removed := st.Nodes[i]
	st.Nodes = append(st.Nodes[:i], st.Nodes[i+1:]...)
	if err := st.Save(common.StateDir); err != nil {
		return c.fail(err)
	}
	fmt.Fprintf(c.stdout, "Removed node %s (%s). Restart the gateway to apply.\n", removed.Name, removed.URL)
	return 0
}
