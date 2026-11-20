// Command proxcommander-gateway is the ProxCommander Gateway: an
// authenticated, allow-listing broker between the ProxCommander app and a
// Proxmox VE cluster.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ProxCommander/proxcommander-gateway/internal/version"
)

const usage = `Usage: proxcommander-gateway <command> [flags]

Commands:
  serve                      run the gateway
  nodes add <https://host:port>  fetch a node's certificate and pin it
  nodes list                 list configured nodes
  nodes remove <name|url>    remove a node
  version                    print the version

Run "proxcommander-gateway <command> -h" for a command's flags.
`

// cli carries the process environment so commands can be tested.
type cli struct {
	stdin       *bufio.Reader
	stdout      io.Writer
	stderr      io.Writer
	getenv      func(string) string
	interactive bool // stdin is a terminal
}

func main() {
	c := &cli{
		stdin:       bufio.NewReader(os.Stdin),
		stdout:      os.Stdout,
		stderr:      os.Stderr,
		getenv:      os.Getenv,
		interactive: isTerminal(os.Stdin),
	}
	os.Exit(c.run(os.Args[1:]))
}

func (c *cli) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(c.stderr, usage)
		return 2
	}
	switch args[0] {
	case "serve":
		return c.serve(args[1:])
	case "nodes":
		return c.nodes(args[1:])
	case "version", "-version", "--version":
		fmt.Fprintln(c.stdout, "proxcommander-gateway", version.Version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Fprint(c.stdout, usage)
		return 0
	}
	fmt.Fprintf(c.stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

func (c *cli) fail(err error) int {
	fmt.Fprintln(c.stderr, "error:", err)
	return 1
}

// parseInterspersed parses flags that may appear before or after positional
// arguments and returns the positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
