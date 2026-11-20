// Package policy normalises proxied API paths and decides, default deny,
// which Proxmox API calls a client may make.
package policy

import (
	"errors"
	"strings"
)

// Prefix is the only path prefix the gateway proxies.
const Prefix = "/api2/json/"

// MaxPathLen bounds the escaped request path.
const MaxPathLen = 1024

// ErrInvalidPath is returned for any path the gateway refuses to proxy.
var ErrInvalidPath = errors.New("invalid API path")

// Path is a normalised API path.
type Path struct {
	// Segments are the decoded segments after /api2/json/.
	Segments []string
}

// String returns the canonical path, including the /api2/json/ prefix.
func (p Path) String() string { return Prefix + strings.Join(p.Segments, "/") }

// Normalize validates an escaped request path (as from URL.EscapedPath) and
// returns its decoded segments. It is deliberately strict: anything that a
// server could interpret differently from the policy matcher is rejected,
// rather than cleaned. That includes dot segments (literal or encoded, at any
// level of encoding), empty segments (so "//" and a trailing "/"), encoded
// slashes and backslashes, and any byte outside a small set of characters
// that Proxmox IDs, node names and task UPIDs use.
func Normalize(escaped string) (Path, error) {
	if len(escaped) > MaxPathLen || !strings.HasPrefix(escaped, Prefix) {
		return Path{}, ErrInvalidPath
	}
	rest := escaped[len(Prefix):]
	if rest == "" {
		return Path{}, ErrInvalidPath
	}
	raw := strings.Split(rest, "/")
	segs := make([]string, 0, len(raw))
	for _, r := range raw {
		s, ok := decodeSegment(r)
		if !ok || s == "" || s == "." || s == ".." {
			return Path{}, ErrInvalidPath
		}
		segs = append(segs, s)
	}
	return Path{Segments: segs}, nil
}

// decodeSegment percent-decodes one segment once. Encoded dots are refused
// outright, and the decoded result must contain only allowed characters, so
// "%25" (an encoded '%', the start of double encoding), "%2F" and "%5C" are
// all rejected.
func decodeSegment(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) {
				return "", false
			}
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			c = hi<<4 | lo
			if c == '.' {
				return "", false
			}
			i += 2
		}
		if !allowed(c) {
			return "", false
		}
		b.WriteByte(c)
	}
	return b.String(), true
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// allowed reports whether c may appear in a decoded segment: ASCII letters,
// digits and - . _ ~ : @ ! (the last three appear in task UPIDs and API
// token IDs).
func allowed(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~:@!", c) >= 0
}
