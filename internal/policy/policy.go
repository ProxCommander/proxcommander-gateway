package policy

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Rule allows one method on one path pattern. Patterns are relative to
// /api2/json/; a segment written as {name} matches any single segment.
// A GET rule also allows HEAD.
type Rule struct {
	Method  string
	Pattern string
}

// Policy is a default-deny allow-list.
type Policy struct {
	name  string
	rules []compiled
}

type compiled struct {
	method string
	segs   []string // "" marks a wildcard segment
}

// Profiles returns the names of the built-in profiles.
func Profiles() []string {
	names := make([]string, 0, len(builtin))
	for n := range builtin {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ForProfile returns the built-in profile with the given name.
func ForProfile(name string) (*Policy, error) {
	rules, ok := builtin[name]
	if !ok {
		return nil, fmt.Errorf("unknown profile %q (want one of %s)", name, strings.Join(Profiles(), ", "))
	}
	return New(name, rules)
}

// New compiles a policy from rules.
func New(name string, rules []Rule) (*Policy, error) {
	p := &Policy{name: name}
	for _, r := range rules {
		segs := strings.Split(strings.Trim(r.Pattern, "/"), "/")
		for i, s := range segs {
			if s == "" {
				return nil, fmt.Errorf("rule %s %s: empty segment", r.Method, r.Pattern)
			}
			if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
				segs[i] = ""
			}
		}
		p.rules = append(p.rules, compiled{method: strings.ToUpper(r.Method), segs: segs})
	}
	return p, nil
}

// Name returns the profile name.
func (p *Policy) Name() string { return p.name }

// Allow reports whether method on path is allowed.
func (p *Policy) Allow(method string, path Path) bool {
	if method == http.MethodHead {
		method = http.MethodGet
	}
	for _, r := range p.rules {
		if r.method == method && match(r.segs, path.Segments) {
			return true
		}
	}
	return false
}

func match(pattern, segs []string) bool {
	if len(pattern) != len(segs) {
		return false
	}
	for i, p := range pattern {
		if p != "" && p != segs[i] {
			return false
		}
	}
	return true
}

// Built-in profiles. Anything not listed is denied, including every
// root-equivalent endpoint: node shells, /access, storage and network
// configuration, apt and ceph.
var builtin = map[string][]Rule{
	"read-only": readOnly,
	"operator":  operator,
}

var readOnly = []Rule{
	{"GET", "version"},
	{"GET", "cluster/status"},
	{"GET", "cluster/resources"},
	{"GET", "cluster/tasks"},
	{"GET", "nodes"},
	{"GET", "nodes/{node}/status"},
	{"GET", "nodes/{node}/version"},
	{"GET", "nodes/{node}/rrddata"},
	{"GET", "nodes/{node}/qemu"},
	{"GET", "nodes/{node}/qemu/{vmid}/status/current"},
	{"GET", "nodes/{node}/qemu/{vmid}/config"},
	{"GET", "nodes/{node}/qemu/{vmid}/rrddata"},
	{"GET", "nodes/{node}/lxc"},
	{"GET", "nodes/{node}/lxc/{vmid}/status/current"},
	{"GET", "nodes/{node}/lxc/{vmid}/config"},
	{"GET", "nodes/{node}/lxc/{vmid}/rrddata"},
	{"GET", "nodes/{node}/storage"},
	{"GET", "nodes/{node}/storage/{storage}/status"},
	{"GET", "nodes/{node}/storage/{storage}/rrddata"},
	{"GET", "nodes/{node}/tasks"},
	{"GET", "nodes/{node}/tasks/{upid}/status"},
}

var operator = func() []Rule {
	r := append([]Rule(nil), readOnly...)
	for _, a := range []string{"start", "stop", "shutdown", "reboot", "reset", "suspend", "resume"} {
		r = append(r, Rule{"POST", "nodes/{node}/qemu/{vmid}/status/" + a})
	}
	for _, a := range []string{"start", "stop", "shutdown", "reboot", "suspend", "resume"} {
		r = append(r, Rule{"POST", "nodes/{node}/lxc/{vmid}/status/" + a})
	}
	for _, g := range []string{"qemu", "lxc"} {
		r = append(r,
			Rule{"POST", "nodes/{node}/" + g + "/{vmid}/vncproxy"},
			Rule{"POST", "nodes/{node}/" + g + "/{vmid}/termproxy"},
			Rule{"GET", "nodes/{node}/" + g + "/{vmid}/vncwebsocket"},
		)
	}
	r = append(r, Rule{"GET", "nodes/{node}/tasks/{upid}/log"})
	return r
}()
