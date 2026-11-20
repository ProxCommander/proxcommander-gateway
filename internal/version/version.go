// Package version holds the build version, set at link time with
// -ldflags "-X github.com/ProxCommander/proxcommander-gateway/internal/version.Version=v1.2.3".
package version

// Version is the gateway version. Release builds override it.
var Version = "dev"
