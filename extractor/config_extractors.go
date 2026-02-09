// Package extractor provides capability extraction from plugin configurations and manifests.
package extractor

import (
	"fmt"
	"strings"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/capability"
)

// FileExtractor extracts required file system permissions.
type FileExtractor struct{}

func (e *FileExtractor) Extract(config map[string]interface{}) *hostfunc.GrantSet {
	// Look for common file path fields in standard plugins
	// - file plugin: "path"
	path, ok := config["path"].(string)
	if !ok || path == "" {
		return nil
	}

	return &hostfunc.GrantSet{
		FS: &hostfunc.FileSystemCapability{
			Rules: []hostfunc.FileSystemRule{
				{
					Read: []string{path},
				},
			},
		},
	}
}

// CommandExtractor extracts required exec permissions.
type CommandExtractor struct{}

func (e *CommandExtractor) Extract(config map[string]interface{}) *hostfunc.GrantSet {
	var cmds []string

	// Direct command
	if cmd, ok := config["command"].(string); ok && cmd != "" {
		cmds = append(cmds, cmd)
	} else if cmd, ok := config["cmd"].(string); ok && cmd != "" {
		cmds = append(cmds, cmd)
	}

	// Shell command
	if run, ok := config["run"].(string); ok && run != "" {
		cmds = append(cmds, "/bin/sh")
		// Extract the first word as an approximation of the command being run via sh
		parts := strings.Fields(run)
		if len(parts) > 0 {
			cmds = append(cmds, parts[0])
		}
	}

	if len(cmds) == 0 {
		return nil
	}

	return &hostfunc.GrantSet{
		Exec: &hostfunc.ExecCapability{
			Commands: cmds,
		},
	}
}

// NetworkExtractor extracts required network permissions.
type NetworkExtractor struct{}

func (e *NetworkExtractor) Extract(config map[string]interface{}) *hostfunc.GrantSet {
	var hosts []string
	var ports []string

	hosts, ports = e.extractFromURL(config, hosts, ports)
	hosts, ports = e.extractFromHostTarget(config, hosts, ports)
	hosts, ports = e.extractFromNameserver(config, hosts, ports)
	ports = e.extractPort(config, ports)

	if len(hosts) == 0 {
		if len(ports) > 0 {
			// If ports are specified but no host, assume wildcard host
			hosts = []string{"*"}
		} else {
			return nil
		}
	}

	// Default ports if not specified
	if len(ports) == 0 {
		// Default to wildcard for broad connectivity if host is specified but port is not
		ports = []string{"*"}
	}

	return &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{
					Hosts: hosts,
					Ports: ports,
				},
			},
		},
	}
}

func (e *NetworkExtractor) extractFromURL(config map[string]interface{}, hosts, ports []string) ([]string, []string) {
	if url, ok := config["url"].(string); ok && url != "" {
		if host := extractHostFromURL(url); host != "" {
			hosts = append(hosts, host)
			if strings.HasPrefix(url, "https://") {
				ports = append(ports, "443")
			} else if strings.HasPrefix(url, "http://") {
				ports = append(ports, "80")
			}
		}
	}
	return hosts, ports
}

func (e *NetworkExtractor) extractFromHostTarget(config map[string]interface{}, hosts, ports []string) ([]string, []string) {
	if host, ok := config["host"].(string); ok && host != "" {
		hosts = append(hosts, host)
	}
	if target, ok := config["target"].(string); ok && target != "" {
		hosts = append(hosts, target)
	}
	return hosts, ports
}

func (e *NetworkExtractor) extractFromNameserver(config map[string]interface{}, hosts, ports []string) ([]string, []string) {
	if ns, ok := config["nameserver"].(string); ok && ns != "" {
		hosts = append(hosts, ns)
		ports = append(ports, "53")
	}
	return hosts, ports
}

func (e *NetworkExtractor) extractPort(config map[string]interface{}, ports []string) []string {
	port, ok := config["port"]
	if !ok {
		return ports
	}

	switch v := port.(type) {
	case int:
		if v > 0 {
			ports = append(ports, fmt.Sprintf("%d", v))
		}
	case string:
		if v != "" {
			ports = append(ports, v)
		}
	case float64:
		ports = append(ports, fmt.Sprintf("%.0f", v))
	case uint64:
		ports = append(ports, fmt.Sprintf("%d", v))
	case int64:
		ports = append(ports, fmt.Sprintf("%d", v))
	case int32:
		ports = append(ports, fmt.Sprintf("%d", v))
	}
	return ports
}

func extractHostFromURL(url string) string {
	parts := strings.Split(url, "://")
	if len(parts) < 2 {
		return ""
	}
	remaining := parts[1]
	// Cut at first slash
	if idx := strings.Index(remaining, "/"); idx != -1 {
		remaining = remaining[:idx]
	}
	// Cut at port
	if idx := strings.Index(remaining, ":"); idx != -1 {
		remaining = remaining[:idx]
	}
	return remaining
}

// Ensure extractors implement the interface.
var (
	_ capability.Extractor = (*FileExtractor)(nil)
	_ capability.Extractor = (*CommandExtractor)(nil)
	_ capability.Extractor = (*NetworkExtractor)(nil)
)

// RegisterDefaultExtractors registers the built-in config-based plugin extractors.
func RegisterDefaultExtractors(registry *capability.Registry) {
	registry.Register("file", &FileExtractor{})
	registry.Register("file.managed", &FileExtractor{}) // Alias
	registry.Register("command", &CommandExtractor{})

	netExtractor := &NetworkExtractor{}
	registry.Register("http", netExtractor)
	registry.Register("tcp", netExtractor)
	registry.Register("dns", netExtractor)
	registry.Register("smtp", netExtractor)
}
