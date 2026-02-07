// Package gatekeeper handles capability granting: loads stored grants,
// diffs against required, prompts for missing, persists decisions.
package gatekeeper

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/capability"
	"github.com/reglet-dev/reglet-host-sdk/capability/grantstore"
)

// SecurityLevel controls the gatekeeper's prompting behavior.
type SecurityLevel string

const (
	SecurityStrict     SecurityLevel = "strict"
	SecurityStandard   SecurityLevel = "standard"
	SecurityPermissive SecurityLevel = "permissive"
)

// Gatekeeper handles capability granting: loads stored grants,
// diffs against required, prompts for missing, persists decisions.
type Gatekeeper struct {
	store         capability.GrantStore
	prompter      capability.Prompter
	securityLevel SecurityLevel
}

// Option configures a Gatekeeper.
type Option func(*Gatekeeper)

// WithStore sets the grant store.
func WithStore(s capability.GrantStore) Option {
	return func(g *Gatekeeper) { g.store = s }
}

// WithPrompter sets the prompter.
func WithPrompter(p capability.Prompter) Option {
	return func(g *Gatekeeper) { g.prompter = p }
}

// WithSecurityLevel sets the security policy level.
func WithSecurityLevel(level SecurityLevel) Option {
	return func(g *Gatekeeper) { g.securityLevel = level }
}

// NewGatekeeper creates a capability gatekeeper with pluggable store and prompter.
func NewGatekeeper(opts ...Option) *Gatekeeper {
	g := &Gatekeeper{
		securityLevel: SecurityStandard,
	}
	for _, opt := range opts {
		opt(g)
	}
	if g.store == nil {
		g.store = grantstore.NewFileStore()
	}
	if g.prompter == nil {
		g.prompter = NewTerminalPrompter()
	}
	return g
}

// GrantCapabilities determines which capabilities to grant based on security policy,
// user input, and saved grants.
func (g *Gatekeeper) GrantCapabilities(
	required *hostfunc.GrantSet,
	capabilityInfo map[string]capability.CapabilityInfo,
	trustAll bool,
) (*hostfunc.GrantSet, error) {
	if required == nil || required.IsEmpty() {
		return &hostfunc.GrantSet{}, nil
	}

	// If trustAll flag is set, grant everything
	if trustAll {
		slog.Warn("Auto-granting all requested capabilities (--trust-plugins enabled)")
		return required.Clone(), nil
	}

	// Load existing grants from config file
	existingGrants, err := g.store.Load()
	if err != nil {
		existingGrants = &hostfunc.GrantSet{}
	}

	// Determine which capabilities are not already granted
	missing := required.Difference(existingGrants)

	if missing.IsEmpty() {
		return existingGrants, nil
	}

	// Deduplicate missing capabilities
	missing.Deduplicate()

	// Non-interactive mode check
	if !g.prompter.IsInteractive() {
		return nil, g.prompter.FormatNonInteractiveError(missing)
	}

	// Interactive prompting for missing capabilities
	newGrants := existingGrants.Clone()
	shouldSave := false

	if err := g.promptForCapabilities(missing, capabilityInfo, newGrants, &shouldSave); err != nil {
		return nil, err
	}

	// Save to config if user chose "always" for any capability
	if shouldSave {
		if err := g.store.Save(newGrants); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to save config: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Permissions saved to %s\n", g.store.ConfigPath())
		}
	}

	return newGrants, nil
}

// promptForCapabilities prompts the user for each type of missing capability.
func (g *Gatekeeper) promptForCapabilities(
	missing *hostfunc.GrantSet,
	capabilityInfo map[string]capability.CapabilityInfo,
	newGrants *hostfunc.GrantSet,
	shouldSave *bool,
) error {
	if err := g.promptForNetwork(missing, capabilityInfo, newGrants, shouldSave); err != nil {
		return err
	}
	if err := g.promptForFS(missing, capabilityInfo, newGrants, shouldSave); err != nil {
		return err
	}
	if err := g.promptForEnv(missing, capabilityInfo, newGrants, shouldSave); err != nil {
		return err
	}
	return g.promptForExec(missing, capabilityInfo, newGrants, shouldSave)
}

func (g *Gatekeeper) promptForNetwork(
	missing *hostfunc.GrantSet,
	capabilityInfo map[string]capability.CapabilityInfo,
	newGrants *hostfunc.GrantSet,
	shouldSave *bool,
) error {
	if missing.Network == nil {
		return nil
	}
	for _, rule := range missing.Network.Rules {
		isBroad := len(rule.Hosts) == 1 && rule.Hosts[0] == "*" && len(rule.Ports) == 1 && rule.Ports[0] == "*"
		gs := &hostfunc.GrantSet{Network: &hostfunc.NetworkCapability{Rules: []hostfunc.NetworkRule{rule}}}

		req := capability.Request{
			Kind:        "network",
			Rule:        rule,
			Description: fmt.Sprintf("network %v:%v", rule.Hosts, rule.Ports),
			IsBroad:     isBroad,
		}

		granted, always, err := g.evaluateWithSecurityLevel(req, capability.AnalyzeRisk(gs).RiskFactors)
		if err != nil {
			return err
		}
		if granted {
			toMerge := &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{rule},
				},
			}
			newGrants.Merge(toMerge)
			if always {
				*shouldSave = true
			}
		} else {
			return fmt.Errorf("capability denied by user: network %v:%v", rule.Hosts, rule.Ports)
		}
	}
	return nil
}

func (g *Gatekeeper) promptForFS(
	missing *hostfunc.GrantSet,
	capabilityInfo map[string]capability.CapabilityInfo,
	newGrants *hostfunc.GrantSet,
	shouldSave *bool,
) error {
	if missing.FS == nil {
		return nil
	}
	for _, rule := range missing.FS.Rules {
		for _, path := range rule.Read {
			isBroad := path == "/**" || path == "**"
			gs := &hostfunc.GrantSet{
				FS: &hostfunc.FileSystemCapability{
					Rules: []hostfunc.FileSystemRule{{Read: []string{path}}},
				},
			}

			req := capability.Request{
				Kind:        "fs",
				Rule:        hostfunc.FileSystemRule{Read: []string{path}},
				Description: fmt.Sprintf("fs read:%s", path),
				IsBroad:     isBroad,
			}

			granted, always, err := g.evaluateWithSecurityLevel(req, capability.AnalyzeRisk(gs).RiskFactors)
			if err != nil {
				return err
			}
			if granted {
				toMerge := &hostfunc.GrantSet{
					FS: &hostfunc.FileSystemCapability{
						Rules: []hostfunc.FileSystemRule{{Read: []string{path}}},
					},
				}
				newGrants.Merge(toMerge)
				if always {
					*shouldSave = true
				}
			} else {
				return fmt.Errorf("capability denied by user: fs read:%s", path)
			}
		}
		for _, path := range rule.Write {
			isBroad := path == "/**" || path == "**"
			gs := &hostfunc.GrantSet{
				FS: &hostfunc.FileSystemCapability{
					Rules: []hostfunc.FileSystemRule{{Write: []string{path}}},
				},
			}

			req := capability.Request{
				Kind:        "fs",
				Rule:        hostfunc.FileSystemRule{Write: []string{path}},
				Description: fmt.Sprintf("fs write:%s", path),
				IsBroad:     isBroad,
			}

			granted, always, err := g.evaluateWithSecurityLevel(req, capability.AnalyzeRisk(gs).RiskFactors)
			if err != nil {
				return err
			}
			if granted {
				toMerge := &hostfunc.GrantSet{
					FS: &hostfunc.FileSystemCapability{
						Rules: []hostfunc.FileSystemRule{{Write: []string{path}}},
					},
				}
				newGrants.Merge(toMerge)
				if always {
					*shouldSave = true
				}
			} else {
				return fmt.Errorf("capability denied by user: fs write:%s", path)
			}
		}
	}
	return nil
}

func (g *Gatekeeper) promptForEnv(
	missing *hostfunc.GrantSet,
	capabilityInfo map[string]capability.CapabilityInfo,
	newGrants *hostfunc.GrantSet,
	shouldSave *bool,
) error {
	if missing.Env == nil {
		return nil
	}
	for _, v := range missing.Env.Variables {
		isBroad := v == "*"
		gs := &hostfunc.GrantSet{Env: &hostfunc.EnvironmentCapability{Variables: []string{v}}}

		req := capability.Request{
			Kind:        "env",
			Rule:        v,
			Description: fmt.Sprintf("env %s", v),
			IsBroad:     isBroad,
		}

		granted, always, err := g.evaluateWithSecurityLevel(req, capability.AnalyzeRisk(gs).RiskFactors)
		if err != nil {
			return err
		}
		if granted {
			toMerge := &hostfunc.GrantSet{
				Env: &hostfunc.EnvironmentCapability{
					Variables: []string{v},
				},
			}
			newGrants.Merge(toMerge)
			if always {
				*shouldSave = true
			}
		} else {
			return fmt.Errorf("capability denied by user: env %s", v)
		}
	}
	return nil
}

func (g *Gatekeeper) promptForExec(
	missing *hostfunc.GrantSet,
	capabilityInfo map[string]capability.CapabilityInfo,
	newGrants *hostfunc.GrantSet,
	shouldSave *bool,
) error {
	if missing.Exec == nil {
		return nil
	}
	for _, cmd := range missing.Exec.Commands {
		isBroad := cmd == "**" || cmd == "*"
		gs := &hostfunc.GrantSet{Exec: &hostfunc.ExecCapability{Commands: []string{cmd}}}

		req := capability.Request{
			Kind:        "exec",
			Rule:        cmd,
			Description: fmt.Sprintf("exec %s", cmd),
			IsBroad:     isBroad,
		}

		granted, always, err := g.evaluateWithSecurityLevel(req, capability.AnalyzeRisk(gs).RiskFactors)
		if err != nil {
			return err
		}
		if granted {
			toMerge := &hostfunc.GrantSet{
				Exec: &hostfunc.ExecCapability{
					Commands: []string{cmd},
				},
			}
			newGrants.Merge(toMerge)
			if always {
				*shouldSave = true
			}
		} else {
			return fmt.Errorf("capability denied by user: exec %s", cmd)
		}
	}
	return nil
}

// evaluateWithSecurityLevel applies security level policy and prompts if needed.
func (g *Gatekeeper) evaluateWithSecurityLevel(req capability.Request, riskFactors []capability.RiskFactor) (bool, bool, error) {
	riskDesc := ""
	if len(riskFactors) > 0 {
		riskDesc = riskFactors[0].Description
	}

	if req.IsBroad {
		switch g.securityLevel {
		case SecurityStrict:
			if riskDesc == "" {
				riskDesc = "broad access beyond what may be necessary"
			}
			slog.Error("broad capability denied by security policy",
				"level", "strict",
				"capability", req.Description,
				"risk", riskDesc)
			return false, false, fmt.Errorf("broad capability denied by strict security policy: %s", req.Description)

		case SecurityPermissive:
			slog.Warn("auto-granting broad capability (permissive mode)",
				"capability", req.Description)
			return true, false, nil
		}
	}

	if g.securityLevel == SecurityPermissive {
		return true, false, nil
	}

	return g.prompter.PromptForCapability(req)
}
