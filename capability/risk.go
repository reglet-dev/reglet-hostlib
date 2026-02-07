package capability

import (
	"fmt"

	"github.com/reglet-dev/reglet-abi/hostfunc"
)

// RiskLevel represents the security risk level of a capability grant.
type RiskLevel int

const (
	RiskNone RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

// RiskReport contains the overall risk assessment for a set of capabilities.
type RiskReport struct {
	RiskFactors []RiskFactor
	Level       RiskLevel
}

// RiskFactor describes a single risk element in a capability grant.
type RiskFactor struct {
	Description string
	Rule        string
	Level       RiskLevel
}

// AnalyzeRisk evaluates the risk level of a GrantSet.
func AnalyzeRisk(grants *hostfunc.GrantSet) RiskReport {
	report := RiskReport{
		Level: RiskNone,
	}

	if grants == nil {
		return report
	}

	addFactor := func(level RiskLevel, desc, rule string) {
		if level > RiskNone {
			report.RiskFactors = append(report.RiskFactors, RiskFactor{
				Level:       level,
				Description: desc,
				Rule:        rule,
			})
			if level > report.Level {
				report.Level = level
			}
		}
	}

	// 1. Analyze Network
	if grants.Network != nil {
		for _, rule := range grants.Network.Rules {
			ruleStr := fmt.Sprintf("Network: %s:%s", rule.Hosts, rule.Ports)

			isWildcardHost := false
			for _, h := range rule.Hosts {
				if h == "*" || h == "0.0.0.0" {
					isWildcardHost = true
					break
				}
			}

			if isWildcardHost {
				addFactor(RiskCritical, "Unrestricted network access", ruleStr)
			} else {
				addFactor(RiskMedium, "Outbound network access", ruleStr)
			}
		}
	}

	// 2. Analyze FS
	if grants.FS != nil {
		for _, rule := range grants.FS.Rules {
			if len(rule.Write) > 0 {
				ruleStr := fmt.Sprintf("FS Write: %v", rule.Write)
				addFactor(RiskHigh, "Filesystem write access", ruleStr)
			}
			if len(rule.Read) > 0 {
				ruleStr := fmt.Sprintf("FS Read: %v", rule.Read)
				addFactor(RiskMedium, "Filesystem read access", ruleStr)
			}
		}
	}

	// 3. Analyze Exec
	if grants.Exec != nil && len(grants.Exec.Commands) > 0 {
		ruleStr := fmt.Sprintf("Exec: %v", grants.Exec.Commands)
		addFactor(RiskCritical, "Arbitrary command execution", ruleStr)
	}

	// 4. Analyze Env
	if grants.Env != nil && len(grants.Env.Variables) > 0 {
		ruleStr := fmt.Sprintf("Env: %v", grants.Env.Variables)
		addFactor(RiskLow, "Environment variable access", ruleStr)
	}

	return report
}
