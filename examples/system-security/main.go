package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("🔒 CEL Go Scanner - System Security Example")
	fmt.Println(strings.Repeat("=", 50))

	// Create composite fetcher with system support
	fetcher := fetchers.NewCompositeFetcherBuilder().
		WithSystem(false). // Safe commands only for security
		Build()

	// Create scanner with logger
	logger := celscanner.DefaultLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	fmt.Println("\n🛡️  Running System Security Checks...")

	// Run security compliance checks
	runSecurityComplianceChecks(scanner)

	// Run direct security assessments
	runDirectSecurityAssessments()

	fmt.Println("\n✅ Security assessment completed!")
}

// Security compliance checks using CEL rules
func runSecurityComplianceChecks(scanner *celscanner.Scanner) {
	fmt.Println("\n🔍 Security Compliance Checks")
	fmt.Println(strings.Repeat("-", 40))

	// Define security rules
	// SELinux enforcement check
	selinuxRule, err := celscanner.NewRuleBuilder("selinux-enforcing").
		WithSystemInput("selinux", "", "getenforce", []string{}).
		SetExpression(`selinux.success && contains(selinux.output, "Enforcing")`).
		WithName("SELinux Enforcement Check").
		WithDescription("Ensures SELinux is in enforcing mode").
		WithExtension("severity", "HIGH").
		WithExtension("compliance", "STIG").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build SELinux rule: %v", err))
	}

	// Firewall status check
	firewallRule, err := celscanner.NewRuleBuilder("firewall-active").
		WithSystemInput("firewall", "", "systemctl", []string{"is-active", "firewalld"}).
		SetExpression(`firewall.success`).
		WithName("Firewall Status Check").
		WithDescription("Ensures firewall service is active").
		WithExtension("severity", "CRITICAL").
		WithExtension("compliance", "CIS").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build firewall rule: %v", err))
	}

	// SSH service security
	sshRule, err := celscanner.NewRuleBuilder("ssh-service-check").
		WithSystemInput("ssh", "sshd", "", []string{}).
		SetExpression(`ssh.success && ssh.status == "active"`).
		WithName("SSH Service Security").
		WithDescription("Validates SSH service is properly configured").
		WithExtension("severity", "HIGH").
		WithExtension("service", "sshd").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build SSH rule: %v", err))
	}

	// User session monitoring
	sessionsRule, err := celscanner.NewRuleBuilder("user-sessions").
		WithSystemInput("sessions", "", "who", []string{}).
		SetExpression(`sessions.success`).
		WithName("Active User Sessions").
		WithDescription("Monitors currently logged in users").
		WithExtension("severity", "MEDIUM").
		WithExtension("monitoring", "continuous").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build sessions rule: %v", err))
	}

	// System integrity check
	integrityRule, err := celscanner.NewRuleBuilder("system-integrity").
		WithSystemInput("processes", "", "ps", []string{"aux"}).
		SetExpression(`processes.success && size(processes.output) > 0`).
		WithName("System Process Integrity").
		WithDescription("Validates system processes are running").
		WithExtension("severity", "HIGH").
		WithExtension("category", "integrity").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build integrity rule: %v", err))
	}

	rules := []celscanner.CelRule{
		selinuxRule,
		firewallRule,
		sshRule,
		sessionsRule,
		integrityRule,
	}

	// Execute each rule
	for _, rule := range rules {
		fmt.Printf("\n🔍 Running: %s\n", rule.Metadata().Name)

		config := celscanner.ScanConfig{
			Rules:              []celscanner.CelRule{rule},
			Variables:          []celscanner.CelVariable{},
			EnableDebugLogging: false,
		}

		results, err := scanner.Scan(context.Background(), config)
		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if len(results) == 0 {
			fmt.Printf("   ❌ No results returned\n")
			continue
		}

		result := results[0]
		statusIcon := getStatusIcon(result.Status)
		severity := rule.Metadata().Extensions["severity"]

		fmt.Printf("   %s Status: %s (%s severity)\n", statusIcon, result.Status, severity)

		if len(result.Warnings) > 0 {
			for _, warning := range result.Warnings {
				fmt.Printf("   ⚠️  %s\n", warning)
			}
		}

		if result.ErrorMessage != "" {
			fmt.Printf("   🚨 %s\n", result.ErrorMessage)
		}
	}
}

// Direct security assessments without CEL rules
func runDirectSecurityAssessments() {
	fmt.Println("\n🔐 Direct Security Assessment")
	fmt.Println(strings.Repeat("-", 40))

	systemFetcher := fetchers.NewSystemFetcher(30*time.Second, false)

	// Security command assessments
	securityChecks := []struct {
		name        string
		command     string
		args        []string
		description string
		severity    string
	}{
		{
			name:        "Password Policy",
			command:     "cat",
			args:        []string{"/etc/login.defs"},
			description: "Check password policy configuration",
			severity:    "HIGH",
		},
		{
			name:        "SSH Configuration",
			command:     "cat",
			args:        []string{"/etc/ssh/sshd_config"},
			description: "Verify SSH daemon configuration",
			severity:    "CRITICAL",
		},
		{
			name:        "Sudo Configuration",
			command:     "cat",
			args:        []string{"/etc/sudoers"},
			description: "Check sudo permissions",
			severity:    "CRITICAL",
		},
		{
			name:        "Network Connections",
			command:     "netstat",
			args:        []string{"-tlnp"},
			description: "Monitor open network ports",
			severity:    "MEDIUM",
		},
		{
			name:        "System Users",
			command:     "cat",
			args:        []string{"/etc/passwd"},
			description: "Audit system user accounts",
			severity:    "HIGH",
		},
		{
			name:        "Failed Login Attempts",
			command:     "grep",
			args:        []string{"Failed", "/var/log/auth.log"},
			description: "Check for failed authentication attempts",
			severity:    "HIGH",
		},
	}

	for _, check := range securityChecks {
		fmt.Printf("\n🔹 %s (%s):\n", check.name, check.severity)
		fmt.Printf("   📝 %s\n", check.description)

		input := celscanner.NewSystemInput("security", "", check.command, check.args)
		data, err := systemFetcher.FetchInputs([]celscanner.Input{input}, nil)

		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if result, ok := data["security"].(*fetchers.SystemResult); ok {
			if result.Success {
				output := strings.TrimSpace(result.Output)

				// Show first few lines for readability
				lines := strings.Split(output, "\n")
				if len(lines) > 5 {
					fmt.Printf("   ✅ Found %d lines of data (showing first 5):\n", len(lines))
					for i, line := range lines[:5] {
						if len(line) > 100 {
							line = line[:100] + "..."
						}
						fmt.Printf("   %d: %s\n", i+1, line)
					}
					fmt.Printf("   ... (%d more lines)\n", len(lines)-5)
				} else {
					fmt.Printf("   ✅ %s\n", output)
				}
			} else {
				fmt.Printf("   ⚠️  %s\n", result.Error)
			}
		}
	}

	// Service security assessment
	fmt.Println("\n🔧 Service Security Assessment")
	fmt.Println(strings.Repeat("-", 40))

	criticalServices := []string{
		"sshd",
		"firewalld",
		"systemd-resolved",
		"NetworkManager",
	}

	for _, service := range criticalServices {
		fmt.Printf("\n🔹 %s Service:\n", service)

		// Check if service is active
		active := fetchers.IsServiceActive(service)
		enabled := fetchers.IsServiceEnabled(service)

		fmt.Printf("   📊 Active: %v\n", active)
		fmt.Printf("   📊 Enabled: %v\n", enabled)

		// Get detailed service status
		input := celscanner.NewSystemInput("service", service, "", []string{})
		data, err := systemFetcher.FetchInputs([]celscanner.Input{input}, nil)

		if err != nil {
			fmt.Printf("   ❌ Error getting service details: %v\n", err)
			continue
		}

		if result, ok := data["service"].(*fetchers.SystemResult); ok {
			if result.Success {
				fmt.Printf("   ✅ Status: %s\n", result.Status)
				if result.Metadata != nil {
					if timestamp, exists := result.Metadata["timestamp"]; exists {
						fmt.Printf("   📅 Checked: %v\n", timestamp)
					}
				}
			} else {
				fmt.Printf("   ❌ Failed to get details: %s\n", result.Error)
			}
		}
	}

	// Security recommendations
	fmt.Println("\n💡 Security Recommendations")
	fmt.Println(strings.Repeat("-", 40))

	recommendations := []struct {
		category string
		items    []string
	}{
		{
			category: "Access Control",
			items: []string{
				"Ensure SSH key-based authentication is configured",
				"Disable root login via SSH",
				"Configure sudo with least privilege principle",
				"Enable account lockout after failed attempts",
			},
		},
		{
			category: "Network Security",
			items: []string{
				"Enable and configure firewall (firewalld/iptables)",
				"Close unnecessary network ports",
				"Monitor network connections regularly",
				"Use SSH port forwarding instead of direct access",
			},
		},
		{
			category: "System Hardening",
			items: []string{
				"Enable SELinux in enforcing mode",
				"Keep system packages updated",
				"Configure log monitoring and alerting",
				"Regular security audits and vulnerability scans",
			},
		},
		{
			category: "Monitoring & Logging",
			items: []string{
				"Configure centralized logging",
				"Monitor failed authentication attempts",
				"Set up intrusion detection system",
				"Regular backup and recovery testing",
			},
		},
	}

	for _, rec := range recommendations {
		fmt.Printf("\n🔒 %s:\n", rec.category)
		for _, item := range rec.items {
			fmt.Printf("   • %s\n", item)
		}
	}
}

// Helper function to get status icon
func getStatusIcon(status celscanner.CheckResultStatus) string {
	switch status {
	case celscanner.CheckResultPass:
		return "✅"
	case celscanner.CheckResultFail:
		return "❌"
	case celscanner.CheckResultError:
		return "🚨"
	case celscanner.CheckResultNotApplicable:
		return "⏭️"
	default:
		return "❓"
	}
}
