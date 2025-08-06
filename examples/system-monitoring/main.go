package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("🔍 CEL Go Scanner - System Monitoring Example")
	fmt.Println(strings.Repeat("=", 50))

	// Create composite fetcher with system support
	fetcher := fetchers.NewCompositeFetcherBuilder().
		WithSystem(false). // Safe commands only
		Build()

	// Create scanner with logger
	logger := celscanner.DefaultLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	fmt.Println("\n📊 Running System Monitoring Scenarios...")

	// Example 1: Basic System Commands
	fmt.Println("\n🔧 Basic System Commands")
	fmt.Println(strings.Repeat("-", 30))
	runBasicSystemChecks(scanner)

	// Example 2: Service Status Monitoring
	fmt.Println("\n🔧 Service Status Monitoring")
	fmt.Println(strings.Repeat("-", 30))
	runServiceStatusChecks(scanner)

	// Example 3: System Information Gathering
	fmt.Println("\n📊 System Information Gathering")
	fmt.Println(strings.Repeat("-", 30))
	runSystemInfoChecks(scanner)

	// Example 4: Direct Fetcher Usage
	fmt.Println("\n⚡ Direct Fetcher Usage Examples")
	fmt.Println(strings.Repeat("-", 30))
	runDirectFetcherExamples()
}

// Example 1: Basic system command checks
func runBasicSystemChecks(scanner *celscanner.Scanner) {
	// Create a simple rule to check if hostname command works
	rule, err := celscanner.NewRuleBuilder("hostname-check").
		WithSystemInput("hostname", "", "hostname", []string{}).
		SetExpression("size(hostname) > 0").
		WithName("Hostname Check").
		WithDescription("Verifies that hostname command returns data").
		WithExtension("category", "system").
		Build()
	if err != nil {
		fmt.Printf("❌ Error building hostname rule: %v\n", err)
		return
	}

	// Run the scan
	config := celscanner.ScanConfig{
		Rules:              []celscanner.CelRule{rule},
		Variables:          []celscanner.CelVariable{},
		EnableDebugLogging: false,
	}

	results, err := scanner.Scan(context.Background(), config)
	if err != nil {
		fmt.Printf("❌ Error running scan: %v\n", err)
		return
	}

	// Display results
	for _, result := range results {
		statusIcon := getStatusIcon(result.Status)
		fmt.Printf("🔍 %s: %s %s\n", rule.Metadata().Name, statusIcon, result.Status)

		if len(result.Warnings) > 0 {
			for _, warning := range result.Warnings {
				fmt.Printf("   ⚠️  %s\n", warning)
			}
		}
	}
}

// Example 2: Service status monitoring
func runServiceStatusChecks(scanner *celscanner.Scanner) {
	// Check SSH service status
	sshRule, err := celscanner.NewRuleBuilder("ssh-service-check").
		WithSystemInput("ssh_service", "sshd", "", []string{}).
		SetExpression("size(ssh_service) > 0").
		WithName("SSH Service Status").
		WithDescription("Checks SSH service status").
		WithExtension("category", "service").
		WithExtension("service", "sshd").
		Build()
	if err != nil {
		fmt.Printf("❌ Error building SSH rule: %v\n", err)
		return
	}

	config := celscanner.ScanConfig{
		Rules:              []celscanner.CelRule{sshRule},
		Variables:          []celscanner.CelVariable{},
		EnableDebugLogging: false,
	}

	results, err := scanner.Scan(context.Background(), config)
	if err != nil {
		fmt.Printf("❌ Error checking SSH service: %v\n", err)
		return
	}

	for _, result := range results {
		statusIcon := getStatusIcon(result.Status)
		fmt.Printf("🔍 %s: %s %s\n", sshRule.Metadata().Name, statusIcon, result.Status)

		if len(result.Warnings) > 0 {
			for _, warning := range result.Warnings {
				fmt.Printf("   ⚠️  %s\n", warning)
			}
		}
	}
}

// Example 3: System information gathering
func runSystemInfoChecks(scanner *celscanner.Scanner) {
	// Get system uptime
	uptimeRule, err := celscanner.NewRuleBuilder("uptime-check").
		WithSystemInput("uptime", "", "uptime", []string{}).
		SetExpression("size(uptime) > 0").
		WithName("System Uptime").
		WithDescription("Gets system uptime information").
		WithExtension("category", "info").
		Build()
	if err != nil {
		fmt.Printf("❌ Error building uptime rule: %v\n", err)
		return
	}

	config := celscanner.ScanConfig{
		Rules:              []celscanner.CelRule{uptimeRule},
		Variables:          []celscanner.CelVariable{},
		EnableDebugLogging: false,
	}

	results, err := scanner.Scan(context.Background(), config)
	if err != nil {
		fmt.Printf("❌ Error getting uptime: %v\n", err)
		return
	}

	for _, result := range results {
		statusIcon := getStatusIcon(result.Status)
		fmt.Printf("🔍 %s: %s %s\n", uptimeRule.Metadata().Name, statusIcon, result.Status)
	}
}

// Example 4: Direct fetcher usage (bypassing scanner)
func runDirectFetcherExamples() {
	// Create system fetcher directly
	systemFetcher := fetchers.NewSystemFetcher(30*time.Second, false)

	// Example 4.1: Execute system commands directly
	fmt.Println("\n📋 Direct Command Execution:")

	commands := []struct {
		name    string
		command string
		args    []string
	}{
		{"System Info", "uname", []string{"-a"}},
		{"Memory Info", "free", []string{"-h"}},
		{"Disk Usage", "df", []string{"-h"}},
		{"Current User", "whoami", []string{}},
		{"Load Average", "uptime", []string{}},
	}

	for _, cmd := range commands {
		fmt.Printf("\n🔹 %s:\n", cmd.name)

		input := celscanner.NewSystemInput("test", "", cmd.command, cmd.args)
		data, err := systemFetcher.FetchInputs([]celscanner.Input{input}, nil)

		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if result, ok := data["test"].(*fetchers.SystemResult); ok {
			if result.Success {
				output := strings.TrimSpace(result.Output)
				if len(output) > 200 {
					output = output[:200] + "..."
				}
				fmt.Printf("   ✅ %s\n", output)
			} else {
				fmt.Printf("   ❌ Command failed: %s\n", result.Error)
			}
		}
	}

	// Example 4.2: Service status checks
	fmt.Println("\n🔧 Direct Service Status Checks:")

	services := []string{"sshd", "NetworkManager", "systemd-resolved"}

	for _, service := range services {
		fmt.Printf("\n🔹 %s Service:\n", service)

		input := celscanner.NewSystemInput("service", service, "", []string{})
		data, err := systemFetcher.FetchInputs([]celscanner.Input{input}, nil)

		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if result, ok := data["service"].(*fetchers.SystemResult); ok {
			if result.Success {
				fmt.Printf("   ✅ Status: %s\n", result.Status)
				if result.Metadata != nil {
					if active, exists := result.Metadata["active"]; exists {
						fmt.Printf("   📊 Active: %v\n", active)
					}
				}
			} else {
				fmt.Printf("   ❌ Failed to get status: %s\n", result.Error)
			}
		}
	}

	// Example 4.3: Security command checks
	fmt.Println("\n🔒 Security Status Checks:")

	securityChecks := []struct {
		name    string
		command string
		args    []string
	}{
		{"SELinux Status", "getenforce", []string{}},
		{"Firewall Status", "systemctl", []string{"is-active", "firewalld"}},
		{"Active Sessions", "who", []string{}},
	}

	for _, check := range securityChecks {
		fmt.Printf("\n🔹 %s:\n", check.name)

		input := celscanner.NewSystemInput("security", "", check.command, check.args)
		data, err := systemFetcher.FetchInputs([]celscanner.Input{input}, nil)

		if err != nil {
			fmt.Printf("   ❌ Error: %v\n", err)
			continue
		}

		if result, ok := data["security"].(*fetchers.SystemResult); ok {
			if result.Success {
				output := strings.TrimSpace(result.Output)
				fmt.Printf("   ✅ %s\n", output)
			} else {
				fmt.Printf("   ⚠️  %s (exit code: %d)\n", strings.TrimSpace(result.Output), result.ExitCode)
			}
		}
	}

	// Example 4.4: Helper function usage
	fmt.Println("\n🛠️  Using Helper Functions:")

	fmt.Printf("\n🔹 System Information:\n")
	if result, err := fetchers.GetSystemInfo(); err == nil && result.Success {
		fmt.Printf("   ✅ %s\n", strings.TrimSpace(result.Output))
	} else {
		fmt.Printf("   ❌ Error: %v\n", err)
	}

	fmt.Printf("\n🔹 Command Execution Example:\n")
	if result, err := fetchers.ExecuteCommand("echo", []string{"Hello from SystemFetcher!"}); err == nil && result.Success {
		fmt.Printf("   ✅ %s\n", strings.TrimSpace(result.Output))
		fmt.Printf("   📊 Command: %s\n", result.Metadata["command"])
		fmt.Printf("   📊 Args: %v\n", result.Metadata["args"])
		fmt.Printf("   📊 Timestamp: %v\n", result.Metadata["timestamp"])
	} else {
		fmt.Printf("   ❌ Error: %v\n", err)
	}

	fmt.Printf("\n🔹 Service Status Helpers:\n")
	testServices := []string{"sshd", "nonexistent-service"}
	for _, service := range testServices {
		active := fetchers.IsServiceActive(service)
		enabled := fetchers.IsServiceEnabled(service)
		fmt.Printf("   📋 %s: Active=%v, Enabled=%v\n", service, active, enabled)
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

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}
