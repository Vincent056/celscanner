package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("CEL Go Scanner - Complex Example")
	fmt.Println("================================")

	// Create test files
	err := setupTestFiles()
	if err != nil {
		log.Fatalf("Failed to setup test files: %v", err)
	}
	defer cleanup()

	// Example 1: Complex rule with multiple input types
	fmt.Println("\n1. Complex rule with multiple input types:")

	// Create a comprehensive rule using simplified structure
	rule := celscanner.NewRuleBuilder("system-health-check").
		WithFileInput("config", "test-system/config.yaml", "yaml", false, false).
		WithFileInput("logs", "test-system/logs/", "text", false, false).
		SetExpression("config.monitoring.enabled == true && size(logs) > 0").
		WithName("System Health Check").
		WithDescription("Comprehensive system health validation").
		WithExtension("severity", "HIGH").
		Build()

	fmt.Printf("   Rule: %s\n", rule.Metadata().Name)
	fmt.Printf("   Expression: %s\n", rule.Expression())
	fmt.Printf("   Inputs: %d\n", len(rule.Inputs()))

	// Example 2: Using composite fetcher with multiple input types
	fmt.Println("\n2. Using composite fetcher:")

	// Create composite fetcher with multiple capabilities
	compositeFetcher := fetchers.NewCompositeFetcherBuilder().
		WithFilesystem("").
		WithSystem(false). // Don't allow arbitrary commands
		Build()

	fmt.Printf("   Supported input types: %v\n", compositeFetcher.GetSupportedInputTypes())

	// Example 3: Fetching data from multiple sources
	fmt.Println("\n3. Fetching data from multiple sources:")

	inputs := []celscanner.Input{
		celscanner.NewFileInput("config", "test-system/config.yaml", "yaml", false, false),
		celscanner.NewFileInput("logs", "test-system/logs/", "text", false, false),
		celscanner.NewFileInput("secrets", "test-system/secrets.txt", "text", false, true),
	}

	data, err := compositeFetcher.FetchInputs(inputs, nil)
	if err != nil {
		log.Printf("Failed to fetch inputs: %v", err)
		return
	}

	fmt.Printf("   Fetched %d data sources:\n", len(data))
	for name, value := range data {
		switch v := value.(type) {
		case map[string]interface{}:
			if content, ok := v["content"]; ok {
				fmt.Printf("   - %s: %T\n", name, content)
			} else {
				fmt.Printf("   - %s: directory with %d files\n", name, len(v))
			}
		default:
			fmt.Printf("   - %s: %T\n", name, v)
		}
	}

	// Example 4: Validation of inputs
	fmt.Println("\n4. Input validation:")

	err = compositeFetcher.ValidateInputs(inputs)
	if err != nil {
		log.Printf("Input validation failed: %v", err)
		return
	}
	fmt.Println("   All inputs are valid ✅")

	// Example 5: Different rule patterns
	fmt.Println("\n5. Different rule patterns:")

	// Security rule
	securityRule := celscanner.NewRuleBuilder("security-check").
		WithFileInput("secrets", "test-system/secrets.txt", "text", false, true).
		SetExpression("secrets.perm == '0600' && !contains(secrets.content, 'password123')").
		WithName("Security Configuration Check").
		WithDescription("Ensure secrets are properly secured").
		WithExtension("severity", "CRITICAL").
		Build()

	fmt.Printf("   Security rule: %s\n", securityRule.Metadata().Name)

	// Performance rule
	perfRule := celscanner.NewRuleBuilder("performance-check").
		WithFileInput("config", "test-system/config.yaml", "yaml", false, false).
		SetExpression("config.database.pool_size >= 10 && config.cache.enabled == true").
		WithName("Performance Configuration Check").
		WithDescription("Ensure optimal performance settings").
		WithExtension("severity", "MEDIUM").
		Build()

	fmt.Printf("   Performance rule: %s\n", perfRule.Metadata().Name)

	// Example 6: Rule with custom metadata using Extensions
	fmt.Println("\n6. Rule with rich metadata using Extensions:")

	metadata := &celscanner.RuleMetadata{
		Name:        "Compliance Check",
		Description: "Ensures system complies with security standards",
		Extensions: map[string]interface{}{
			"rationale":    "Security compliance is mandatory for production systems",
			"severity":     "HIGH",
			"instructions": "Fix any security violations immediately",
			"title":        "Security Compliance Validation",
			"labels": map[string]string{
				"category":  "security",
				"framework": "SOC2",
				"automated": "true",
			},
			"annotations": map[string]string{
				"owner":    "security-team",
				"reviewed": "2024-01-01",
			},
		},
	}

	complianceRule := celscanner.NewRuleWithMetadata(
		"compliance-check",
		"config.security.enabled == true && secrets.perm == '0600'",
		[]celscanner.Input{
			celscanner.NewFileInput("config", "test-system/config.yaml", "yaml", false, false),
			celscanner.NewFileInput("secrets", "test-system/secrets.txt", "text", false, true),
		},
		metadata,
	)

	fmt.Printf("   Compliance rule: %s\n", complianceRule.Metadata().Name)
	fmt.Printf("   Rationale: %s\n", complianceRule.Metadata().Extensions["rationale"])
	fmt.Printf("   Labels: %v\n", complianceRule.Metadata().Extensions["labels"])

	fmt.Println("\n✅ Complex examples completed successfully!")
}

func setupTestFiles() error {
	// Create test directory structure
	err := os.MkdirAll("test-system/logs", 0755)
	if err != nil {
		return err
	}

	// Create config file
	configContent := `
name: test-system
version: 2.0.0
monitoring:
  enabled: true
  interval: 30s
database:
  host: localhost
  port: 5432
  pool_size: 20
cache:
  enabled: true
  ttl: 300s
security:
  enabled: true
  encryption: true
`
	err = os.WriteFile("test-system/config.yaml", []byte(configContent), 0644)
	if err != nil {
		return err
	}

	// Create log files
	logContent := "2024-01-01 12:00:00 INFO Application started\n2024-01-01 12:00:01 INFO Database connected\n"
	err = os.WriteFile("test-system/logs/app.log", []byte(logContent), 0644)
	if err != nil {
		return err
	}

	err = os.WriteFile("test-system/logs/error.log", []byte("2024-01-01 12:00:02 ERROR Connection timeout\n"), 0644)
	if err != nil {
		return err
	}

	// Create secrets file with restricted permissions
	secretContent := "api_key=secret123\ndb_password=supersecret\n"
	err = os.WriteFile("test-system/secrets.txt", []byte(secretContent), 0600)
	if err != nil {
		return err
	}

	return nil
}

func cleanup() {
	os.RemoveAll("test-system")
}
