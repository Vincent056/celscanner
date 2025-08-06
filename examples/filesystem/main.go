package main

import (
	"fmt"
	"log"
	"os"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("CEL Go Scanner - Filesystem Example")
	fmt.Println("===================================")

	// Create test directory structure
	err := setupTestFiles()
	if err != nil {
		log.Fatalf("Failed to setup test files: %v", err)
	}
	defer cleanup()

	// Example 1: Scanning a configuration file
	fmt.Println("\n1. Scanning a configuration file:")
	// This shows how to create a rule with file input using NEW PATTERN
	configRule, err := celscanner.NewRuleBuilder("config-check").
		WithFileInput("config", "test-app/config.yaml", "yaml", false, false).
		SetExpression("config.database.host == 'localhost' && config.database.port == 5432").
		WithName("Configuration Validation").
		WithDescription("Check database configuration").
		Build()
	if err != nil {
		log.Fatalf("Failed to build config rule: %v", err)
	}

	fmt.Printf("   Created rule: %s\n", configRule.Metadata().Name)
	fmt.Printf("   Expression: %s\n", configRule.Expression())

	// Create filesystem fetcher
	fetcher := fetchers.NewFilesystemFetcher("")

	// Fetch inputs
	inputs := []celscanner.Input{
		celscanner.NewFileInput("config", "test-app/config.yaml", "yaml", false, false),
	}

	data, err := fetcher.FetchInputs(inputs, nil)
	if err != nil {
		log.Printf("Failed to fetch inputs: %v", err)
		return
	}

	fmt.Printf("   Fetched config: %+v\n", data)

	// Example 2: Scanning directory with multiple files
	fmt.Println("\n2. Scanning directory with multiple files:")
	// This shows how to create a rule with directory input using NEW PATTERN
	dirRule, err := celscanner.NewRuleBuilder("dir-check").
		WithFileInput("configs", "test-app/", "yaml", false, false).
		SetExpression("size(configs) > 0").
		WithName("Directory Validation").
		WithDescription("Check configuration directory").
		Build()
	if err != nil {
		log.Fatalf("Failed to build dir rule: %v", err)
	}

	fmt.Printf("   Created rule: %s\n", dirRule.Metadata().Name)
	fmt.Printf("   Expression: %s\n", dirRule.Expression())

	dirInputs := []celscanner.Input{
		celscanner.NewFileInput("configs", "test-app/", "yaml", false, false),
	}

	dirData, err := fetcher.FetchInputs(dirInputs, nil)
	if err != nil {
		log.Printf("Failed to fetch directory inputs: %v", err)
		return
	}

	fmt.Printf("   Directory contents: %d files\n", len(dirData))
	for name := range dirData {
		fmt.Printf("   - %s\n", name)
	}

	// Example 3: Checking file permissions
	fmt.Println("\n3. Checking file permissions:")
	permInputs := []celscanner.Input{
		celscanner.NewFileInput("secret", "test-app/secret.txt", "text", false, true),
	}

	permData, err := fetcher.FetchInputs(permInputs, nil)
	if err != nil {
		log.Printf("Failed to fetch permission inputs: %v", err)
		return
	}

	if secretData, ok := permData["secret"].(map[string]interface{}); ok {
		fmt.Printf("   Secret file permissions: %s\n", secretData["perm"])
		fmt.Printf("   Secret file mode: %s\n", secretData["mode"])
	}

	// Example 4: Recursive directory scanning
	fmt.Println("\n4. Recursive directory scanning:")
	recursiveInputs := []celscanner.Input{
		celscanner.NewFileInput("all-configs", "test-app/", "yaml", true, false),
	}

	recursiveData, err := fetcher.FetchInputs(recursiveInputs, nil)
	if err != nil {
		log.Printf("Failed to fetch recursive inputs: %v", err)
		return
	}

	fmt.Printf("   Recursive scan found %d files\n", len(recursiveData))

	fmt.Println("\n✅ Filesystem examples completed successfully!")
}

func setupTestFiles() error {
	// Create test directory
	err := os.MkdirAll("test-app/subdir", 0755)
	if err != nil {
		return err
	}

	// Create config file
	configContent := `
name: test-app
version: 1.0.0
database:
  host: localhost
  port: 5432
  name: testdb
logging:
  level: info
  file: /var/log/app.log
`
	err = os.WriteFile("test-app/config.yaml", []byte(configContent), 0644)
	if err != nil {
		return err
	}

	// Create another config file
	dbConfigContent := `
host: localhost
port: 5432
username: testuser
password: secret123
`
	err = os.WriteFile("test-app/database.yaml", []byte(dbConfigContent), 0644)
	if err != nil {
		return err
	}

	// Create a secret file with restricted permissions
	secretContent := "supersecret"
	err = os.WriteFile("test-app/secret.txt", []byte(secretContent), 0600)
	if err != nil {
		return err
	}

	// Create a subdirectory config
	subConfigContent := `
feature: enabled
debug: true
`
	err = os.WriteFile("test-app/subdir/feature.yaml", []byte(subConfigContent), 0644)
	if err != nil {
		return err
	}

	return nil
}

func cleanup() {
	os.RemoveAll("test-app")
}
