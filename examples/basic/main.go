package main

import (
	"fmt"

	"github.com/Vincent056/celscanner"
)

func main() {
	fmt.Println("CEL Go Scanner - Basic Example")
	fmt.Println("==============================")

	// Example 1: Creating a simple rule with file input
	fmt.Println("\n1. Creating a rule with file input:")
	fileInput := celscanner.NewFileInput("config", "/etc/app/config.yaml", "yaml", false, false)
	fmt.Printf("   Input: %s (type: %s)\n", fileInput.Name(), fileInput.Type())
	fmt.Printf("   File path: %s\n", fileInput.Spec().(*celscanner.FileInput).Path())

	// Example 2: Creating a Kubernetes input
	fmt.Println("\n2. Creating a Kubernetes input:")
	k8sInput := celscanner.NewKubernetesInput("pods", "", "v1", "pods", "default", "")
	fmt.Printf("   Input: %s (type: %s)\n", k8sInput.Name(), k8sInput.Type())
	fmt.Printf("   Resource: %s\n", k8sInput.Spec().(*celscanner.KubernetesInput).ResourceType())

	// Example 3: Creating a rule with metadata using simplified structure
	fmt.Println("\n3. Creating a rule with metadata (simplified structure):")
	metadata := &celscanner.RuleMetadata{
		Name:        "Pod Security Check",
		Description: "Ensures pods have proper security configuration",
		Extensions: map[string]interface{}{
			"severity": "HIGH",
			"category": "security",
			"type":     "kubernetes",
		},
	}

	rule := celscanner.NewRuleWithMetadata(
		"pod-security-check",
		"size(pods) > 0",
		[]celscanner.Input{k8sInput},
		metadata,
	)

	fmt.Printf("   Rule ID: %s\n", rule.Identifier())
	fmt.Printf("   Rule Name: %s\n", rule.Metadata().Name)
	fmt.Printf("   Expression: %s\n", rule.Expression())
	fmt.Printf("   Inputs: %d\n", len(rule.Inputs()))

	// Example 4: Using the fluent builder pattern (inputs first, expression last)
	fmt.Println("\n4. Using the fluent builder pattern:")
	complexRule, err := celscanner.NewRuleBuilder("security-compliance").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		WithFileInput("policy", "/etc/security/policy.yaml", "yaml", false, false).
		SetExpression("size(pods) > 0 && has(policy.securityEnabled) && policy.securityEnabled == true").
		WithName("Security Compliance Check").
		WithDescription("Comprehensive security validation").
		WithExtension("category", "security").
		WithExtension("owner", "security-team").
		Build()
	if err != nil {
		fmt.Printf("   Error building rule: %v\n", err)
		return
	}

	fmt.Printf("   Rule ID: %s\n", complexRule.Identifier())
	fmt.Printf("   Rule Name: %s\n", complexRule.Metadata().Name)
	fmt.Printf("   Expression: %s\n", complexRule.Expression())
	fmt.Printf("   Inputs: %d\n", len(complexRule.Inputs()))

	for i, input := range complexRule.Inputs() {
		fmt.Printf("   Input %d: %s (%s)\n", i+1, input.Name(), input.Type())
	}

	// Example 5: Different input types with builder
	fmt.Println("\n5. Building rule with different input types:")

	// Show the logical flow: define inputs, then expression using those inputs
	builder := celscanner.NewRuleBuilder("comprehensive-health-check")

	// Add inputs first
	builder.WithKubernetesInput("pods", "", "v1", "pods", "", "").
		WithFileInput("config", "/etc/app/config.yaml", "yaml", false, false).
		WithSystemInput("nginx", "nginx", "", []string{"status"}).
		WithHTTPInput("api", "https://api.example.com/status", "GET", nil, nil)

	// Show available inputs before setting expression
	fmt.Printf("   Available inputs: %v\n", builder.GetAvailableInputNames())

	// Now set expression that uses the defined inputs
	healthRule, err := builder.
		SetExpression("size(pods) > 0 && config.monitoring.enabled == true && nginx.active == true && api.status == 'ok'").
		WithName("Comprehensive Health Check").
		WithDescription("Validates system health across multiple dimensions").
		WithExtension("severity", "HIGH").
		Build()
	if err != nil {
		fmt.Printf("   Error building health rule: %v\n", err)
		return
	}

	fmt.Printf("   Health check rule: %s\n", healthRule.Metadata().Name)
	fmt.Printf("   Uses %d inputs: %v\n", len(healthRule.Inputs()), builder.GetAvailableInputNames())

	// Example 6: Show validation in action
	fmt.Println("\n6. Builder validation:")
	fmt.Println("   ✅ Rules require ID, inputs, and expression")
	fmt.Println("   ✅ Logical order: inputs first, then expression")
	fmt.Println("   ✅ Expression can reference all defined inputs")
	fmt.Println("   ✅ Extensions field for custom metadata")

	fmt.Println("\n✅ Examples completed successfully!")
}
