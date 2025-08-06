package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("CEL Go Scanner - Kubernetes Example (Unified API)")
	fmt.Println("=================================================")

	// Create test data to simulate Kubernetes API responses
	err := setupTestData()
	if err != nil {
		log.Fatalf("Failed to setup test data: %v", err)
	}
	defer cleanup()

	// Example 1: Create rules using the new unified API
	fmt.Println("\n1. Creating rules with the new RuleBuilder API:")

	// Security-focused rule
	securityRule, err := celscanner.NewRuleBuilder("pod-security-check").
		WithKubernetesInput("pods", "", "v1", "pods", "default", "").
		SetExpression("size(pods.items) > 0 && pods.items.all(pod, has(pod.spec.securityContext))").
		WithName("Pod Security Context Check").
		WithDescription("Ensures all pods have security context defined").
		Build()
	if err != nil {
		log.Fatalf("Failed to build security rule: %v", err)
	}

	// Resource management rule
	resourceRule, err := celscanner.NewRuleBuilder("pod-resource-limits").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		SetExpression("pods.items.all(pod, pod.spec.containers.all(container, has(container.resources.limits)))").
		WithName("Pod Resource Limits Check").
		WithDescription("Ensures all containers have resource limits").
		Build()
	if err != nil {
		log.Fatalf("Failed to build resource rule: %v", err)
	}

	// Multi-resource compliance rule
	complianceRule, err := celscanner.NewRuleBuilder("namespace-compliance").
		WithKubernetesInput("namespaces", "", "v1", "namespaces", "", "").
		WithKubernetesInput("networkpolicies", "networking.k8s.io", "v1", "networkpolicies", "", "").
		SetExpression(`
			namespaces.items.all(ns, 
				networkpolicies.items.exists(np, 
					np.metadata.namespace == ns.metadata.name
				)
			)
		`).
		WithName("Namespace Network Policy Compliance").
		WithDescription("Ensures namespaces have associated network policies").
		Build()
	if err != nil {
		log.Fatalf("Failed to build compliance rule: %v", err)
	}

	rules := []celscanner.CelRule{securityRule, resourceRule, complianceRule}

	fmt.Printf("   Created %d rules\n", len(rules))
	for i, rule := range rules {
		fmt.Printf("   Rule %d: %s (%d inputs)\n", i+1, rule.Metadata().Name, len(rule.Inputs()))
	}

	// Example 2: Create scanner with composite fetcher
	fmt.Println("\n2. Creating scanner with unified API:")

	// Create composite fetcher that uses file-based Kubernetes resources
	fetcher := fetchers.NewCompositeFetcherBuilder().
		WithKubernetesFiles("testdata"). // Use test data directory
		Build()

	// Create scanner with the fetcher
	scanner := celscanner.NewScanner(fetcher, nil)
	fmt.Printf("   Scanner created with composite fetcher\n")

	// Example 3: Execute scan with unified API
	fmt.Println("\n3. Executing scan with unified API:")

	// Create scan configuration
	config := celscanner.ScanConfig{
		Rules:              rules,
		Variables:          []celscanner.CelVariable{}, // No additional variables
		ApiResourcePath:    "testdata",                 // Use test data files
		EnableDebugLogging: true,
	}

	// Run the scan
	ctx := context.Background()
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Printf("Scan failed: %v", err)
		return
	}

	// Example 4: Process results
	fmt.Println("\n4. Scan Results:")
	fmt.Println("================")

	for i, result := range results {
		fmt.Printf("\nResult %d:\n", i+1)
		fmt.Printf("  Rule ID: %s\n", result.ID)
		fmt.Printf("  Status: %s\n", result.Status)

		if result.ErrorMessage != "" {
			fmt.Printf("  Error: %s\n", result.ErrorMessage)
		}

		if len(result.Warnings) > 0 {
			fmt.Printf("  Warnings: %v\n", result.Warnings)
		}

		// Show status icon
		switch result.Status {
		case celscanner.CheckResultPass:
			fmt.Printf("  ✅ PASSED\n")
		case celscanner.CheckResultFail:
			fmt.Printf("  ❌ FAILED\n")
		case celscanner.CheckResultError:
			fmt.Printf("  🚨 ERROR\n")
		default:
			fmt.Printf("  ⚠️  UNKNOWN\n")
		}
	}

	// Example 5: Summary statistics
	fmt.Println("\n5. Summary:")
	fmt.Println("===========")

	passed := 0
	failed := 0
	errors := 0

	for _, result := range results {
		switch result.Status {
		case celscanner.CheckResultPass:
			passed++
		case celscanner.CheckResultFail:
			failed++
		case celscanner.CheckResultError:
			errors++
		}
	}

	fmt.Printf("  Total Rules: %d\n", len(results))
	fmt.Printf("  Passed: %d\n", passed)
	fmt.Printf("  Failed: %d\n", failed)
	fmt.Printf("  Errors: %d\n", errors)

	if errors == 0 && failed == 0 {
		fmt.Printf("  🎉 All checks passed!\n")
	} else if errors > 0 {
		fmt.Printf("  ⚠️  Some rules had errors\n")
	} else {
		fmt.Printf("  ❌ Some rules failed\n")
	}

	fmt.Println("\n✅ Kubernetes unified API example completed!")
}

func setupTestData() error {
	// Create testdata directory
	err := os.MkdirAll("testdata", 0755)
	if err != nil {
		return err
	}

	// Create namespaces test data
	namespacesData := `{
  "apiVersion": "v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "v1",
      "kind": "Namespace",
      "metadata": {
        "name": "default",
        "labels": {
          "name": "default"
        }
      }
    },
    {
      "apiVersion": "v1", 
      "kind": "Namespace",
      "metadata": {
        "name": "kube-system",
        "labels": {
          "name": "kube-system"
        }
      }
    }
  ]
}`

	err = os.WriteFile("testdata/namespaces.json", []byte(namespacesData), 0644)
	if err != nil {
		return err
	}

	// Create pods test data
	podsData := `{
  "apiVersion": "v1",
  "kind": "List", 
  "items": [
    {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {
        "name": "secure-pod",
        "namespace": "default"
      },
      "spec": {
        "securityContext": {
          "runAsUser": 1000
        },
        "containers": [
          {
            "name": "app",
            "image": "nginx:latest",
            "resources": {
              "limits": {
                "cpu": "100m",
                "memory": "128Mi"
              }
            }
          }
        ]
      }
    },
    {
      "apiVersion": "v1",
      "kind": "Pod", 
      "metadata": {
        "name": "insecure-pod",
        "namespace": "default"
      },
      "spec": {
        "containers": [
          {
            "name": "app",
            "image": "nginx:latest"
          }
        ]
      }
    }
  ]
}`

	err = os.WriteFile("testdata/pods.json", []byte(podsData), 0644)
	if err != nil {
		return err
	}

	// Create network policies test data
	networkPoliciesData := `{
  "apiVersion": "networking.k8s.io/v1",
  "kind": "List",
  "items": [
    {
      "apiVersion": "networking.k8s.io/v1",
      "kind": "NetworkPolicy",
      "metadata": {
        "name": "default-deny",
        "namespace": "default"
      },
      "spec": {
        "podSelector": {},
        "policyTypes": ["Ingress", "Egress"]
      }
    }
  ]
}`

	err = os.WriteFile("testdata/networkpolicies.json", []byte(networkPoliciesData), 0644)
	if err != nil {
		return err
	}

	return nil
}

func cleanup() {
	os.RemoveAll("testdata")
}
