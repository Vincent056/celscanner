package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	runtimeclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
)

func main() {
	fmt.Println("CEL Go Scanner - Live Kubernetes Example")
	fmt.Println("========================================")

	// Check if we can connect to a Kubernetes cluster
	kubeconfigPath := getKubeconfigPath()
	if kubeconfigPath == "" {
		fmt.Println("❌ No kubeconfig found. This example requires access to a Kubernetes cluster.")
		fmt.Println("   Please ensure you have kubectl configured or set KUBECONFIG environment variable.")
		os.Exit(1)
	}

	fmt.Printf("📝 Using kubeconfig: %s\n", kubeconfigPath)

	// Example 1: Real-world security rules
	fmt.Println("\n1. Creating real-world security compliance rules:")

	securityRules := []celscanner.CelRule{
		// Rule 1: Check for pods without security context
		celscanner.NewRuleBuilder("pod-security-context").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression("pods.items.all(pod, has(pod.spec.securityContext))").
			WithName("Pod Security Context Check").
			WithDescription("Ensures all pods have security context defined").
			WithExtension("severity", "HIGH").
			WithExtension("category", "security").
			Build(),

		// Rule 2: Check for containers without resource limits
		celscanner.NewRuleBuilder("container-resource-limits").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`pods.items.all(pod, 
				pod.spec.containers.all(container, 
					has(container.resources) && 
					has(container.resources.limits) && 
					has(container.resources.limits.memory) && 
					has(container.resources.limits.cpu)
				)
			)`).
			WithName("Container Resource Limits Check").
			WithDescription("Ensures all containers have CPU and memory limits").
			WithExtension("severity", "MEDIUM").
			WithExtension("category", "resource-management").
			Build(),

		// Rule 3: Check for privileged containers
		celscanner.NewRuleBuilder("privileged-containers").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`!pods.items.exists(pod,
				pod.spec.containers.exists(container,
					has(container.securityContext) &&
					has(container.securityContext.privileged) &&
					container.securityContext.privileged == true
				)
			)`).
			WithName("No Privileged Containers").
			WithDescription("Ensures no containers run with privileged access").
			WithExtension("severity", "CRITICAL").
			WithExtension("category", "security").
			Build(),

		// Rule 4: Check for default service account usage
		celscanner.NewRuleBuilder("service-account-check").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`!pods.items.exists(pod,
				!has(pod.spec.serviceAccountName) || 
				pod.spec.serviceAccountName == "default"
			)`).
			WithName("Service Account Usage").
			WithDescription("Ensures pods don't use the default service account").
			WithExtension("severity", "MEDIUM").
			WithExtension("category", "security").
			Build(),
	}

	fmt.Printf("   Created %d security rules\n", len(securityRules))

	// Example 2: Create Kubernetes clients
	fmt.Println("\n2. Setting up live Kubernetes scanner:")

	// Create rest config from kubeconfig
	restConfig, err := createKubeConfig(kubeconfigPath)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes config: %v", err)
	}

	// Create standard Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes clientset: %v", err)
	}

	// Create controller-runtime client
	runtimeClient, err := runtimeclient.New(restConfig, runtimeclient.Options{})
	if err != nil {
		log.Fatalf("Failed to create runtime client: %v", err)
	}

	// Create composite fetcher with Kubernetes support
	compositeFetcher := fetchers.NewCompositeFetcherBuilder().
		WithKubernetes(runtimeClient, clientset).
		WithFilesystem(""). // Add filesystem support too
		Build()

	// Create scanner
	scanner := celscanner.NewScanner(compositeFetcher, &LiveLogger{})
	fmt.Println("   ✅ Scanner created with live Kubernetes connection")

	// Example 3: Test connection by listing namespaces
	fmt.Println("\n3. Testing connection - fetching namespaces:")

	namespaceRule := celscanner.NewRuleBuilder("namespace-count").
		WithKubernetesInput("namespaces", "", "v1", "namespaces", "", "").
		SetExpression("size(namespaces.items) > 0").
		WithName("Namespace Existence Check").
		WithDescription("Verifies that namespaces exist in the cluster").
		Build()

	testConfig := celscanner.ScanConfig{
		Rules: []celscanner.CelRule{namespaceRule},
	}

	ctx := context.Background()
	testResults, err := scanner.Scan(ctx, testConfig)
	if err != nil {
		log.Fatalf("Failed to connect to Kubernetes cluster: %v", err)
	}

	if len(testResults) > 0 && testResults[0].Status == celscanner.CheckResultPass {
		fmt.Println("   ✅ Successfully connected to Kubernetes cluster")
	} else {
		fmt.Println("   ❌ Failed to verify cluster connection")
		if len(testResults) > 0 {
			fmt.Printf("   Error: %s\n", testResults[0].ErrorMessage)
		}
		return
	}

	// Example 4: Run comprehensive security scan
	fmt.Println("\n4. Running comprehensive security scan on live cluster:")

	config := celscanner.ScanConfig{
		Rules: securityRules,
	}

	results, err := scanner.Scan(ctx, config)
	if err != nil {
		log.Fatalf("Security scan failed: %v", err)
	}

	// Example 5: Analyze and report results
	fmt.Println("\n5. Security Scan Results:")
	fmt.Println("========================")

	var passed, failed, errors int
	for i, result := range results {
		fmt.Printf("\nRule %d: %s\n", i+1, result.ID)
		fmt.Printf("  Status: %s\n", result.Status)

		switch result.Status {
		case celscanner.CheckResultPass:
			fmt.Printf("  ✅ COMPLIANT\n")
			passed++
		case celscanner.CheckResultFail:
			fmt.Printf("  ❌ NON-COMPLIANT\n")
			failed++
		case celscanner.CheckResultError:
			fmt.Printf("  🚨 ERROR: %s\n", result.ErrorMessage)
			errors++
		}

		if len(result.Warnings) > 0 {
			fmt.Printf("  Warnings: %v\n", result.Warnings)
		}
	}

	// Example 6: Summary and recommendations
	fmt.Println("\n6. Security Assessment Summary:")
	fmt.Println("==============================")
	fmt.Printf("  Total Rules: %d\n", len(results))
	fmt.Printf("  ✅ Compliant: %d\n", passed)
	fmt.Printf("  ❌ Non-Compliant: %d\n", failed)
	fmt.Printf("  🚨 Errors: %d\n", errors)

	if failed > 0 {
		fmt.Println("\n🔍 Recommendations:")
		fmt.Println("  - Review non-compliant resources")
		fmt.Println("  - Implement security contexts for all pods")
		fmt.Println("  - Set resource limits on all containers")
		fmt.Println("  - Avoid privileged containers")
		fmt.Println("  - Use dedicated service accounts")
	}

	if passed == len(securityRules) {
		fmt.Println("\n🎉 Excellent! Your cluster passes all security checks.")
	} else {
		fmt.Printf("\n⚠️  Security improvements needed: %d/%d rules passed\n", passed, len(securityRules))
	}

	fmt.Println("\n✅ Live Kubernetes security scan completed!")
}

// createKubeConfig creates a Kubernetes rest config from kubeconfig file
func createKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	// Try to use in-cluster config first (if running in a pod)
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	// Use kubeconfig file
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}

	// Fallback to controller-runtime's config loader
	return config.GetConfig()
}

// getKubeconfigPath returns the path to kubeconfig file
func getKubeconfigPath() string {
	// Check KUBECONFIG environment variable first
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return kubeconfig
	}

	// Check default location
	if home := homedir.HomeDir(); home != "" {
		kubeconfigPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfigPath); err == nil {
			return kubeconfigPath
		}
	}

	return ""
}

// LiveLogger provides structured logging for the live example
type LiveLogger struct{}

func (l *LiveLogger) Debug(msg string, args ...interface{}) {
	// Only show debug in verbose mode
	if os.Getenv("DEBUG") == "true" {
		fmt.Printf("[DEBUG] "+msg+"\n", args...)
	}
}

func (l *LiveLogger) Info(msg string, args ...interface{}) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}

func (l *LiveLogger) Warn(msg string, args ...interface{}) {
	fmt.Printf("[WARN] "+msg+"\n", args...)
}

func (l *LiveLogger) Error(msg string, args ...interface{}) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}
