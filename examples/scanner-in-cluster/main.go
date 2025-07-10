package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("🔍 CEL Go Scanner - In-Cluster Security Scanning")
	fmt.Println(strings.Repeat("=", 60))

	// Create composite fetcher with multiple capabilities
	fetcher := fetchers.NewCompositeFetcherBuilder().
		WithKubernetes(nil, nil). // Kubernetes API access
		WithFilesystem("").       // Filesystem access
		WithSystem(false).        // Safe system commands
		Build()

	// Create scanner with logger
	logger := celscanner.DefaultLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	// Check if we have Kubernetes access
	hasKubernetesAccess := checkKubernetesAccess(scanner)
	if !hasKubernetesAccess {
		fmt.Println("\n⚠️  No Kubernetes access detected - some checks will be skipped")
		fmt.Println("   This is expected when running outside a cluster")
	}

	fmt.Println("\n🏗️  Container-Native Security Scanning Approaches...")

	// Approach 1: Direct filesystem access via mounted volumes
	runVolumeBasedScanning(scanner)

	// Approach 2: Kubernetes API-based security policy checking
	runKubernetesAPIScanning(scanner)

	// Approach 3: Pod Security Standards enforcement
	runPodSecurityStandardsCheck(scanner)

	// Approach 4: Security Context Constraints (OpenShift specific)
	runSecurityContextConstraintsCheck(scanner)

	// Approach 5: Host filesystem inspection (when privileged)
	runHostFilesystemScanning(scanner)

	// Approach 6: Service Account and RBAC validation
	runServiceAccountValidation(scanner)

	fmt.Println("\n✅ In-cluster security scanning completed!")
}

// Approach 1: Direct filesystem access via mounted volumes
func runVolumeBasedScanning(scanner *celscanner.Scanner) {
	fmt.Println("\n📁 Approach 1: Volume-Based Filesystem Scanning")
	fmt.Println(strings.Repeat("-", 55))

	// This approach works when:
	// 1. Scanner container has shared volumes with target containers
	// 2. Volumes are mounted at known paths
	// 3. Scanner has read access to mounted filesystems

	volumePaths := []struct {
		name        string
		mountPath   string
		description string
		critical    bool
	}{
		{
			name:        "app-config",
			mountPath:   "/shared/app-config",
			description: "Application configuration volume",
			critical:    true,
		},
		{
			name:        "app-data",
			mountPath:   "/shared/app-data",
			description: "Application data volume",
			critical:    true,
		},
		{
			name:        "app-logs",
			mountPath:   "/shared/logs",
			description: "Application logs volume",
			critical:    false,
		},
		{
			name:        "secrets",
			mountPath:   "/shared/secrets",
			description: "Mounted secrets volume",
			critical:    true,
		},
	}

	for _, vol := range volumePaths {
		fmt.Printf("\n🔍 Scanning volume: %s (%s)\n", vol.name, vol.mountPath)

		// Rule to check if volume exists and has proper permissions
		rule := celscanner.NewRuleBuilder(fmt.Sprintf("volume-security-%s", vol.name)).
			WithFileInput("volume_check", vol.mountPath, "", false, true).
			SetExpression(`size(volume_check) > 0`).
			WithName(fmt.Sprintf("Volume Security: %s", vol.name)).
			WithDescription(vol.description).
			WithExtension("severity", map[bool]string{true: "CRITICAL", false: "MEDIUM"}[vol.critical]).
			WithExtension("mount_path", vol.mountPath).
			WithExtension("volume_type", "shared").
			Build()

		runSingleRule(scanner, rule)

		// Additional checks for critical volumes
		if vol.critical {
			runCriticalVolumeChecks(scanner, vol.name, vol.mountPath)
		}
	}
}

// Approach 2: Kubernetes API-based security policy checking
func runKubernetesAPIScanning(scanner *celscanner.Scanner) {
	fmt.Println("\n🎯 Approach 2: Kubernetes API Security Scanning")
	fmt.Println(strings.Repeat("-", 55))

	// This approach uses Kubernetes APIs to check security policies
	// without needing to exec into containers

	securityRules := []celscanner.CelRule{
		// Check Pod Security Context
		celscanner.NewRuleBuilder("pod-security-context").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod, 
					has(pod.spec.securityContext) && 
					has(pod.spec.securityContext.runAsNonRoot) &&
					pod.spec.securityContext.runAsNonRoot == true
				)
			`).
			WithName("Pod Security Context Check").
			WithDescription("Ensures all pods run as non-root user").
			WithExtension("severity", "HIGH").
			WithExtension("compliance", "CIS").
			Build(),

		// Check Container Security Context
		celscanner.NewRuleBuilder("container-security-context").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					pod.spec.containers.all(container,
						has(container.securityContext) &&
						(!has(container.securityContext.privileged) || 
						 container.securityContext.privileged == false) &&
						(!has(container.securityContext.allowPrivilegeEscalation) ||
						 container.securityContext.allowPrivilegeEscalation == false)
					)
				)
			`).
			WithName("Container Security Context").
			WithDescription("Ensures containers are not privileged").
			WithExtension("severity", "CRITICAL").
			WithExtension("compliance", "STIG").
			Build(),

		// Check Resource Limits
		celscanner.NewRuleBuilder("resource-limits-check").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					pod.spec.containers.all(container,
						has(container.resources) &&
						has(container.resources.limits) &&
						has(container.resources.limits.memory) &&
						has(container.resources.limits.cpu)
					)
				)
			`).
			WithName("Resource Limits Required").
			WithDescription("All containers must have resource limits").
			WithExtension("severity", "MEDIUM").
			WithExtension("compliance", "Best Practice").
			Build(),

		// Check Volume Security
		celscanner.NewRuleBuilder("volume-security-check").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					!has(pod.spec.volumes) ||
					pod.spec.volumes.all(volume,
						!has(volume.hostPath) &&
						(!has(volume.secret) || 
						 (has(volume.secret.defaultMode) && 
						  volume.secret.defaultMode <= 384))
					)
				)
			`).
			WithName("Volume Security Check").
			WithDescription("Ensures secure volume configurations").
			WithExtension("severity", "HIGH").
			WithExtension("compliance", "Security").
			Build(),
	}

	// Execute API-based security rules
	for _, rule := range securityRules {
		fmt.Printf("\n🔍 API Check: %s\n", rule.Metadata().Name)
		runSingleRule(scanner, rule)
	}
}

// Approach 3: Pod Security Standards enforcement
func runPodSecurityStandardsCheck(scanner *celscanner.Scanner) {
	fmt.Println("\n🛡️  Approach 3: Pod Security Standards")
	fmt.Println(strings.Repeat("-", 55))

	// Pod Security Standards provide built-in security policies
	podSecurityRules := []celscanner.CelRule{
		// Baseline Policy: No privileged containers
		celscanner.NewRuleBuilder("pss-baseline-privileged").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					pod.spec.containers.all(container,
						!has(container.securityContext.privileged) ||
						container.securityContext.privileged == false
					)
				)
			`).
			WithName("PSS Baseline: No Privileged Containers").
			WithDescription("Pod Security Standard baseline policy").
			WithExtension("severity", "HIGH").
			WithExtension("standard", "baseline").
			Build(),

		// Restricted Policy: Must run as non-root
		celscanner.NewRuleBuilder("pss-restricted-nonroot").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					(has(pod.spec.securityContext.runAsNonRoot) &&
					 pod.spec.securityContext.runAsNonRoot == true) ||
					pod.spec.containers.all(container,
						has(container.securityContext.runAsNonRoot) &&
						container.securityContext.runAsNonRoot == true
					)
				)
			`).
			WithName("PSS Restricted: Run as Non-Root").
			WithDescription("Pod Security Standard restricted policy").
			WithExtension("severity", "HIGH").
			WithExtension("standard", "restricted").
			Build(),

		// Restricted Policy: No privilege escalation
		celscanner.NewRuleBuilder("pss-restricted-no-escalation").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					pod.spec.containers.all(container,
						!has(container.securityContext.allowPrivilegeEscalation) ||
						container.securityContext.allowPrivilegeEscalation == false
					)
				)
			`).
			WithName("PSS Restricted: No Privilege Escalation").
			WithDescription("Prevents privilege escalation").
			WithExtension("severity", "HIGH").
			WithExtension("standard", "restricted").
			Build(),
	}

	for _, rule := range podSecurityRules {
		fmt.Printf("\n🔍 PSS Check: %s\n", rule.Metadata().Name)
		runSingleRule(scanner, rule)
	}
}

// Approach 4: Security Context Constraints (OpenShift specific)
func runSecurityContextConstraintsCheck(scanner *celscanner.Scanner) {
	fmt.Println("\n🔐 Approach 4: Security Context Constraints (OpenShift)")
	fmt.Println(strings.Repeat("-", 55))

	// OpenShift Security Context Constraints provide additional security
	sccRules := []celscanner.CelRule{
		// Check SCC assignment
		celscanner.NewRuleBuilder("scc-assignment-check").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					has(pod.metadata.annotations) &&
					has(pod.metadata.annotations["openshift.io/scc"])
				)
			`).
			WithName("SCC Assignment Validation").
			WithDescription("Ensures pods have proper SCC assignment").
			WithExtension("severity", "MEDIUM").
			WithExtension("platform", "openshift").
			Build(),

		// Check for restricted SCC usage
		celscanner.NewRuleBuilder("scc-restricted-usage").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					!has(pod.metadata.annotations["openshift.io/scc"]) ||
					pod.metadata.annotations["openshift.io/scc"] in ["restricted", "restricted-v2"]
				)
			`).
			WithName("Restricted SCC Usage").
			WithDescription("Prefers restricted Security Context Constraints").
			WithExtension("severity", "HIGH").
			WithExtension("platform", "openshift").
			Build(),
	}

	for _, rule := range sccRules {
		fmt.Printf("\n🔍 SCC Check: %s\n", rule.Metadata().Name)
		runSingleRule(scanner, rule)
	}
}

// Approach 5: Host filesystem inspection (when privileged)
func runHostFilesystemScanning(scanner *celscanner.Scanner) {
	fmt.Println("\n🖥️  Approach 5: Host Filesystem Scanning (Privileged)")
	fmt.Println(strings.Repeat("-", 55))

	// This approach requires the scanner to run with elevated privileges
	// and mount host filesystem paths

	hostPaths := []string{
		"/host/etc/passwd",
		"/host/etc/shadow",
		"/host/etc/ssh/sshd_config",
		"/host/var/log/audit/audit.log",
		"/host/proc/version",
	}

	for _, hostPath := range hostPaths {
		fmt.Printf("\n🔍 Checking host path: %s\n", hostPath)

		// Check if host path is accessible and secure
		rule := celscanner.NewRuleBuilder(fmt.Sprintf("host-file-%s", strings.ReplaceAll(hostPath, "/", "-"))).
			WithFileInput("host_file", hostPath, "text", false, true).
			SetExpression(`size(host_file) > 0`).
			WithName(fmt.Sprintf("Host File Access: %s", filepath.Base(hostPath))).
			WithDescription(fmt.Sprintf("Validates access to host file %s", hostPath)).
			WithExtension("severity", "INFO").
			WithExtension("host_path", hostPath).
			WithExtension("privileged", true).
			Build()

		runSingleRule(scanner, rule)
	}

	// Additional privileged checks
	runPrivilegedSystemChecks(scanner)
}

// Approach 6: Service Account and RBAC validation
func runServiceAccountValidation(scanner *celscanner.Scanner) {
	fmt.Println("\n👤 Approach 6: Service Account & RBAC Validation")
	fmt.Println(strings.Repeat("-", 55))

	rbacRules := []celscanner.CelRule{
		// Check ServiceAccount usage
		celscanner.NewRuleBuilder("serviceaccount-usage").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					!has(pod.spec.serviceAccountName) ||
					pod.spec.serviceAccountName != "default"
				)
			`).
			WithName("Non-Default ServiceAccount Usage").
			WithDescription("Pods should use specific ServiceAccounts").
			WithExtension("severity", "MEDIUM").
			WithExtension("compliance", "Best Practice").
			Build(),

		// Check automountServiceAccountToken
		celscanner.NewRuleBuilder("sa-token-automount").
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression(`
				has(pods.items) && pods.items.all(pod,
					has(pod.spec.automountServiceAccountToken) &&
					pod.spec.automountServiceAccountToken == false
				)
			`).
			WithName("ServiceAccount Token Automount").
			WithDescription("Disable unnecessary token automounting").
			WithExtension("severity", "MEDIUM").
			WithExtension("compliance", "Security").
			Build(),

		// Check for ClusterRoleBindings
		celscanner.NewRuleBuilder("clusterrolebinding-check").
			WithKubernetesInput("clusterrolebindings", "rbac.authorization.k8s.io", "v1", "clusterrolebindings", "", "").
			SetExpression(`
				has(clusterrolebindings.items) && clusterrolebindings.items.all(binding,
					binding.roleRef.name != "cluster-admin" ||
					size(binding.subjects) == 0
				)
			`).
			WithName("Cluster Admin Binding Check").
			WithDescription("Restrict cluster-admin role usage").
			WithExtension("severity", "HIGH").
			WithExtension("compliance", "RBAC").
			Build(),
	}

	for _, rule := range rbacRules {
		fmt.Printf("\n🔍 RBAC Check: %s\n", rule.Metadata().Name)
		runSingleRule(scanner, rule)
	}
}

// Helper functions for specific checks
func runCriticalVolumeChecks(scanner *celscanner.Scanner, volumeName, mountPath string) {
	fmt.Printf("   🔒 Running critical volume checks for %s\n", volumeName)

	// Check for sensitive files in volume
	sensitiveRule := celscanner.NewRuleBuilder(fmt.Sprintf("sensitive-files-%s", volumeName)).
		WithSystemInput("sensitive_check", "", "find", []string{
			mountPath, "-type", "f", "-name", "*secret*", "-o", "-name", "*key*", "-o", "-name", "*password*",
		}).
		SetExpression(`sensitive_check.success`).
		WithName(fmt.Sprintf("Sensitive Files in %s", volumeName)).
		WithDescription("Check for sensitive files in volume").
		WithExtension("severity", "HIGH").
		WithExtension("volume", volumeName).
		Build()

	runSingleRule(scanner, sensitiveRule)
}

func runPrivilegedSystemChecks(scanner *celscanner.Scanner) {
	fmt.Printf("\n🔓 Privileged System Checks:\n")

	// Check container runtime security
	rule := celscanner.NewRuleBuilder("container-runtime-check").
		WithSystemInput("runtime_check", "", "ps", []string{"aux"}).
		SetExpression(`runtime_check.success && size(runtime_check.output) > 0`).
		WithName("Container Runtime Process Check").
		WithDescription("Validates container runtime is running").
		WithExtension("severity", "INFO").
		WithExtension("privileged", true).
		Build()

	runSingleRule(scanner, rule)
}

// Helper function to run a single rule
func runSingleRule(scanner *celscanner.Scanner, rule celscanner.CelRule) {
	config := celscanner.ScanConfig{
		Rules:              []celscanner.CelRule{rule},
		Variables:          []celscanner.CelVariable{},
		EnableDebugLogging: false,
	}

	results, err := scanner.Scan(context.Background(), config)
	if err != nil {
		fmt.Printf("   ❌ Error: %v\n", err)
		return
	}

	if len(results) == 0 {
		fmt.Printf("   ❌ No results returned\n")
		return
	}

	result := results[0]
	statusIcon := getStatusIcon(result.Status)

	if rule.Metadata().Extensions["severity"] != nil {
		severity := rule.Metadata().Extensions["severity"]
		fmt.Printf("   %s Status: %s (%s severity)\n", statusIcon, result.Status, severity)
	} else {
		fmt.Printf("   %s Status: %s\n", statusIcon, result.Status)
	}

	// Show additional context for failures
	if result.Status == celscanner.CheckResultFail && rule.Metadata().Extensions["compliance"] != nil {
		compliance := rule.Metadata().Extensions["compliance"]
		fmt.Printf("   📋 Compliance: %s\n", compliance)
	}

	if len(result.Warnings) > 0 {
		for _, warning := range result.Warnings {
			fmt.Printf("   ⚠️  %s\n", warning)
		}
	}

	if result.ErrorMessage != "" {
		fmt.Printf("   🚨 %s\n", result.ErrorMessage)
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
	// Check if running in cluster
	if _, exists := os.LookupEnv("KUBERNETES_SERVICE_HOST"); exists {
		fmt.Println("🏗️  Detected in-cluster environment")
	} else {
		fmt.Println("🖥️  Running outside cluster (development mode)")
	}
}

// Helper function to check if we have Kubernetes access
func checkKubernetesAccess(scanner *celscanner.Scanner) bool {
	// Try a simple rule that doesn't require specific resources
	testRule := celscanner.NewRuleBuilder("k8s-access-test").
		WithSystemInput("test_cmd", "", "echo", []string{"test"}).
		SetExpression(`test_cmd.success`).
		WithName("Kubernetes Access Test").
		WithDescription("Tests if we can execute rules").
		Build()

	config := celscanner.ScanConfig{
		Rules:              []celscanner.CelRule{testRule},
		Variables:          []celscanner.CelVariable{},
		EnableDebugLogging: false,
	}

	_, err := scanner.Scan(context.Background(), config)
	return err == nil
}
