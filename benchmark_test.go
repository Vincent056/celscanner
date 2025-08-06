/*
Copyright © 2024 Red Hat Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package celscanner

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func BenchmarkScanner_Scan(b *testing.B) {
	// Create test rules using the new unified API
	podSecurityContextRule, err := NewRuleBuilder("pod-security-context").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		SetExpression("pods.items.all(pod, has(pod.spec.securityContext))").
		WithName("Pod Security Context Check").
		WithDescription("Ensures all pods have security context").
		Build()
	if err != nil {
		b.Fatalf("Failed to build rule: %v", err)
	}
	podResourceLimitsRule, err := NewRuleBuilder("pod-resource-limits").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		SetExpression("pods.items.all(pod, pod.spec.containers.all(container, has(container.resources)))").
		WithName("Pod Resource Limits Check").
		WithDescription("Ensures all containers have resource limits").
		Build()
	if err != nil {
		b.Fatalf("Failed to build rule: %v", err)
	}
	serviceValidationRule, err := NewRuleBuilder("service-validation").
		WithKubernetesInput("services", "", "v1", "services", "", "").
		SetExpression("services.items.all(svc, has(svc.spec.selector))").
		WithName("Service Selector Check").
		WithDescription("Ensures all services have selectors").
		Build()
	if err != nil {
		b.Fatalf("Failed to build rule: %v", err)
	}
	rules := []CelRule{
		podSecurityContextRule,
		podResourceLimitsRule,
		serviceValidationRule,
	}

	// Create test variables using the new unified API
	variables := []CelVariable{
		&TestCelVariable{
			name:  "env",
			value: "production",
		},
		&TestCelVariable{
			name:  "namespace",
			value: "default",
		},
	}

	// Create scanner with mock fetcher
	scanner := NewScanner(nil, &BenchmarkLogger{})

	// Setup test data
	testDataDir := setupBenchmarkTestData(b)

	config := ScanConfig{
		Rules:           rules,
		Variables:       variables,
		ApiResourcePath: testDataDir,
	}

	// Run benchmark
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := scanner.Scan(ctx, config)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

func BenchmarkScanner_ScanSingleRule(b *testing.B) {
	// Create a single rule for focused benchmarking
	rule, err := NewRuleBuilder("pod-count").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		SetExpression("pods.items.size() > 0").
		WithName("Pod Count Check").
		WithDescription("Ensures pods exist").
		Build()
	if err != nil {
		b.Fatalf("Failed to build rule: %v", err)
	}
	scanner := NewScanner(nil, &BenchmarkLogger{})
	testDataDir := setupBenchmarkTestData(b)

	config := ScanConfig{
		Rules:           []CelRule{rule},
		Variables:       []CelVariable{},
		ApiResourcePath: testDataDir,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := scanner.Scan(ctx, config)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

func BenchmarkScanner_ScanComplexRule(b *testing.B) {
	// Create a complex rule for performance testing
	rule, err := NewRuleBuilder("complex-multi-resource").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		WithKubernetesInput("services", "", "v1", "services", "", "").
		WithKubernetesInput("configmaps", "", "v1", "configmaps", "", "").
		SetExpression(`
			pods.items.all(pod, 
				has(pod.spec.securityContext) &&
				has(pod.metadata.labels.app) &&
				services.items.exists(svc, 
					has(svc.spec.selector.app) &&
					pod.metadata.labels.app == svc.spec.selector.app
				) &&
				configmaps.items.exists(cm,
					cm.metadata.name == "app-config" &&
					has(cm.data)
				)
			)
		`).
		WithName("Complex Multi-Resource Check").
		WithDescription("Complex rule testing multiple resources").
		Build()
	if err != nil {
		b.Fatalf("Failed to build rule: %v", err)
	}
	scanner := NewScanner(nil, &BenchmarkLogger{})
	testDataDir := setupBenchmarkTestData(b)

	config := ScanConfig{
		Rules:           []CelRule{rule},
		Variables:       []CelVariable{},
		ApiResourcePath: testDataDir,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := scanner.Scan(ctx, config)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

func BenchmarkScanner_ScanManyRules(b *testing.B) {
	// Create many rules for scaling tests
	rules := []CelRule{}
	for i := 0; i < 50; i++ {
		rule, err := NewRuleBuilder(fmt.Sprintf("rule-%d", i)).
			WithKubernetesInput("pods", "", "v1", "pods", "", "").
			SetExpression("pods.items.size() > 0").
			WithName(fmt.Sprintf("Rule %d", i)).
			WithDescription(fmt.Sprintf("Test rule %d", i)).
			Build()
		if err != nil {
			b.Fatalf("Failed to build rule: %v", err)
		}
		rules = append(rules, rule)
	}

	scanner := NewScanner(nil, &BenchmarkLogger{})
	testDataDir := setupBenchmarkTestData(b)

	config := ScanConfig{
		Rules:           rules,
		Variables:       []CelVariable{},
		ApiResourcePath: testDataDir,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := context.Background()
		_, err := scanner.Scan(ctx, config)
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}

func setupBenchmarkTestData(b *testing.B) string {
	testDataDir := b.TempDir()

	// Create minimal test data for benchmarks
	podsData := `{
		"apiVersion": "v1",
		"kind": "List",
		"items": [
			{
				"apiVersion": "v1",
				"kind": "Pod",
				"metadata": {
					"name": "test-pod",
					"labels": {
						"app": "test-app"
					}
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
			}
		]
	}`

	servicesData := `{
		"apiVersion": "v1",
		"kind": "List",
		"items": [
			{
				"apiVersion": "v1",
				"kind": "Service",
				"metadata": {
					"name": "test-service"
				},
				"spec": {
					"selector": {
						"app": "test-app"
					},
					"ports": [
						{
							"port": 80,
							"targetPort": 8080
						}
					]
				}
			}
		]
	}`

	configmapsData := `{
		"apiVersion": "v1",
		"kind": "List",
		"items": [
			{
				"apiVersion": "v1",
				"kind": "ConfigMap",
				"metadata": {
					"name": "app-config"
				},
				"data": {
					"config.yaml": "key: value"
				}
			}
		]
	}`

	writeTestFile(b, testDataDir+"/pods.json", podsData)
	writeTestFile(b, testDataDir+"/services.json", servicesData)
	writeTestFile(b, testDataDir+"/configmaps.json", configmapsData)

	return testDataDir
}

func writeTestFile(b *testing.B, filename, content string) {
	err := os.WriteFile(filename, []byte(content), 0644)
	if err != nil {
		b.Fatalf("Failed to write test file %s: %v", filename, err)
	}
}

// BenchmarkLogger is a no-op logger for benchmarks
type BenchmarkLogger struct{}

func (l *BenchmarkLogger) Debug(msg string, args ...interface{}) {}
func (l *BenchmarkLogger) Info(msg string, args ...interface{})  {}
func (l *BenchmarkLogger) Warn(msg string, args ...interface{})  {}
func (l *BenchmarkLogger) Error(msg string, args ...interface{}) {}
