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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestScanner_Scan_WithSimplifiedAPI(t *testing.T) {
	tests := []struct {
		name           string
		rules          []CelRule
		variables      []CelVariable
		expectedCount  int
		expectedStatus []CheckResultStatus
		description    string
	}{
		{
			name: "basic pod existence check",
			rules: []CelRule{
				NewRuleBuilder("pod-existence-check").
					WithKubernetesInput("pods", "", "v1", "pods", "", "").
					SetExpression("size(pods.items) > 0").
					WithName("Pod Existence Check").
					WithDescription("Ensures pods exist in the cluster").
					Build(),
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when pods exist",
		},
		{
			name: "configmap data validation",
			rules: []CelRule{
				NewRuleBuilder("configmap-validation").
					WithKubernetesInput("configmaps", "", "v1", "configmaps", "", "").
					SetExpression(`configmaps.items.exists(cm, cm.metadata.name == "app-config")`).
					WithName("ConfigMap Check").
					WithDescription("Check if specific configmap exists").
					Build(),
			},
			expectedCount:  1,
			expectedStatus: []CheckResultStatus{CheckResultPass},
			description:    "Should pass when required configmap exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test scanner
			scanner := NewScanner(nil, &TestLogger{t: t})

			// Setup test data directory
			testDataDir := setupTestData(t)

			config := ScanConfig{
				Rules:           tt.rules,
				Variables:       tt.variables,
				ApiResourcePath: testDataDir,
			}

			// Execute scan
			ctx := context.Background()
			results, err := scanner.Scan(ctx, config)

			// Verify results
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(results) != tt.expectedCount {
				t.Fatalf("Expected %d results, got %d", tt.expectedCount, len(results))
			}

			for i, result := range results {
				if i < len(tt.expectedStatus) {
					if result.Status != tt.expectedStatus[i] {
						t.Errorf("Rule %s: expected status %s, got %s",
							result.ID, tt.expectedStatus[i], result.Status)
					}
				}
			}

			t.Logf("Test '%s' completed: %s", tt.name, tt.description)
		})
	}
}

func TestScanner_ErrorHandling(t *testing.T) {
	tests := []struct {
		name           string
		rule           CelRule
		expectError    bool
		expectedStatus CheckResultStatus
		description    string
	}{
		{
			name: "invalid CEL expression",
			rule: NewRuleBuilder("invalid-expression").
				WithKubernetesInput("pods", "", "v1", "pods", "", "").
				SetExpression("invalid.expression.syntax...").
				WithName("Invalid Expression Test").
				Build(),
			expectError:    false, // Should not fail the scan, but create an ERROR result
			expectedStatus: CheckResultError,
			description:    "Should create ERROR result for invalid CEL expression",
		},
		{
			name: "missing resource reference",
			rule: NewRuleBuilder("missing-resource").
				WithKubernetesInput("pods", "", "v1", "pods", "", "").
				SetExpression("nonexistent.items.size() > 0").
				WithName("Missing Resource Test").
				Build(),
			expectError:    false, // Should not fail the scan, but create an ERROR result
			expectedStatus: CheckResultError,
			description:    "Should create ERROR result for undeclared resource references",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner(nil, &TestLogger{t: t})
			testDataDir := setupTestData(t)

			config := ScanConfig{
				Rules:           []CelRule{tt.rule},
				ApiResourcePath: testDataDir,
			}

			ctx := context.Background()
			results, err := scanner.Scan(ctx, config)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// Check that we got a result (even for compilation errors)
			if len(results) != 1 {
				t.Fatalf("Expected 1 result, got %d", len(results))
			}

			result := results[0]
			if result.Status != tt.expectedStatus {
				t.Errorf("Expected status %s, got %s", tt.expectedStatus, result.Status)
			}

			// For error results, check that detailed information is provided
			if result.Status == CheckResultError {
				if len(result.Warnings) == 0 {
					t.Errorf("Expected error warnings but got none")
				}

				t.Logf("Error details: %v", result.Warnings)
			}

			t.Logf("Error handling test '%s' completed: %s", tt.name, tt.description)
		})
	}
}

func TestScanner_WithVariables(t *testing.T) {
	// Test with variables using the new API
	rule := NewRuleBuilder("configmap-with-variable").
		WithKubernetesInput("configmaps", "", "v1", "configmaps", "", "").
		SetExpression(`configmaps.items.exists(cm, cm.metadata.name == configName)`).
		WithName("ConfigMap Variable Test").
		WithDescription("Test rule with variables").
		Build()

	variables := []CelVariable{
		&TestCelVariable{
			name:  "configName",
			value: "app-config",
		},
	}

	scanner := NewScanner(nil, &TestLogger{t: t})
	testDataDir := setupTestData(t)

	config := ScanConfig{
		Rules:           []CelRule{rule},
		Variables:       variables,
		ApiResourcePath: testDataDir,
	}

	ctx := context.Background()
	results, err := scanner.Scan(ctx, config)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	t.Logf("Variable test completed - result status: %s", results[0].Status)
}

func TestSaveResults(t *testing.T) {
	results := []CheckResult{
		{
			ID:           "test-001",
			Status:       CheckResultPass,
			Metadata:     CheckResultMetadata{},
			Warnings:     []string{},
			ErrorMessage: "",
		},
	}

	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "test_results.json")

	err := SaveResults(filePath, results)
	if err != nil {
		t.Fatalf("SaveResults failed: %v", err)
	}

	// Verify file exists and has correct content
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read results file: %v", err)
	}

	var savedResults []CheckResult
	err = json.Unmarshal(data, &savedResults)
	if err != nil {
		t.Fatalf("Failed to unmarshal results: %v", err)
	}

	if len(savedResults) != 1 {
		t.Fatalf("Expected 1 saved result, got %d", len(savedResults))
	}

	if savedResults[0].ID != "test-001" {
		t.Errorf("Expected ID 'test-001', got '%s'", savedResults[0].ID)
	}
}

// setupTestData creates test data directory with mock resources
func setupTestData(t *testing.T) string {
	testDataDir := t.TempDir()

	// Copy test resource files to temp directory
	copyTestResource(t, "testdata/pods.json", filepath.Join(testDataDir, "pods.json"))
	copyTestResource(t, "testdata/configmaps.json", filepath.Join(testDataDir, "configmaps.json"))
	copyTestResource(t, "testdata/services.json", filepath.Join(testDataDir, "services.json"))

	return testDataDir
}

// copyTestResource copies a test resource file
func copyTestResource(t *testing.T, src, dst string) {
	srcData, err := os.ReadFile(src)
	if err != nil {
		// If source file doesn't exist, create minimal test data
		srcData = []byte(`{"apiVersion": "v1", "kind": "List", "items": []}`)
	}

	err = os.WriteFile(dst, srcData, 0644)
	if err != nil {
		t.Fatalf("Failed to write test resource %s: %v", dst, err)
	}
}

// Test implementations for the new unified API

type TestCelVariable struct {
	name      string
	namespace string
	value     string
	gvk       schema.GroupVersionKind
}

func (v *TestCelVariable) Name() string                              { return v.name }
func (v *TestCelVariable) Namespace() string                         { return v.namespace }
func (v *TestCelVariable) Value() string                             { return v.value }
func (v *TestCelVariable) GroupVersionKind() schema.GroupVersionKind { return v.gvk }

type TestLogger struct {
	t *testing.T
}

func (l *TestLogger) Debug(msg string, args ...interface{}) {
	l.t.Logf("[DEBUG] "+msg, args...)
}

func (l *TestLogger) Info(msg string, args ...interface{}) {
	l.t.Logf("[INFO] "+msg, args...)
}

func (l *TestLogger) Warn(msg string, args ...interface{}) {
	l.t.Logf("[WARN] "+msg, args...)
}

func (l *TestLogger) Error(msg string, args ...interface{}) {
	l.t.Logf("[ERROR] "+msg, args...)
}
