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

package testing

import (
	"testing"

	"github.com/Vincent056/celscanner"
)

func TestUnitTestHelper_BasicRule(t *testing.T) {
	tester := NewRuleTester()

	// Create a simple rule that should pass
	rule, err := celscanner.NewRuleBuilder("test-basic").
		WithSystemInput("dummy", "echo", "", []string{"test"}).
		SetExpression("true").
		WithName("Basic Test Rule").
		WithDescription("A simple rule that always passes").
		Build()
	if err != nil {
		t.Fatalf("Failed to build rule: %v", err)
	}

	// Test that the rule passes
	result := tester.WithRule(rule).
		WithMockData("dummy", CreateMockSystemCommand(true, "test", 0)).
		WithTestContext(t).
		ShouldPass()

	if !result.Passed {
		t.Errorf("Expected rule to pass, but it failed: %s", result.Message)
	}
}

func TestUnitTestHelper_MockData(t *testing.T) {
	tester := NewRuleTester()

	// Create mock pod data
	pods := []map[string]interface{}{
		CreateMockPod("test-pod", "default", []map[string]interface{}{
			CreateMockContainer("nginx", "nginx:latest", false, map[string]string{
				"memory": "100Mi",
				"cpu":    "100m",
			}),
		}),
	}

	// Create a rule that checks for resource limits
	rule, err := celscanner.NewRuleBuilder("resource-limits").
		WithKubernetesInput("pods", "", "v1", "pods", "", "").
		SetExpression(`
			has(pods.items) &&
			pods.items.size() > 0 &&
			pods.items.all(pod,
				pod.spec.containers.all(container,
					has(container.resources) &&
					has(container.resources.limits)
				)
			)
		`).
		WithName("Resource Limits Check").
		Build()
	if err != nil {
		t.Fatalf("Failed to build rule: %v", err)
	}

	// Test with mock data
	result := tester.WithRule(rule).
		WithMockData("pods", CreateMockKubernetesPods(pods)).
		WithTestContext(t).
		ShouldPass()

	if !result.Passed {
		t.Errorf("Expected rule to pass with mock data, but it failed: %s", result.Message)
	}
}

func TestUnitTestHelper_ShouldFail(t *testing.T) {
	tester := NewRuleTester()

	// Create a rule that should fail
	rule, err := celscanner.NewRuleBuilder("test-fail").
		WithSystemInput("dummy", "echo", "", []string{"test"}).
		SetExpression("false").
		WithName("Failing Test Rule").
		WithDescription("A simple rule that always fails").
		Build()
	if err != nil {
		t.Fatalf("Failed to build rule: %v", err)
	}

	// Test that the rule fails
	result := tester.WithRule(rule).
		WithMockData("dummy", CreateMockSystemCommand(true, "test", 0)).
		WithTestContext(t).
		ShouldFail()

	if !result.Passed {
		t.Errorf("Expected test to pass (rule should fail), but test failed: %s", result.Message)
	}
}

func TestUnitTestHelper_HTTPMockData(t *testing.T) {
	tester := NewRuleTester()

	// Create mock HTTP response
	httpResponse := CreateMockHTTPResponse(200, map[string]interface{}{
		"status":  "healthy",
		"version": "1.0.0",
	}, map[string][]string{
		"Content-Type": {"application/json"},
	})

	// Create a rule that checks HTTP response
	rule, err := celscanner.NewRuleBuilder("http-health").
		WithHTTPInput("api", "https://api.example.com/health", "GET", map[string]string{}, nil).
		SetExpression(`
			api.success &&
			api.statusCode == 200 &&
			has(api.body) &&
			api.body.status == "healthy"
		`).
		WithName("HTTP Health Check").
		Build()
	if err != nil {
		t.Fatalf("Failed to build rule: %v", err)
	}

	// Test with mock HTTP data
	result := tester.WithRule(rule).
		WithMockData("api", httpResponse).
		WithTestContext(t).
		ShouldPass()

	if !result.Passed {
		t.Errorf("Expected HTTP rule to pass with mock data, but it failed: %s", result.Message)
	}
}

func TestUnitTestHelper_TestSuite(t *testing.T) {
	tester := NewRuleTester()

	// Create a simple test suite
	suite := NewSecurityTestSuite("Basic Security Tests")

	// Add some test cases
	passingRule, err := celscanner.NewRuleBuilder("always-pass").
		WithSystemInput("dummy", "echo", "", []string{"test"}).
		SetExpression("true").
		WithName("Always Pass").
		Build()
	if err != nil {
		t.Fatalf("Failed to build rule: %v", err)
	}

	failingRule, err := celscanner.NewRuleBuilder("always-fail").
		WithSystemInput("dummy", "echo", "", []string{"test"}).
		SetExpression("false").
		WithName("Always Fail").
		Build()

	suite.AddPodSecurityTest(passingRule, []map[string]interface{}{}, true)
	suite.AddFileSecurityTest(failingRule, "config", map[string]interface{}{}, false)

	// Run the test suite
	result := tester.RunTestSuite(suite.Build())

	if result.TotalTests != 2 {
		t.Errorf("Expected 2 tests, got %d", result.TotalTests)
	}

	if result.PassedTests != 2 {
		t.Errorf("Expected 2 passed tests, got %d", result.PassedTests)
	}

	if result.FailedTests != 0 {
		t.Errorf("Expected 0 failed tests, got %d", result.FailedTests)
	}
}

func TestUnitTestHelper_MockHelpers(t *testing.T) {
	// Test mock data creation helpers
	pod := CreateMockPod("test-pod", "default", []map[string]interface{}{
		CreateMockContainer("nginx", "nginx:latest", true, map[string]string{
			"memory": "100Mi",
		}),
	})

	if pod["metadata"].(map[string]interface{})["name"] != "test-pod" {
		t.Error("Mock pod name not set correctly")
	}

	fileContent := CreateMockFileContent("test content", "644", "root")
	if fileContent["content"] != "test content" {
		t.Error("Mock file content not set correctly")
	}

	systemCmd := CreateMockSystemCommand(true, "service active", 0)
	if !systemCmd["success"].(bool) {
		t.Error("Mock system command success not set correctly")
	}

	httpResp := CreateMockHTTPResponse(404, "Not Found", map[string][]string{
		"Content-Type": {"text/plain"},
	})
	if httpResp["statusCode"] != 404 {
		t.Error("Mock HTTP response status code not set correctly")
	}
	if httpResp["success"].(bool) {
		t.Error("Mock HTTP response should not be successful for 404")
	}
}
