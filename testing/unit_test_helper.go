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
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Vincent056/celscanner"
)

// RuleTestCase represents a single test case for a rule
type RuleTestCase struct {
	Name               string                   `json:"name"`
	Description        string                   `json:"description"`
	Rule               celscanner.CelRule       `json:"rule"`
	MockData           map[string]interface{}   `json:"mockData"`
	ExpectedPass       bool                     `json:"expectedPass"`
	ExpectedViolations []string                 `json:"expectedViolations"`
	Variables          []celscanner.CelVariable `json:"variables,omitempty"`
}

// RuleTestSuite represents a collection of test cases
type RuleTestSuite struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	TestCases   []RuleTestCase `json:"testCases"`
	Setup       func() error   `json:"-"`
	Teardown    func() error   `json:"-"`
}

// TestResult represents the result of a single test
type TestResult struct {
	TestCase   string        `json:"testCase"`
	Rule       string        `json:"rule"`
	Passed     bool          `json:"passed"`
	Expected   bool          `json:"expected"`
	Actual     bool          `json:"actual"`
	Duration   time.Duration `json:"duration"`
	Error      string        `json:"error,omitempty"`
	Violations []string      `json:"violations,omitempty"`
	Message    string        `json:"message,omitempty"`
}

// SuiteResult represents the result of running a test suite
type SuiteResult struct {
	Suite       string        `json:"suite"`
	Duration    time.Duration `json:"duration"`
	TotalTests  int           `json:"totalTests"`
	PassedTests int           `json:"passedTests"`
	FailedTests int           `json:"failedTests"`
	Results     []TestResult  `json:"results"`
}

// MockFetcher implements ResourceFetcher for testing with predefined data
type MockFetcher struct {
	data map[string]interface{}
}

// NewMockFetcher creates a new mock fetcher with predefined data
func NewMockFetcher(data map[string]interface{}) *MockFetcher {
	return &MockFetcher{data: data}
}

// FetchResources implements ResourceFetcher interface for testing
func (m *MockFetcher) FetchResources(ctx context.Context, rule celscanner.CelRule, variables []celscanner.CelVariable) (map[string]interface{}, []string, error) {
	return m.data, nil, nil
}

// FetchInputs returns the predefined mock data
func (m *MockFetcher) FetchInputs(inputs []celscanner.Input, variables []celscanner.CelVariable) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	for _, input := range inputs {
		if data, exists := m.data[input.Name()]; exists {
			result[input.Name()] = data
		} else {
			return nil, fmt.Errorf("mock data not found for input: %s", input.Name())
		}
	}
	return result, nil
}

// SupportsInputType returns true for all input types in mock mode
func (m *MockFetcher) SupportsInputType(inputType celscanner.InputType) bool {
	return true
}

// RuleTester provides utilities for testing CEL rules
type RuleTester struct {
	scanner *celscanner.Scanner
	logger  TestLogger
}

// TestLogger captures test output for reporting
type TestLogger struct {
	logs []string
}

func (l *TestLogger) Debug(msg string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("DEBUG: "+msg, args...))
}

func (l *TestLogger) Info(msg string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("INFO: "+msg, args...))
}

func (l *TestLogger) Warn(msg string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("WARN: "+msg, args...))
}

func (l *TestLogger) Error(msg string, args ...interface{}) {
	l.logs = append(l.logs, fmt.Sprintf("ERROR: "+msg, args...))
}

func (l *TestLogger) GetLogs() []string {
	return l.logs
}

func (l *TestLogger) Clear() {
	l.logs = []string{}
}

// NewRuleTester creates a new rule tester
func NewRuleTester() *RuleTester {
	logger := TestLogger{}
	// Use a mock fetcher that will be overridden per test
	fetcher := NewMockFetcher(map[string]interface{}{})
	scanner := celscanner.NewScanner(fetcher, &logger)

	return &RuleTester{
		scanner: scanner,
		logger:  logger,
	}
}

// RunTestCase executes a single test case
func (rt *RuleTester) RunTestCase(testCase RuleTestCase) TestResult {
	start := time.Now()

	result := TestResult{
		TestCase: testCase.Name,
		Rule:     testCase.Rule.Identifier(),
		Expected: testCase.ExpectedPass,
		Duration: 0,
	}

	// Setup mock fetcher with test data
	mockFetcher := NewMockFetcher(testCase.MockData)
	rt.scanner = celscanner.NewScanner(mockFetcher, &rt.logger)

	// Clear previous logs
	rt.logger.Clear()

	// Execute the rule using the Scanner's Scan method
	config := celscanner.ScanConfig{
		Rules:     []celscanner.CelRule{testCase.Rule},
		Variables: testCase.Variables,
	}

	scanResults, err := rt.scanner.Scan(context.Background(), config)
	result.Duration = time.Since(start)

	if err != nil {
		result.Error = err.Error()
		result.Passed = false
		result.Message = fmt.Sprintf("Rule execution failed: %v", err)
		return result
	}

	// Analyze results (should have exactly one result)
	if len(scanResults) == 0 {
		result.Error = "No scan results returned"
		result.Passed = false
		result.Message = "Scanner returned empty results"
		return result
	}

	scanResult := scanResults[0]
	result.Actual = (scanResult.Status == celscanner.CheckResultPass)
	result.Passed = (result.Actual == result.Expected)

	// Collect violations (warnings are used as violations in CheckResult)
	result.Violations = append(result.Violations, scanResult.Warnings...)

	// Check expected violations if specified
	if len(testCase.ExpectedViolations) > 0 {
		if !rt.checkExpectedViolations(result.Violations, testCase.ExpectedViolations) {
			result.Passed = false
			result.Message = fmt.Sprintf("Expected violations %v, got %v",
				testCase.ExpectedViolations, result.Violations)
		}
	}

	if result.Passed {
		result.Message = "Test passed successfully"
	} else if result.Message == "" {
		result.Message = fmt.Sprintf("Expected %v, got %v", result.Expected, result.Actual)
	}

	return result
}

// RunTestSuite executes all test cases in a suite
func (rt *RuleTester) RunTestSuite(suite RuleTestSuite) SuiteResult {
	start := time.Now()

	result := SuiteResult{
		Suite:      suite.Name,
		TotalTests: len(suite.TestCases),
		Results:    make([]TestResult, 0, len(suite.TestCases)),
	}

	// Run setup if provided
	if suite.Setup != nil {
		if err := suite.Setup(); err != nil {
			result.Results = append(result.Results, TestResult{
				TestCase: "Setup",
				Error:    fmt.Sprintf("Suite setup failed: %v", err),
				Passed:   false,
			})
			result.FailedTests = result.TotalTests
			result.Duration = time.Since(start)
			return result
		}
	}

	// Run each test case
	for _, testCase := range suite.TestCases {
		testResult := rt.RunTestCase(testCase)
		result.Results = append(result.Results, testResult)

		if testResult.Passed {
			result.PassedTests++
		} else {
			result.FailedTests++
		}
	}

	// Run teardown if provided
	if suite.Teardown != nil {
		if err := suite.Teardown(); err != nil {
			// Don't fail the entire suite for teardown errors, but log them
			result.Results = append(result.Results, TestResult{
				TestCase: "Teardown",
				Error:    fmt.Sprintf("Suite teardown failed: %v", err),
				Passed:   false,
				Message:  "Teardown error (doesn't affect test results)",
			})
		}
	}

	result.Duration = time.Since(start)
	return result
}

// checkExpectedViolations verifies that actual violations match expected ones
func (rt *RuleTester) checkExpectedViolations(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}

	for _, expectedViolation := range expected {
		found := false
		for _, actualViolation := range actual {
			if strings.Contains(actualViolation, expectedViolation) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Assertion helpers for fluent testing

// AssertionBuilder provides fluent assertion interface
type AssertionBuilder struct {
	tester    *RuleTester
	rule      celscanner.CelRule
	mockData  map[string]interface{}
	variables []celscanner.CelVariable
	t         *testing.T
}

// WithRule starts a new assertion chain
func (rt *RuleTester) WithRule(rule celscanner.CelRule) *AssertionBuilder {
	return &AssertionBuilder{
		tester:   rt,
		rule:     rule,
		mockData: make(map[string]interface{}),
	}
}

// WithMockData adds mock data for inputs
func (ab *AssertionBuilder) WithMockData(inputName string, data interface{}) *AssertionBuilder {
	ab.mockData[inputName] = data
	return ab
}

// WithVariables adds variables for the test
func (ab *AssertionBuilder) WithVariables(variables []celscanner.CelVariable) *AssertionBuilder {
	ab.variables = variables
	return ab
}

// WithTestContext adds testing.T for automatic test reporting
func (ab *AssertionBuilder) WithTestContext(t *testing.T) *AssertionBuilder {
	ab.t = t
	return ab
}

// ShouldPass asserts that the rule should pass
func (ab *AssertionBuilder) ShouldPass() TestResult {
	return ab.runAndAssert(true)
}

// ShouldFail asserts that the rule should fail
func (ab *AssertionBuilder) ShouldFail() TestResult {
	return ab.runAndAssert(false)
}

// ShouldFailWith asserts that the rule should fail with specific violations
func (ab *AssertionBuilder) ShouldFailWith(expectedViolations ...string) TestResult {
	testCase := RuleTestCase{
		Name:               fmt.Sprintf("Rule %s should fail with violations", ab.rule.Identifier()),
		Rule:               ab.rule,
		MockData:           ab.mockData,
		ExpectedPass:       false,
		ExpectedViolations: expectedViolations,
		Variables:          ab.variables,
	}

	result := ab.tester.RunTestCase(testCase)

	if ab.t != nil {
		if !result.Passed {
			ab.t.Errorf("Test failed: %s", result.Message)
		}
	}

	return result
}

// runAndAssert executes the test and checks the result
func (ab *AssertionBuilder) runAndAssert(shouldPass bool) TestResult {
	testCase := RuleTestCase{
		Name:         fmt.Sprintf("Rule %s should pass: %v", ab.rule.Identifier(), shouldPass),
		Rule:         ab.rule,
		MockData:     ab.mockData,
		ExpectedPass: shouldPass,
		Variables:    ab.variables,
	}

	result := ab.tester.RunTestCase(testCase)

	if ab.t != nil {
		if !result.Passed {
			ab.t.Errorf("Test failed: %s", result.Message)
		}
	}

	return result
}

// Utility functions for creating common mock data

// CreateMockKubernetesPods creates mock Kubernetes pod data
func CreateMockKubernetesPods(pods []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "List",
		"items":      pods,
	}
}

// CreateMockPod creates a mock Kubernetes pod
func CreateMockPod(name, namespace string, containers []map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"containers": containers,
		},
	}
}

// CreateMockContainer creates a mock container specification
func CreateMockContainer(name, image string, privileged bool, limits map[string]string) map[string]interface{} {
	container := map[string]interface{}{
		"name":  name,
		"image": image,
	}

	if privileged || limits != nil {
		securityContext := make(map[string]interface{})
		if privileged {
			securityContext["privileged"] = privileged
		}
		container["securityContext"] = securityContext
	}

	if limits != nil {
		container["resources"] = map[string]interface{}{
			"limits": limits,
		}
	}

	return container
}

// CreateMockFileContent creates mock file content
func CreateMockFileContent(content string, permissions string, owner string) map[string]interface{} {
	return map[string]interface{}{
		"content":     content,
		"permissions": permissions,
		"owner":       owner,
		"exists":      true,
	}
}

// CreateMockSystemCommand creates mock system command result
func CreateMockSystemCommand(success bool, output string, exitCode int) map[string]interface{} {
	return map[string]interface{}{
		"success":  success,
		"output":   output,
		"exitCode": exitCode,
	}
}

// CreateMockHTTPResponse creates mock HTTP response
func CreateMockHTTPResponse(statusCode int, body interface{}, headers map[string][]string) map[string]interface{} {
	return map[string]interface{}{
		"statusCode": statusCode,
		"success":    statusCode >= 200 && statusCode < 300,
		"body":       body,
		"headers":    headers,
	}
}

// Test suite builders for common scenarios

// SecurityTestSuiteBuilder helps build security-focused test suites
type SecurityTestSuiteBuilder struct {
	suite RuleTestSuite
}

// NewSecurityTestSuite creates a new security test suite builder
func NewSecurityTestSuite(name string) *SecurityTestSuiteBuilder {
	return &SecurityTestSuiteBuilder{
		suite: RuleTestSuite{
			Name:        name,
			Description: "Security compliance test suite",
			TestCases:   []RuleTestCase{},
		},
	}
}

// AddPodSecurityTest adds a pod security test case
func (builder *SecurityTestSuiteBuilder) AddPodSecurityTest(rule celscanner.CelRule, pods []map[string]interface{}, shouldPass bool) *SecurityTestSuiteBuilder {
	testCase := RuleTestCase{
		Name:         fmt.Sprintf("Pod security test for %s", rule.Identifier()),
		Description:  "Test pod security compliance",
		Rule:         rule,
		MockData:     map[string]interface{}{"pods": CreateMockKubernetesPods(pods)},
		ExpectedPass: shouldPass,
	}

	builder.suite.TestCases = append(builder.suite.TestCases, testCase)
	return builder
}

// AddFileSecurityTest adds a file security test case
func (builder *SecurityTestSuiteBuilder) AddFileSecurityTest(rule celscanner.CelRule, fileName string, fileData map[string]interface{}, shouldPass bool) *SecurityTestSuiteBuilder {
	testCase := RuleTestCase{
		Name:         fmt.Sprintf("File security test for %s", rule.Identifier()),
		Description:  "Test file security compliance",
		Rule:         rule,
		MockData:     map[string]interface{}{fileName: fileData},
		ExpectedPass: shouldPass,
	}

	builder.suite.TestCases = append(builder.suite.TestCases, testCase)
	return builder
}

// Build returns the completed test suite
func (builder *SecurityTestSuiteBuilder) Build() RuleTestSuite {
	return builder.suite
}

// Report generation utilities

// GenerateReport creates a formatted test report
func GenerateReport(results []SuiteResult) string {
	var report strings.Builder

	report.WriteString("# CEL Scanner Test Report\n\n")
	report.WriteString(fmt.Sprintf("Generated: %s\n\n", time.Now().Format(time.RFC3339)))

	totalTests := 0
	totalPassed := 0
	totalFailed := 0

	for _, suite := range results {
		totalTests += suite.TotalTests
		totalPassed += suite.PassedTests
		totalFailed += suite.FailedTests

		report.WriteString(fmt.Sprintf("## Suite: %s\n", suite.Suite))
		report.WriteString(fmt.Sprintf("Duration: %s\n", suite.Duration))
		report.WriteString(fmt.Sprintf("Tests: %d passed, %d failed, %d total\n\n",
			suite.PassedTests, suite.FailedTests, suite.TotalTests))

		for _, test := range suite.Results {
			status := "✅ PASS"
			if !test.Passed {
				status = "❌ FAIL"
			}

			report.WriteString(fmt.Sprintf("- %s **%s** (%s) - %s\n",
				status, test.TestCase, test.Duration, test.Message))

			if test.Error != "" {
				report.WriteString(fmt.Sprintf("  Error: %s\n", test.Error))
			}

			if len(test.Violations) > 0 {
				report.WriteString("  Violations:\n")
				for _, violation := range test.Violations {
					report.WriteString(fmt.Sprintf("    - %s\n", violation))
				}
			}
		}
		report.WriteString("\n")
	}

	report.WriteString("## Summary\n")
	report.WriteString(fmt.Sprintf("Total Tests: %d\n", totalTests))
	report.WriteString(fmt.Sprintf("Passed: %d (%.1f%%)\n", totalPassed, float64(totalPassed)/float64(totalTests)*100))
	report.WriteString(fmt.Sprintf("Failed: %d (%.1f%%)\n", totalFailed, float64(totalFailed)/float64(totalTests)*100))

	return report.String()
}

// SaveReportToFile saves the test report to a file
func SaveReportToFile(results []SuiteResult, filename string) error {
	report := GenerateReport(results)
	return writeToFile(filename, report)
}

// ExportResultsAsJSON exports test results as JSON
func ExportResultsAsJSON(results []SuiteResult, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	return writeToFile(filename, string(data))
}

// Helper function to write content to file (placeholder - would need actual implementation)
func writeToFile(filename, content string) error {
	// This would be implemented to write to file system
	// For now, it's a placeholder
	fmt.Printf("Would write to file %s:\n%s\n", filename, content)
	return nil
}

// Advanced testing utilities

// CompareTestResults compares two test results for regression testing
func CompareTestResults(baseline, current SuiteResult) TestComparison {
	return TestComparison{
		Baseline:        baseline,
		Current:         current,
		NewFailures:     findNewFailures(baseline, current),
		FixedFailures:   findFixedFailures(baseline, current),
		RegressionTests: findRegressions(baseline, current),
	}
}

// TestComparison represents a comparison between two test runs
type TestComparison struct {
	Baseline        SuiteResult  `json:"baseline"`
	Current         SuiteResult  `json:"current"`
	NewFailures     []TestResult `json:"newFailures"`
	FixedFailures   []TestResult `json:"fixedFailures"`
	RegressionTests []TestResult `json:"regressionTests"`
}

func findNewFailures(baseline, current SuiteResult) []TestResult {
	baselineMap := make(map[string]TestResult)
	for _, test := range baseline.Results {
		baselineMap[test.TestCase] = test
	}

	var newFailures []TestResult
	for _, test := range current.Results {
		if baselineTest, exists := baselineMap[test.TestCase]; exists {
			if baselineTest.Passed && !test.Passed {
				newFailures = append(newFailures, test)
			}
		} else if !test.Passed {
			newFailures = append(newFailures, test)
		}
	}

	return newFailures
}

func findFixedFailures(baseline, current SuiteResult) []TestResult {
	baselineMap := make(map[string]TestResult)
	for _, test := range baseline.Results {
		baselineMap[test.TestCase] = test
	}

	var fixedFailures []TestResult
	for _, test := range current.Results {
		if baselineTest, exists := baselineMap[test.TestCase]; exists {
			if !baselineTest.Passed && test.Passed {
				fixedFailures = append(fixedFailures, test)
			}
		}
	}

	return fixedFailures
}

func findRegressions(baseline, current SuiteResult) []TestResult {
	// This would implement regression detection logic
	// For now, return empty slice
	return []TestResult{}
}
