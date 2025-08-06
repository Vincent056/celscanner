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

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/Vincent056/celscanner/fetchers"
)

func main() {
	fmt.Println("🌐 CEL Go Scanner - HTTP API Security Scanning")
	fmt.Println(strings.Repeat("=", 60))

	// Create composite fetcher with HTTP support
	fetcher := fetchers.NewCompositeFetcherBuilder().
		WithHTTP(30*time.Second, true, 3). // 30s timeout, follow redirects, 3 retries
		Build()

	// Create scanner with logger
	logger := celscanner.DefaultLogger{}
	scanner := celscanner.NewScanner(fetcher, logger)

	fmt.Println("\n🔍 Scanning REST API endpoints for security compliance...")

	// Define API security rules
	rules := createAPISecurityRules()

	// Configure scan
	config := celscanner.ScanConfig{
		Rules:              rules,
		Variables:          []celscanner.CelVariable{},
		ApiResourcePath:    "",
		EnableDebugLogging: true,
	}

	// Execute scan
	ctx := context.Background()
	results, err := scanner.Scan(ctx, config)
	if err != nil {
		fmt.Printf("❌ Scan failed: %v\n", err)
		return
	}

	// Display results
	displayResults(results)
}

func createAPISecurityRules() []celscanner.CelRule {
	var rules []celscanner.CelRule

	// Check if health endpoint returns expected status
	healthRule, err := celscanner.NewRuleBuilder("api-health-check").
		WithHTTPInput("health", "https://httpbin.org/status/200", "GET", map[string]string{
			"User-Agent": "CEL-Scanner/1.0",
		}, nil).
		SetExpression(`
			health.success && health.statusCode == 200
		`).
		WithName("API Health Check").
		WithDescription("Ensures API health endpoint is accessible").
		WithExtension("severity", "HIGH").
		WithExtension("category", "availability").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build health check rule: %v", err))
	}
	rules = append(rules, healthRule)

	// Check API response time
	responseTimeRule, err := celscanner.NewRuleBuilder("api-response-time").
		WithHTTPInput("api", "https://httpbin.org/delay/1", "GET", map[string]string{
			"Accept": "application/json",
		}, nil).
		SetExpression(`
			api.success && api.responseTime < 3000
		`).
		WithName("API Response Time Check").
		WithDescription("API responses should be under 3 seconds").
		WithExtension("severity", "MEDIUM").
		WithExtension("category", "performance").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build response time rule: %v", err))
	}
	rules = append(rules, responseTimeRule)

	// Check for proper Content-Type headers
	contentTypeRule, err := celscanner.NewRuleBuilder("api-content-type").
		WithHTTPInput("json_api", "https://httpbin.org/json", "GET", map[string]string{
			"Accept": "application/json",
		}, nil).
		SetExpression(`
			json_api.success && 
			has(json_api.headers) &&
			"Content-Type" in json_api.headers &&
			size(json_api.headers["Content-Type"]) > 0 &&
			json_api.headers["Content-Type"][0].contains("application/json")
		`).
		WithName("Content-Type Header Check").
		WithDescription("API should return proper Content-Type headers").
		WithExtension("severity", "MEDIUM").
		WithExtension("category", "security").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build content type rule: %v", err))
	}
	rules = append(rules, contentTypeRule)

	// Check for security headers
	securityHeadersRule, err := celscanner.NewRuleBuilder("security-headers").
		WithHTTPInput("headers", "https://httpbin.org/response-headers?X-Frame-Options=DENY&X-Content-Type-Options=nosniff", "GET", map[string]string{}, nil).
		SetExpression(`
			headers.success &&
			has(headers.headers) &&
			(("X-Frame-Options" in headers.headers) || ("x-frame-options" in headers.headers)) &&
			(("X-Content-Type-Options" in headers.headers) || ("x-content-type-options" in headers.headers))
		`).
		WithName("Security Headers Check").
		WithDescription("API should include security headers").
		WithExtension("severity", "HIGH").
		WithExtension("category", "security").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build security headers rule: %v", err))
	}
	rules = append(rules, securityHeadersRule)

	// Check POST endpoint functionality
	postEndpointRule, err := celscanner.NewRuleBuilder("post-endpoint").
		WithHTTPInput("post", "https://httpbin.org/post", "POST", map[string]string{
			"Content-Type": "application/json",
		}, []byte(`{"test": "data", "scanner": "cel-go-scanner"}`)).
		SetExpression(`
			post.success &&
			post.statusCode == 200 &&
			has(post.body.json) &&
			post.body.json.test == "data"
		`).
		WithName("POST Endpoint Check").
		WithDescription("POST endpoints should handle JSON data correctly").
		WithExtension("severity", "HIGH").
		WithExtension("category", "functionality").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build POST endpoint rule: %v", err))
	}
	rules = append(rules, postEndpointRule)

	// Check for authentication requirement
	authRequiredRule, err := celscanner.NewRuleBuilder("auth-required").
		WithHTTPInput("basic_auth", "https://httpbin.org/basic-auth/user/pass", "GET", map[string]string{}, nil).
		SetExpression(`
			!basic_auth.success && basic_auth.statusCode == 401
		`).
		WithName("Authentication Required Check").
		WithDescription("Protected endpoints should require authentication").
		WithExtension("severity", "CRITICAL").
		WithExtension("category", "security").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build auth required rule: %v", err))
	}
	rules = append(rules, authRequiredRule)

	// Check for rate limiting headers
	rateLimitingRule, err := celscanner.NewRuleBuilder("rate-limiting").
		WithHTTPInput("rate_limit", "https://httpbin.org/response-headers?X-RateLimit-Limit=100&X-RateLimit-Remaining=99", "GET", map[string]string{}, nil).
		SetExpression(`
			rate_limit.success &&
			has(rate_limit.headers) &&
			(("X-RateLimit-Limit" in rate_limit.headers) || 
			 ("x-ratelimit-limit" in rate_limit.headers) ||
			 ("X-Rate-Limit" in rate_limit.headers))
		`).
		WithName("Rate Limiting Headers").
		WithDescription("API should implement rate limiting").
		WithExtension("severity", "MEDIUM").
		WithExtension("category", "security").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build rate limiting rule: %v", err))
	}
	rules = append(rules, rateLimitingRule)

	// Check CORS headers
	corsHeadersRule, err := celscanner.NewRuleBuilder("cors-headers").
		WithHTTPInput("cors", "https://httpbin.org/response-headers?Access-Control-Allow-Origin=*", "OPTIONS", map[string]string{
			"Origin": "https://example.com",
		}, nil).
		SetExpression(`
			cors.success &&
			has(cors.headers) &&
			"Access-Control-Allow-Origin" in cors.headers
		`).
		WithName("CORS Headers Check").
		WithDescription("API should have proper CORS configuration").
		WithExtension("severity", "MEDIUM").
		WithExtension("category", "security").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build CORS headers rule: %v", err))
	}
	rules = append(rules, corsHeadersRule)

	// Check for proper error handling
	errorHandlingRule, err := celscanner.NewRuleBuilder("error-handling").
		WithHTTPInput("error", "https://httpbin.org/status/500", "GET", map[string]string{}, nil).
		SetExpression(`
			!error.success && 
			error.statusCode == 500 &&
			error.responseTime < 5000
		`).
		WithName("Error Handling Check").
		WithDescription("API should handle errors gracefully").
		WithExtension("severity", "MEDIUM").
		WithExtension("category", "reliability").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build error handling rule: %v", err))
	}
	rules = append(rules, errorHandlingRule)

	// Check SSL/TLS security
	sslRedirectRule, err := celscanner.NewRuleBuilder("ssl-redirect").
		WithHTTPInput("ssl", "https://httpbin.org/get", "GET", map[string]string{}, nil).
		SetExpression(`
			ssl.success && 
			ssl.metadata.url.startsWith("https://")
		`).
		WithName("SSL/TLS Check").
		WithDescription("API should use HTTPS").
		WithExtension("severity", "CRITICAL").
		WithExtension("category", "security").
		Build()
	if err != nil {
		panic(fmt.Sprintf("Failed to build SSL redirect rule: %v", err))
	}
	rules = append(rules, sslRedirectRule)

	return rules
}

func displayResults(results []celscanner.CheckResult) {
	fmt.Printf("\n📊 Scan Results Summary\n")
	fmt.Println(strings.Repeat("-", 40))

	passed := 0
	failed := 0
	errors := 0

	for _, result := range results {
		switch result.Status {
		case celscanner.CheckResultPass:
			fmt.Printf("✅ PASS: %s\n", result.ID)
			passed++
		case celscanner.CheckResultFail:
			fmt.Printf("❌ FAIL: %s\n", result.ID)
			failed++
			if len(result.Warnings) > 0 {
				for _, warning := range result.Warnings {
					fmt.Printf("   ⚠️  %s\n", warning)
				}
			}
		case celscanner.CheckResultError:
			fmt.Printf("🔥 ERROR: %s - %s\n", result.ID, result.ErrorMessage)
			errors++
		case celscanner.CheckResultNotApplicable:
			fmt.Printf("🔸 N/A: %s\n", result.ID)
		}
	}

	fmt.Printf("\n📈 Summary:\n")
	fmt.Printf("   Total: %d\n", len(results))
	fmt.Printf("   Passed: %d\n", passed)
	fmt.Printf("   Failed: %d\n", failed)
	fmt.Printf("   Errors: %d\n", errors)

	successRate := float64(passed) / float64(len(results)) * 100
	fmt.Printf("   Success Rate: %.1f%%\n", successRate)

	if failed > 0 || errors > 0 {
		fmt.Printf("\n⚠️  Some security checks failed. Review the issues above.\n")
	} else {
		fmt.Printf("\n🎉 All HTTP API security checks passed!\n")
	}

	fmt.Printf("\nℹ️  HTTP scanning capabilities:\n")
	fmt.Printf("   • REST API endpoint validation\n")
	fmt.Printf("   • Security headers verification\n")
	fmt.Printf("   • Authentication and authorization checks\n")
	fmt.Printf("   • Performance and reliability testing\n")
	fmt.Printf("   • CORS and SSL/TLS configuration\n")
	fmt.Printf("   • Rate limiting and error handling\n")
}
