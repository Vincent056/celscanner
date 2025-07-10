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

package fetchers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Vincent056/celscanner"
)

func TestHTTPFetcher_FetchInputs(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/health":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "healthy",
				"version": "1.0.0",
				"checks": map[string]bool{
					"database": true,
					"cache":    true,
				},
			})
		case "/api/users":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"id": 1, "name": "John", "role": "admin"},
				{"id": 2, "name": "Jane", "role": "user"},
			})
		case "/api/slow":
			time.Sleep(100 * time.Millisecond)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("slow response"))
		case "/api/error":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Internal Server Error"))
		case "/api/text":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("Hello, World!"))
		case "/api/redirect":
			http.Redirect(w, r, "/api/health", http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	fetcher := NewHTTPFetcher(5*time.Second, true, 2)

	tests := []struct {
		name     string
		inputs   []celscanner.Input
		wantData map[string]interface{}
		wantErr  bool
	}{
		{
			name: "successful JSON GET request",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("health", server.URL+"/api/health", "GET", map[string]string{
					"Accept": "application/json",
				}, nil),
			},
			wantData: map[string]interface{}{
				"health": map[string]interface{}{
					"statusCode": 200,
					"success":    true,
					"body": map[string]interface{}{
						"status":  "healthy",
						"version": "1.0.0",
						"checks": map[string]interface{}{
							"database": true,
							"cache":    true,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "request with authorization",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("users", server.URL+"/api/users", "GET", map[string]string{
					"Authorization": "Bearer test-token",
					"Accept":        "application/json",
				}, nil),
			},
			wantData: map[string]interface{}{
				"users": map[string]interface{}{
					"statusCode": 200,
					"success":    true,
					"body": []interface{}{
						map[string]interface{}{"id": float64(1), "name": "John", "role": "admin"},
						map[string]interface{}{"id": float64(2), "name": "Jane", "role": "user"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unauthorized request",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("users_unauth", server.URL+"/api/users", "GET", map[string]string{
					"Accept": "application/json",
				}, nil),
			},
			wantData: map[string]interface{}{
				"users_unauth": map[string]interface{}{
					"statusCode": 401,
					"success":    false,
				},
			},
			wantErr: false,
		},
		{
			name: "text response",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("text", server.URL+"/api/text", "GET", map[string]string{}, nil),
			},
			wantData: map[string]interface{}{
				"text": map[string]interface{}{
					"statusCode": 200,
					"success":    true,
					"body":       "Hello, World!",
					"rawBody":    "Hello, World!",
				},
			},
			wantErr: false,
		},
		{
			name: "server error",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("error", server.URL+"/api/error", "GET", map[string]string{}, nil),
			},
			wantData: map[string]interface{}{
				"error": map[string]interface{}{
					"statusCode": 500,
					"success":    false,
					"rawBody":    "Internal Server Error",
				},
			},
			wantErr: false,
		},
		{
			name: "not found",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("notfound", server.URL+"/api/notfound", "GET", map[string]string{}, nil),
			},
			wantData: map[string]interface{}{
				"notfound": map[string]interface{}{
					"statusCode": 404,
					"success":    false,
				},
			},
			wantErr: false,
		},
		{
			name: "multiple inputs",
			inputs: []celscanner.Input{
				celscanner.NewHTTPInput("health", server.URL+"/api/health", "GET", map[string]string{}, nil),
				celscanner.NewHTTPInput("text", server.URL+"/api/text", "GET", map[string]string{}, nil),
			},
			wantData: map[string]interface{}{
				"health": map[string]interface{}{
					"statusCode": 200,
					"success":    true,
				},
				"text": map[string]interface{}{
					"statusCode": 200,
					"success":    true,
					"body":       "Hello, World!",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := fetcher.FetchInputs(tt.inputs, nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("HTTPFetcher.FetchInputs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && data != nil {
				// Check that all expected keys exist and have correct status codes
				for key, expected := range tt.wantData {
					actual, exists := data[key]
					if !exists {
						t.Errorf("Expected key %s not found in result", key)
						continue
					}

					actualMap, ok := actual.(map[string]interface{})
					if !ok {
						t.Errorf("Expected map for key %s, got %T", key, actual)
						continue
					}

					expectedMap := expected.(map[string]interface{})

					// Check status code
					if statusCode, exists := expectedMap["statusCode"]; exists {
						if actualMap["statusCode"] != statusCode {
							t.Errorf("For key %s, expected statusCode %v, got %v", key, statusCode, actualMap["statusCode"])
						}
					}

					// Check success
					if success, exists := expectedMap["success"]; exists {
						if actualMap["success"] != success {
							t.Errorf("For key %s, expected success %v, got %v", key, success, actualMap["success"])
						}
					}

					// Check body if expected
					if expectedBody, exists := expectedMap["body"]; exists {
						if actualMap["body"] == nil {
							t.Errorf("For key %s, expected body %v, got nil", key, expectedBody)
						}
					}
				}
			}
		})
	}
}

func TestHTTPFetcher_SupportsInputType(t *testing.T) {
	fetcher := NewHTTPFetcher(30*time.Second, true, 3)

	tests := []struct {
		inputType celscanner.InputType
		want      bool
	}{
		{celscanner.InputTypeHTTP, true},
		{celscanner.InputTypeKubernetes, false},
		{celscanner.InputTypeFile, false},
		{celscanner.InputTypeSystem, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.inputType), func(t *testing.T) {
			if got := fetcher.SupportsInputType(tt.inputType); got != tt.want {
				t.Errorf("HTTPFetcher.SupportsInputType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHTTPFetcher_Timeout(t *testing.T) {
	// Create slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond) // Longer than our timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create fetcher with short timeout
	fetcher := NewHTTPFetcher(100*time.Millisecond, true, 1)

	inputs := []celscanner.Input{
		celscanner.NewHTTPInput("slow", server.URL, "GET", map[string]string{}, nil),
	}

	data, err := fetcher.FetchInputs(inputs, nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
		return
	}

	result, exists := data["slow"]
	if !exists {
		t.Error("Expected slow result")
		return
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Errorf("Expected map, got %T", result)
		return
	}

	if resultMap["success"].(bool) {
		t.Error("Expected request to fail due to timeout")
	}

	if resultMap["error"].(string) == "" {
		t.Error("Expected error message for timeout")
	}
}

func TestHTTPFetcher_Redirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("redirected"))
		}
	}))
	defer server.Close()

	tests := []struct {
		name            string
		followRedirects bool
		expectedStatus  int
	}{
		{
			name:            "follow redirects",
			followRedirects: true,
			expectedStatus:  200,
		},
		{
			name:            "don't follow redirects",
			followRedirects: false,
			expectedStatus:  302,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetcher := NewHTTPFetcher(30*time.Second, tt.followRedirects, 3)

			inputs := []celscanner.Input{
				celscanner.NewHTTPInput("redirect", server.URL+"/redirect", "GET", map[string]string{}, nil),
			}

			data, err := fetcher.FetchInputs(inputs, nil)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			result := data["redirect"].(map[string]interface{})
			if result["statusCode"] != tt.expectedStatus {
				t.Errorf("Expected status %d, got %v", tt.expectedStatus, result["statusCode"])
			}
		})
	}
}

func TestHTTPFetcher_POST(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"received": payload,
			"message":  "success",
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	fetcher := NewHTTPFetcher(30*time.Second, true, 3)

	payload := map[string]interface{}{
		"name": "test",
		"data": []string{"item1", "item2"},
	}
	body, _ := json.Marshal(payload)

	inputs := []celscanner.Input{
		celscanner.NewHTTPInput("post", server.URL, "POST", map[string]string{
			"Content-Type": "application/json",
		}, body),
	}

	data, err := fetcher.FetchInputs(inputs, nil)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	result := data["post"].(map[string]interface{})
	if result["statusCode"] != 200 {
		t.Errorf("Expected status 200, got %v", result["statusCode"])
	}

	if !result["success"].(bool) {
		t.Error("Expected successful response")
	}

	body_resp := result["body"].(map[string]interface{})
	if body_resp["message"] != "success" {
		t.Errorf("Expected success message, got %v", body_resp["message"])
	}
}

func TestHTTPResult_Conversion(t *testing.T) {
	fetcher := NewHTTPFetcher(30*time.Second, true, 3)

	result := &HTTPResult{
		StatusCode:   200,
		Headers:      map[string][]string{"Content-Type": {"application/json"}},
		Body:         map[string]interface{}{"key": "value"},
		RawBody:      `{"key":"value"}`,
		ResponseTime: 100,
		Success:      true,
		Error:        "",
		Metadata:     map[string]interface{}{"url": "test"},
	}

	converted := fetcher.httpResultToMap(result)

	if converted["statusCode"] != 200 {
		t.Errorf("Expected statusCode 200, got %v", converted["statusCode"])
	}

	if !converted["success"].(bool) {
		t.Error("Expected success true")
	}

	if converted["responseTime"] != int64(100) {
		t.Errorf("Expected responseTime 100, got %v", converted["responseTime"])
	}

	headers := converted["headers"].(map[string][]string)
	if headers["Content-Type"][0] != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %v", headers["Content-Type"][0])
	}
}

func TestValidateHTTPInputSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    celscanner.HTTPInputSpec
		wantErr bool
	}{
		{
			name: "valid GET request",
			spec: &celscanner.HTTPInput{
				Endpoint:   "https://api.example.com/health",
				HTTPMethod: "GET",
			},
			wantErr: false,
		},
		{
			name: "valid POST request",
			spec: &celscanner.HTTPInput{
				Endpoint:   "https://api.example.com/data",
				HTTPMethod: "POST",
				HTTPHeaders: map[string]string{
					"Content-Type": "application/json",
				},
				HTTPBody: []byte(`{"test": true}`),
			},
			wantErr: false,
		},
		{
			name: "empty URL",
			spec: &celscanner.HTTPInput{
				HTTPMethod: "GET",
			},
			wantErr: true,
		},
		{
			name: "invalid method",
			spec: &celscanner.HTTPInput{
				Endpoint:   "https://api.example.com/health",
				HTTPMethod: "INVALID",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHTTPInputSpec(tt.spec)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHTTPInputSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestHTTPHelperFunctions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"method": "GET"})
		case "POST":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"method": "POST"})
		}
	}))
	defer server.Close()

	t.Run("Get helper", func(t *testing.T) {
		result, err := Get(server.URL, map[string]string{"Accept": "application/json"})
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			return
		}

		if result.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", result.StatusCode)
		}

		if !result.Success {
			t.Error("Expected successful response")
		}

		body := result.Body.(map[string]interface{})
		if body["method"] != "GET" {
			t.Errorf("Expected method GET, got %v", body["method"])
		}
	})

	t.Run("Post helper", func(t *testing.T) {
		payload := []byte(`{"test": true}`)
		result, err := Post(server.URL, payload, map[string]string{"Content-Type": "application/json"})
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
			return
		}

		if result.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", result.StatusCode)
		}

		if !result.Success {
			t.Error("Expected successful response")
		}

		body := result.Body.(map[string]interface{})
		if body["method"] != "POST" {
			t.Errorf("Expected method POST, got %v", body["method"])
		}
	})
}

// Benchmark tests
func BenchmarkHTTPFetcher_FetchInputs(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	fetcher := NewHTTPFetcher(30*time.Second, true, 3)
	inputs := []celscanner.Input{
		celscanner.NewHTTPInput("test", server.URL, "GET", map[string]string{}, nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fetcher.FetchInputs(inputs, nil)
		if err != nil {
			b.Errorf("Unexpected error: %v", err)
		}
	}
}

func BenchmarkHTTPFetcher_ConcurrentRequests(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	fetcher := NewHTTPFetcher(30*time.Second, true, 3)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		inputs := []celscanner.Input{
			celscanner.NewHTTPInput("test", server.URL, "GET", map[string]string{}, nil),
		}
		for pb.Next() {
			_, err := fetcher.FetchInputs(inputs, nil)
			if err != nil {
				b.Errorf("Unexpected error: %v", err)
			}
		}
	})
}
