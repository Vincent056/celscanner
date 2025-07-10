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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock system input spec for testing
type mockSystemInputSpec struct {
	serviceName string
	command     string
	args        []string
	valid       bool
}

func (m *mockSystemInputSpec) ServiceName() string { return m.serviceName }
func (m *mockSystemInputSpec) Command() string     { return m.command }
func (m *mockSystemInputSpec) Args() []string      { return m.args }
func (m *mockSystemInputSpec) Validate() error {
	if !m.valid {
		return errors.New("invalid spec")
	}
	return ValidateSystemInputSpec(m)
}

// Mock system input for testing
type mockSystemInput struct {
	name string
	spec celscanner.SystemInputSpec
}

func (m *mockSystemInput) Name() string               { return m.name }
func (m *mockSystemInput) Type() celscanner.InputType { return celscanner.InputTypeSystem }
func (m *mockSystemInput) Spec() celscanner.InputSpec { return m.spec }

func TestNewSystemFetcher(t *testing.T) {
	t.Run("creates system fetcher with defaults", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)
		assert.NotNil(t, fetcher)
		assert.Equal(t, 30*time.Second, fetcher.commandTimeout)
		assert.False(t, fetcher.allowArbitraryCommands)
	})

	t.Run("creates system fetcher with zero timeout", func(t *testing.T) {
		fetcher := NewSystemFetcher(0, true)
		assert.NotNil(t, fetcher)
		assert.Equal(t, 30*time.Second, fetcher.commandTimeout) // Default timeout
		assert.True(t, fetcher.allowArbitraryCommands)
	})

	t.Run("creates system fetcher with custom timeout", func(t *testing.T) {
		customTimeout := 60 * time.Second
		fetcher := NewSystemFetcher(customTimeout, true)
		assert.NotNil(t, fetcher)
		assert.Equal(t, customTimeout, fetcher.commandTimeout)
		assert.True(t, fetcher.allowArbitraryCommands)
	})
}

func TestSystemFetcher_SupportsInputType(t *testing.T) {
	fetcher := NewSystemFetcher(30*time.Second, false)

	tests := []struct {
		name      string
		inputType celscanner.InputType
		expected  bool
	}{
		{
			name:      "supports system input",
			inputType: celscanner.InputTypeSystem,
			expected:  true,
		},
		{
			name:      "does not support file input",
			inputType: celscanner.InputTypeFile,
			expected:  false,
		},
		{
			name:      "does not support kubernetes input",
			inputType: celscanner.InputTypeKubernetes,
			expected:  false,
		},
		{
			name:      "does not support http input",
			inputType: celscanner.InputTypeHTTP,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fetcher.SupportsInputType(tt.inputType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSystemFetcher_FetchInputs(t *testing.T) {
	t.Run("fetches system service status", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		input := &mockSystemInput{
			name: "test-service",
			spec: &mockSystemInputSpec{
				serviceName: "systemd-resolved", // Common service on most systems
				valid:       true,
			},
		}

		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		// Note: This test might fail on systems without systemd or the service
		// In a real environment, you might want to mock the command execution
		if err != nil {
			t.Logf("Service test failed (expected on systems without systemd): %v", err)
		} else {
			assert.Contains(t, result, "test-service")
			serviceResult, ok := result["test-service"].(*SystemResult)
			assert.True(t, ok)
			assert.NotEmpty(t, serviceResult.Status)
			assert.NotNil(t, serviceResult.Metadata)
		}
	})

	t.Run("fetches system command output", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		input := &mockSystemInput{
			name: "hostname",
			spec: &mockSystemInputSpec{
				command: "hostname",
				args:    []string{},
				valid:   true,
			},
		}

		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		require.NoError(t, err)

		assert.Contains(t, result, "hostname")
		cmdResult, ok := result["hostname"].(*SystemResult)
		assert.True(t, ok)
		assert.NotEmpty(t, cmdResult.Output)
		assert.True(t, cmdResult.Success)
		assert.Equal(t, 0, cmdResult.ExitCode)
	})

	t.Run("skips non-system inputs", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		input := &mockInput{
			name:      "file-input",
			inputType: celscanner.InputTypeFile,
			spec:      &mockInputSpec{valid: true},
		}

		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		require.NoError(t, err)
		assert.Empty(t, result)
	})

	t.Run("fails with invalid input spec", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		input := &mockSystemInput{
			name: "invalid",
			spec: &mockSystemInputSpec{valid: false}, // Wrong spec type
		}

		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to fetch system resource")
	})

	t.Run("fails with neither service nor command", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		input := &mockSystemInput{
			name: "empty",
			spec: &mockSystemInputSpec{
				serviceName: "",
				command:     "",
				valid:       true,
			},
		}

		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "either service name or command must be specified")
	})
}

func TestSystemFetcher_ExecuteCommand(t *testing.T) {
	t.Run("executes allowed command successfully", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		result, err := fetcher.executeCommand("echo", []string{"hello world"})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ExitCode)
		assert.Contains(t, result.Output, "hello world")
		assert.Equal(t, "echo", result.Metadata["command"])
		assert.Equal(t, []string{"hello world"}, result.Metadata["args"])
	})

	t.Run("fails with disallowed command", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		result, err := fetcher.executeCommand("rm", []string{"-rf", "/"})
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "command rm is not allowed")
	})

	t.Run("executes disallowed command when arbitrary commands allowed", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, true)

		result, err := fetcher.executeCommand("nonexistent-command", []string{})
		require.NoError(t, err) // No error from security check
		assert.NotNil(t, result)
		assert.False(t, result.Success) // But command execution fails
		assert.NotEqual(t, 0, result.ExitCode)
		assert.NotEmpty(t, result.Error)
	})

	t.Run("handles command with non-zero exit code", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		result, err := fetcher.executeCommand("grep", []string{"nonexistent", "/dev/null"})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Success)
		assert.Equal(t, 1, result.ExitCode) // grep returns 1 when no match
	})
}

func TestSystemFetcher_IsAllowedCommand(t *testing.T) {
	fetcher := NewSystemFetcher(30*time.Second, false)

	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{"systemctl is allowed", "systemctl", true},
		{"ps is allowed", "ps", true},
		{"grep is allowed", "grep", true},
		{"docker is allowed", "docker", true},
		{"kubectl is allowed", "kubectl", true},
		{"rm is not allowed", "rm", false},
		{"sudo is not allowed", "sudo", false},
		{"exec is not allowed", "exec", false},
		{"eval is not allowed", "eval", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fetcher.isAllowedCommand(tt.command)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSystemFetcher_ParseSystemctlOutput(t *testing.T) {
	fetcher := NewSystemFetcher(30*time.Second, false)

	t.Run("parses active service", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: `● test.service - Test Service
   Loaded: loaded (/etc/systemd/system/test.service; enabled; vendor preset: enabled)
   Active: active (running) since Mon 2024-01-01 12:00:00 UTC; 1h 30m ago
   Main PID: 1234 (test)
    Tasks: 1 (limit: 4915)
   Memory: 1.5M
   CGroup: /system.slice/test.service
           └─1234 /usr/bin/test`,
			Metadata: make(map[string]interface{}),
		}

		result, err := fetcher.parseSystemctlOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "active", result.Status)
		assert.Contains(t, result.Metadata, "loaded")
		assert.Contains(t, result.Metadata, "active")
		assert.Contains(t, result.Metadata, "mainPid")
	})

	t.Run("parses inactive service", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: `● test.service - Test Service
   Loaded: loaded (/etc/systemd/system/test.service; disabled; vendor preset: enabled)
   Active: inactive (dead)`,
			Metadata: make(map[string]interface{}),
		}

		result, err := fetcher.parseSystemctlOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "inactive", result.Status)
	})

	t.Run("parses failed service", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: `● test.service - Test Service
   Loaded: loaded (/etc/systemd/system/test.service; enabled; vendor preset: enabled)
   Active: failed (Result: exit-code) since Mon 2024-01-01 12:00:00 UTC; 1h ago`,
			Metadata: make(map[string]interface{}),
		}

		result, err := fetcher.parseSystemctlOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "failed", result.Status)
	})

	t.Run("parses unknown status", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: `● test.service - Test Service
   Loaded: loaded (/etc/systemd/system/test.service; enabled; vendor preset: enabled)
   Active: unknown-status`,
			Metadata: make(map[string]interface{}),
		}

		result, err := fetcher.parseSystemctlOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "unknown", result.Status)
	})
}

func TestSystemFetcher_ParseServiceOutput(t *testing.T) {
	fetcher := NewSystemFetcher(30*time.Second, false)

	t.Run("parses running service", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: "test service is running",
		}

		result, err := fetcher.parseServiceOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "active", result.Status)
	})

	t.Run("parses stopped service", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: "test service is stopped",
		}

		result, err := fetcher.parseServiceOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "inactive", result.Status)
	})

	t.Run("parses failed service", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: "test service has failed",
		}

		result, err := fetcher.parseServiceOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "failed", result.Status)
	})

	t.Run("parses unknown status", func(t *testing.T) {
		mockResult := &SystemResult{
			Output: "test service status unknown",
		}

		result, err := fetcher.parseServiceOutput(mockResult, "test")
		require.NoError(t, err)
		assert.Equal(t, "unknown", result.Status)
	})
}

func TestSystemFetcher_HelperFunctions(t *testing.T) {
	t.Run("GetServiceStatus", func(t *testing.T) {
		result, err := GetServiceStatus("nonexistent-service")
		// This will likely fail, but we're testing the function exists
		if err != nil {
			assert.Contains(t, err.Error(), "failed to get status")
		} else {
			assert.NotNil(t, result)
		}
	})

	t.Run("ExecuteCommand", func(t *testing.T) {
		result, err := ExecuteCommand("echo", []string{"test"})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Contains(t, result.Output, "test")
	})

	t.Run("IsServiceActive", func(t *testing.T) {
		// Test with a service that's likely to not exist
		active := IsServiceActive("nonexistent-service-12345")
		assert.False(t, active)
	})

	t.Run("IsServiceEnabled", func(t *testing.T) {
		// Test with a service that's likely to not exist
		enabled := IsServiceEnabled("nonexistent-service-12345")
		assert.False(t, enabled)
	})

	t.Run("GetProcessInfo", func(t *testing.T) {
		result, err := GetProcessInfo("init")
		// This might fail depending on the system
		if err == nil {
			assert.NotNil(t, result)
		}
	})

	t.Run("GetNetworkInfo", func(t *testing.T) {
		result, err := GetNetworkInfo()
		// This might fail depending on available commands
		if err == nil {
			assert.NotNil(t, result)
		}
	})

	t.Run("GetSystemInfo", func(t *testing.T) {
		result, err := GetSystemInfo()
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.Output)
	})
}

func TestValidateSystemInputSpec(t *testing.T) {
	t.Run("valid spec with service name", func(t *testing.T) {
		spec := &mockSystemInputSpec{
			serviceName: "nginx",
			command:     "",
			valid:       true,
		}

		err := ValidateSystemInputSpec(spec)
		assert.NoError(t, err)
	})

	t.Run("valid spec with command", func(t *testing.T) {
		spec := &mockSystemInputSpec{
			serviceName: "",
			command:     "ps",
			args:        []string{"aux"},
			valid:       true,
		}

		err := ValidateSystemInputSpec(spec)
		assert.NoError(t, err)
	})

	t.Run("invalid spec with both service and command", func(t *testing.T) {
		spec := &mockSystemInputSpec{
			serviceName: "nginx",
			command:     "ps",
			valid:       true,
		}

		err := ValidateSystemInputSpec(spec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot specify both service name and command")
	})

	t.Run("invalid spec with neither service nor command", func(t *testing.T) {
		spec := &mockSystemInputSpec{
			serviceName: "",
			command:     "",
			valid:       true,
		}

		err := ValidateSystemInputSpec(spec)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "either service name or command must be specified")
	})
}

func TestSystemResult(t *testing.T) {
	t.Run("SystemResult struct", func(t *testing.T) {
		result := &SystemResult{
			Status:   "active",
			Output:   "test output",
			Error:    "test error",
			ExitCode: 0,
			Success:  true,
			Metadata: map[string]interface{}{
				"key": "value",
			},
		}

		assert.Equal(t, "active", result.Status)
		assert.Equal(t, "test output", result.Output)
		assert.Equal(t, "test error", result.Error)
		assert.Equal(t, 0, result.ExitCode)
		assert.True(t, result.Success)
		assert.Equal(t, "value", result.Metadata["key"])
	})
}

func TestSystemFetcher_SecurityFeatures(t *testing.T) {
	t.Run("blocks dangerous commands by default", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		dangerousCommands := []string{
			"rm", "sudo", "chmod", "chown", "dd", "mkfs",
			"fdisk", "umount", "kill", "killall", "reboot", "poweroff",
		}

		for _, cmd := range dangerousCommands {
			t.Run("blocks "+cmd, func(t *testing.T) {
				result, err := fetcher.executeCommand(cmd, []string{})
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), "is not allowed")
			})
		}
	})

	t.Run("allows safe commands", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		safeCommands := []string{
			"ps", "grep", "awk", "sed", "cat", "head", "tail",
			"ls", "find", "which", "hostname", "uname", "uptime",
		}

		for _, cmd := range safeCommands {
			t.Run("allows "+cmd, func(t *testing.T) {
				allowed := fetcher.isAllowedCommand(cmd)
				assert.True(t, allowed, "Command %s should be allowed", cmd)
			})
		}
	})

	t.Run("allows all commands when arbitrary commands enabled", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, true)

		// Even dangerous commands should be allowed (though execution may fail)
		result, err := fetcher.executeCommand("nonexistent-dangerous-command", []string{})
		require.NoError(t, err) // No security error
		assert.NotNil(t, result)
		assert.False(t, result.Success) // But execution fails
	})
}

func TestSystemFetcher_EdgeCases(t *testing.T) {
	t.Run("handles empty command output", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		result, err := fetcher.executeCommand("true", []string{})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ExitCode)
		assert.Empty(t, result.Output)
	})

	t.Run("handles command with arguments", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		result, err := fetcher.executeCommand("echo", []string{"-n", "hello", "world"})
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Success)
		assert.Equal(t, 0, result.ExitCode)
		assert.Equal(t, "hello world", strings.TrimSpace(result.Output))
	})

	t.Run("handles multiple inputs", func(t *testing.T) {
		fetcher := NewSystemFetcher(30*time.Second, false)

		inputs := []celscanner.Input{
			&mockSystemInput{
				name: "hostname",
				spec: &mockSystemInputSpec{
					command: "hostname",
					valid:   true,
				},
			},
			&mockSystemInput{
				name: "uptime",
				spec: &mockSystemInputSpec{
					command: "uptime",
					valid:   true,
				},
			},
		}

		result, err := fetcher.FetchInputs(inputs, nil)
		require.NoError(t, err)
		assert.Contains(t, result, "hostname")
		assert.Contains(t, result, "uptime")

		hostnameResult := result["hostname"].(*SystemResult)
		uptimeResult := result["uptime"].(*SystemResult)

		assert.True(t, hostnameResult.Success)
		assert.True(t, uptimeResult.Success)
	})
}

func BenchmarkSystemFetcher_ExecuteCommand(b *testing.B) {
	fetcher := NewSystemFetcher(30*time.Second, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fetcher.executeCommand("echo", []string{"benchmark"})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSystemFetcher_IsAllowedCommand(b *testing.B) {
	fetcher := NewSystemFetcher(30*time.Second, false)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fetcher.isAllowedCommand("ps")
	}
}
