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
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Vincent056/celscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Mock implementations for testing

type mockInputFetcher struct {
	supportedTypes []celscanner.InputType
	fetchData      map[string]interface{}
	fetchError     error
}

func (m *mockInputFetcher) FetchInputs(inputs []celscanner.Input, variables []celscanner.CelVariable) (map[string]interface{}, error) {
	if m.fetchError != nil {
		return nil, m.fetchError
	}
	return m.fetchData, nil
}

func (m *mockInputFetcher) SupportsInputType(inputType celscanner.InputType) bool {
	for _, supported := range m.supportedTypes {
		if supported == inputType {
			return true
		}
	}
	return false
}

type mockCelRule struct {
	identifier string
	inputs     []celscanner.Input
}

func (m *mockCelRule) Identifier() string                  { return m.identifier }
func (m *mockCelRule) Expression() string                  { return "true" }
func (m *mockCelRule) Inputs() []celscanner.Input          { return m.inputs }
func (m *mockCelRule) Metadata() *celscanner.RuleMetadata  { return &celscanner.RuleMetadata{} }
func (m *mockCelRule) Variables() []celscanner.CelVariable { return nil }
func (m *mockCelRule) Evaluate(context.Context, map[string]interface{}) (celscanner.CheckResult, error) {
	return celscanner.CheckResult{}, nil
}

type mockInput struct {
	name      string
	inputType celscanner.InputType
	spec      celscanner.InputSpec
}

func (m *mockInput) Name() string               { return m.name }
func (m *mockInput) Type() celscanner.InputType { return m.inputType }
func (m *mockInput) Spec() celscanner.InputSpec { return m.spec }

type mockInputSpec struct {
	valid bool
}

func (m *mockInputSpec) Validate() error {
	if !m.valid {
		return errors.New("invalid spec")
	}
	return nil
}

func TestNewCompositeFetcher(t *testing.T) {
	t.Run("creates empty composite fetcher", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		assert.NotNil(t, fetcher)
		assert.NotNil(t, fetcher.customFetchers)
		assert.Equal(t, 0, len(fetcher.customFetchers))
	})
}

func TestNewCompositeFetcherWithDefaults(t *testing.T) {
	t.Run("creates fetcher with defaults", func(t *testing.T) {
		fetcher := NewCompositeFetcherWithDefaults(
			nil,
			nil,
			"/tmp/api-resources",
			"/tmp/files",
			true,
		)
		assert.NotNil(t, fetcher)
		assert.NotNil(t, fetcher.kubernetesFetcher)
		assert.NotNil(t, fetcher.filesystemFetcher)
		assert.NotNil(t, fetcher.systemFetcher)
	})

	t.Run("creates fetcher with minimal config", func(t *testing.T) {
		fetcher := NewCompositeFetcherWithDefaults(
			nil,
			nil,
			"",
			"",
			false,
		)
		assert.NotNil(t, fetcher)
		assert.Nil(t, fetcher.kubernetesFetcher)
		assert.NotNil(t, fetcher.filesystemFetcher)
		assert.NotNil(t, fetcher.systemFetcher)
	})
}

func TestCompositeFetcher_FetchResources(t *testing.T) {
	t.Run("successfully fetches resources", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
			fetchData: map[string]interface{}{
				"test": "data",
			},
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, mockFetcher)

		rule := &mockCelRule{
			identifier: "test-rule",
			inputs: []celscanner.Input{
				&mockInput{
					name:      "test",
					inputType: celscanner.InputTypeFile,
					spec:      &mockInputSpec{valid: true},
				},
			},
		}

		result, warnings, err := fetcher.FetchResources(context.Background(), rule, nil)
		require.NoError(t, err)
		assert.Nil(t, warnings)
		assert.Equal(t, "data", result["test"])
	})

	t.Run("returns error on fetch failure", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
			fetchError:     errors.New("fetch failed"),
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, mockFetcher)

		rule := &mockCelRule{
			identifier: "test-rule",
			inputs: []celscanner.Input{
				&mockInput{
					name:      "test",
					inputType: celscanner.InputTypeFile,
					spec:      &mockInputSpec{valid: true},
				},
			},
		}

		result, warnings, err := fetcher.FetchResources(context.Background(), rule, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Nil(t, warnings)
		assert.Contains(t, err.Error(), "fetch failed")
	})
}

func TestCompositeFetcher_FetchInputs(t *testing.T) {
	t.Run("successfully fetches multiple input types", func(t *testing.T) {
		fetcher := NewCompositeFetcher()

		// Mock file fetcher
		fileFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
			fetchData: map[string]interface{}{
				"config": "file data",
			},
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, fileFetcher)

		// Mock system fetcher
		systemFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeSystem},
			fetchData: map[string]interface{}{
				"nginx": "system data",
			},
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeSystem, systemFetcher)

		inputs := []celscanner.Input{
			&mockInput{
				name:      "config",
				inputType: celscanner.InputTypeFile,
				spec:      &mockInputSpec{valid: true},
			},
			&mockInput{
				name:      "nginx",
				inputType: celscanner.InputTypeSystem,
				spec:      &mockInputSpec{valid: true},
			},
		}

		result, err := fetcher.FetchInputs(inputs, nil)
		require.NoError(t, err)
		assert.Equal(t, "file data", result["config"])
		assert.Equal(t, "system data", result["nginx"])
	})

	t.Run("returns error for unsupported input type", func(t *testing.T) {
		fetcher := NewCompositeFetcher()

		inputs := []celscanner.Input{
			&mockInput{
				name:      "unsupported",
				inputType: celscanner.InputTypeHTTP,
				spec:      &mockInputSpec{valid: true},
			},
		}

		result, err := fetcher.FetchInputs(inputs, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "no fetcher available for input type")
	})

	t.Run("returns error on fetcher failure", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
			fetchError:     errors.New("fetcher error"),
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, mockFetcher)

		inputs := []celscanner.Input{
			&mockInput{
				name:      "test",
				inputType: celscanner.InputTypeFile,
				spec:      &mockInputSpec{valid: true},
			},
		}

		result, err := fetcher.FetchInputs(inputs, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to fetch inputs for type")
	})
}

func TestCompositeFetcher_SupportsInputType(t *testing.T) {
	t.Run("supports custom fetcher types", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, mockFetcher)

		assert.True(t, fetcher.SupportsInputType(celscanner.InputTypeFile))
		assert.False(t, fetcher.SupportsInputType(celscanner.InputTypeHTTP))
	})

	t.Run("supports built-in fetcher types", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		fetcher.SetFilesystemFetcher(NewFilesystemFetcher(""))
		fetcher.SetSystemFetcher(NewSystemFetcher(30*time.Second, false))
		fetcher.SetKubernetesFetcher(NewKubernetesFetcher(nil, nil))

		assert.True(t, fetcher.SupportsInputType(celscanner.InputTypeFile))
		assert.True(t, fetcher.SupportsInputType(celscanner.InputTypeSystem))
		assert.True(t, fetcher.SupportsInputType(celscanner.InputTypeKubernetes))
	})
}

func TestCompositeFetcher_GetFetcherForType(t *testing.T) {
	t.Run("returns custom fetcher first", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, mockFetcher)
		fetcher.SetFilesystemFetcher(NewFilesystemFetcher(""))

		result := fetcher.getFetcherForType(celscanner.InputTypeFile)
		assert.Equal(t, mockFetcher, result)
	})

	t.Run("returns built-in fetcher if no custom", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		fileFetcher := NewFilesystemFetcher("")
		fetcher.SetFilesystemFetcher(fileFetcher)

		result := fetcher.getFetcherForType(celscanner.InputTypeFile)
		assert.Equal(t, fileFetcher, result)
	})

	t.Run("returns nil for unsupported type", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		result := fetcher.getFetcherForType(celscanner.InputTypeHTTP)
		assert.Nil(t, result)
	})
}

func TestCompositeFetcher_RegisterCustomFetcher(t *testing.T) {
	t.Run("registers custom fetcher", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
		}

		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, mockFetcher)
		assert.Equal(t, mockFetcher, fetcher.customFetchers[celscanner.InputTypeFile])
	})
}

func TestCompositeFetcher_SetFetchers(t *testing.T) {
	t.Run("sets kubernetes fetcher", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		kubeFetcher := NewKubernetesFetcher(nil, nil)

		fetcher.SetKubernetesFetcher(kubeFetcher)
		assert.Equal(t, kubeFetcher, fetcher.kubernetesFetcher)
	})

	t.Run("sets filesystem fetcher", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		fileFetcher := NewFilesystemFetcher("")

		fetcher.SetFilesystemFetcher(fileFetcher)
		assert.Equal(t, fileFetcher, fetcher.filesystemFetcher)
	})

	t.Run("sets system fetcher", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		systemFetcher := NewSystemFetcher(30*time.Second, false)

		fetcher.SetSystemFetcher(systemFetcher)
		assert.Equal(t, systemFetcher, fetcher.systemFetcher)
	})
}

func TestCompositeFetcher_GetSupportedInputTypes(t *testing.T) {
	t.Run("returns all supported types", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		fetcher.SetFilesystemFetcher(NewFilesystemFetcher(""))
		fetcher.SetSystemFetcher(NewSystemFetcher(30*time.Second, false))

		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeHTTP},
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeHTTP, mockFetcher)

		types := fetcher.GetSupportedInputTypes()
		assert.Contains(t, types, celscanner.InputTypeFile)
		assert.Contains(t, types, celscanner.InputTypeSystem)
		assert.Contains(t, types, celscanner.InputTypeHTTP)
		assert.NotContains(t, types, celscanner.InputTypeKubernetes)
	})

	t.Run("returns empty for no fetchers", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		types := fetcher.GetSupportedInputTypes()
		assert.Empty(t, types)
	})
}

func TestCompositeFetcher_ValidateInputs(t *testing.T) {
	t.Run("validates supported inputs", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		fetcher.SetFilesystemFetcher(NewFilesystemFetcher(""))

		inputs := []celscanner.Input{
			&mockInput{
				name:      "test",
				inputType: celscanner.InputTypeFile,
				spec:      &mockInputSpec{valid: true},
			},
		}

		err := fetcher.ValidateInputs(inputs)
		assert.NoError(t, err)
	})

	t.Run("fails for unsupported input type", func(t *testing.T) {
		fetcher := NewCompositeFetcher()

		inputs := []celscanner.Input{
			&mockInput{
				name:      "unsupported",
				inputType: celscanner.InputTypeHTTP,
				spec:      &mockInputSpec{valid: true},
			},
		}

		err := fetcher.ValidateInputs(inputs)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported input type")
	})

	t.Run("fails for invalid input spec", func(t *testing.T) {
		fetcher := NewCompositeFetcher()
		fetcher.SetFilesystemFetcher(NewFilesystemFetcher(""))

		inputs := []celscanner.Input{
			&mockInput{
				name:      "test",
				inputType: celscanner.InputTypeFile,
				spec:      &mockInputSpec{valid: false},
			},
		}

		err := fetcher.ValidateInputs(inputs)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid input spec")
	})
}

func TestCompositeFetcherBuilder(t *testing.T) {
	t.Run("builds composite fetcher with builder pattern", func(t *testing.T) {
		builder := NewCompositeFetcherBuilder()
		assert.NotNil(t, builder)
		assert.NotNil(t, builder.fetcher)
	})

	t.Run("builds with kubernetes support", func(t *testing.T) {
		fetcher := NewCompositeFetcherBuilder().
			WithKubernetes(nil, nil).
			Build()

		assert.NotNil(t, fetcher.kubernetesFetcher)
	})

	t.Run("builds with kubernetes file support", func(t *testing.T) {
		fetcher := NewCompositeFetcherBuilder().
			WithKubernetesFiles("/tmp/api-resources").
			Build()

		assert.NotNil(t, fetcher.kubernetesFetcher)
	})
 
	t.Run("builds with filesystem support", func(t *testing.T) {
		fetcher := NewCompositeFetcherBuilder().
			WithFilesystem("/tmp").
			Build()

		assert.NotNil(t, fetcher.filesystemFetcher)
	})

	t.Run("builds with system support", func(t *testing.T) {
		fetcher := NewCompositeFetcherBuilder().
			WithSystem(false).
			Build()

		assert.NotNil(t, fetcher.systemFetcher)
	})

	t.Run("builds with custom fetcher", func(t *testing.T) {
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeHTTP},
		}

		fetcher := NewCompositeFetcherBuilder().
			WithCustomFetcher(celscanner.InputTypeHTTP, mockFetcher).
			Build()

		assert.Equal(t, mockFetcher, fetcher.customFetchers[celscanner.InputTypeHTTP])
	})

	t.Run("builds with all components", func(t *testing.T) {
		mockFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeHTTP},
		}

		fetcher := NewCompositeFetcherBuilder().
			WithKubernetesFiles("/tmp/api-resources").
			WithFilesystem("/tmp").
			WithSystem(true).
			WithCustomFetcher(celscanner.InputTypeHTTP, mockFetcher).
			Build()

		assert.NotNil(t, fetcher.kubernetesFetcher)
		assert.NotNil(t, fetcher.filesystemFetcher)
		assert.NotNil(t, fetcher.systemFetcher)
		assert.Equal(t, mockFetcher, fetcher.customFetchers[celscanner.InputTypeHTTP])
	})
}

func TestCompositeFetcher_Integration(t *testing.T) {
	t.Run("integrates with real filesystem fetcher", func(t *testing.T) {
		// Create temporary test file
		tempDir, err := os.MkdirTemp("", "composite_test")
		require.NoError(t, err)
		defer os.RemoveAll(tempDir)

		testFile := filepath.Join(tempDir, "test.txt")
		err = os.WriteFile(testFile, []byte("test content"), 0644)
		require.NoError(t, err)

		fetcher := NewCompositeFetcherBuilder().
			WithFilesystem(tempDir).
			Build()

		input := celscanner.NewFileInput("testfile", "test.txt", "text", false, false)
		result, err := fetcher.FetchInputs([]celscanner.Input{input}, nil)

		require.NoError(t, err)
		assert.Equal(t, "test content", result["testfile"])
	})
}

func TestCelVariable(t *testing.T) {
	t.Run("implements CelVariable interface", func(t *testing.T) {
		gvk := schema.GroupVersionKind{
			Group:   "apps",
			Version: "v1",
			Kind:    "Deployment",
		}

		variable := &CelVariable{
			name:      "test-var",
			namespace: "default",
			value:     "test-value",
			gvk:       gvk,
		}

		assert.Equal(t, "test-var", variable.Name())
		assert.Equal(t, "default", variable.Namespace())
		assert.Equal(t, "test-value", variable.Value())
		assert.Equal(t, gvk, variable.GroupVersionKind())
	})
}

func TestCompositeFetcher_ErrorHandling(t *testing.T) {
	t.Run("handles fetcher panic gracefully", func(t *testing.T) {
		fetcher := NewCompositeFetcher()

		// Mock fetcher that panics
		panicFetcher := &mockInputFetcher{
			supportedTypes: []celscanner.InputType{celscanner.InputTypeFile},
			fetchError:     errors.New("panic: something went wrong"),
		}
		fetcher.RegisterCustomFetcher(celscanner.InputTypeFile, panicFetcher)

		inputs := []celscanner.Input{
			&mockInput{
				name:      "test",
				inputType: celscanner.InputTypeFile,
				spec:      &mockInputSpec{valid: true},
			},
		}

		result, err := fetcher.FetchInputs(inputs, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "panic: something went wrong")
	})
}

func TestCompositeFetcher_EmptyInputs(t *testing.T) {
	t.Run("handles empty inputs gracefully", func(t *testing.T) {
		fetcher := NewCompositeFetcher()

		result, err := fetcher.FetchInputs([]celscanner.Input{}, nil)
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}
