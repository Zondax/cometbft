package file

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	config2 "github.com/cometbft/cometbft/config"
	cp "github.com/cosmos/crypto-provider/pkg/components"
)

func TestFactory_Create_New(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	factory := Factory{
		BaseFactory: cp.BaseFactory{
			BaseDir: tempDir,
		},
	}
	providerName := "test_provider"

	// Test
	source := cp.BuildSourceNew{Name: providerName}
	provider, err := factory.Create(source)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Verify metadata from the provider interface
	meta := provider.Metadata()
	assert.Equal(t, Version, meta.Version)
	assert.Equal(t, providerName, meta.Name)
	assert.Equal(t, ProviderTypeFile, meta.Type)

	// Check provider json file exists
	providerJsonFile := filepath.Join(tempDir, providerName+".json")
	assert.FileExists(t, providerJsonFile)
}

func TestFactory_Create_FromJSON(t *testing.T) {
	// Setup
	tempDir := t.TempDir()
	factory := Factory{
		BaseFactory: cp.BaseFactory{
			BaseDir: tempDir,
		},
	}
	providerName := "test_provider"

	// Create random keys
	keys := NewKeys(filepath.Join(tempDir, providerName, config2.DefaultBaseConfig().PrivValidatorKey))
	keys.Save()

	// Create empty state file
	state := LastSignState{
		filePath: filepath.Join(tempDir, providerName, config2.DefaultBaseConfig().PrivValidatorState),
	}
	state.Save()

	// Create metadata mock
	meta := cp.ProviderMetadata{
		Type:      ProviderTypeFile,
		Version:   Version,
		Name:      providerName,
		PublicKey: keys.PubKey.String(),
		Config: map[string]any{
			"key_file_path":   keys.filePath,
			"state_file_path": state.filePath,
		},
	}

	configJSON, err := json.Marshal(meta)
	require.NoError(t, err)

	// Test creation from JSON
	source := cp.BuildSourceJson{JsonString: string(configJSON)}
	provider, err := factory.Create(source)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Verify metadata
	newMeta := provider.Metadata()
	assert.Equal(t, Version, newMeta.Version)
	assert.Equal(t, providerName, newMeta.Name)
	assert.Equal(t, ProviderTypeFile, newMeta.Type)
	assert.Equal(t, keys.PubKey.String(), newMeta.PublicKey)
}

func TestFactory_Create_InvalidSource(t *testing.T) {
	factory := Factory{}

	tests := []struct {
		name        string
		source      cp.BuildSource
		expectedErr string
	}{
		{
			name:        "nil source",
			source:      nil,
			expectedErr: "source is nil",
		},
		{
			name:        "invalid json",
			source:      cp.BuildSourceJson{JsonString: "invalid json"},
			expectedErr: "failed to parse JSON config",
		},
		{
			name:        "empty provider name",
			source:      cp.BuildSourceNew{Name: ""},
			expectedErr: "build source contains invalid data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := factory.Create(tt.source)
			assert.Nil(t, provider)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}
