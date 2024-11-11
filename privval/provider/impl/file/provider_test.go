package file

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	config2 "github.com/cometbft/cometbft/config"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	cp "github.com/cosmos/crypto-provider/pkg/components"
	"github.com/stretchr/testify/require"
)

type testContext struct {
	tempDir     string
	providerDir string
	config      FileProviderConfig
	cleanup     func()
}

func setupTestContext(t *testing.T) *testContext {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "crypto_provider_test_*")
	require.NoError(t, err)

	// Create provider directory
	providerDir := filepath.Join(tempDir, "test_provider")
	err = os.MkdirAll(providerDir, 0700)
	require.NoError(t, err)

	// Setup config with temp directory paths
	config := FileProviderConfig{
		KeyFilePath:   filepath.Join(providerDir, config2.DefaultPrivValKeyName),
		StateFilePath: filepath.Join(providerDir, config2.DefaultPrivValStateName),
		Metadata: cp.ProviderMetadata{
			Version: Version,
			Name:    "test_provider",
			Type:    ProviderTypeFile,
		},
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return &testContext{
		tempDir:     tempDir,
		providerDir: providerDir,
		config:      config,
		cleanup:     cleanup,
	}
}

func TestNewFileCryptoProvider(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	// Create new provider
	provider, err := NewFileCryptoProvider(ctx.config)
	require.NoError(t, err)
	require.NotNil(t, provider)

	// Check that files were created and contain valid data
	keyFileInfo, err := os.Stat(ctx.config.KeyFilePath)
	require.NoError(t, err)
	require.True(t, keyFileInfo.Size() > 0, "key file should not be empty")

	stateFileInfo, err := os.Stat(ctx.config.StateFilePath)
	require.NoError(t, err)
	require.True(t, stateFileInfo.Size() > 0, "state file should not be empty")

	// Verify key file contents
	keyFileBytes, err := os.ReadFile(ctx.config.KeyFilePath)
	require.NoError(t, err)
	var keys Keys
	err = json.Unmarshal(keyFileBytes, &keys)
	require.NoError(t, err)
	require.NotEmpty(t, keys.Address)
	require.NotNil(t, keys.PubKey)
	require.NotNil(t, keys.PrivKey)

	// Verify state file contents
	stateFileBytes, err := os.ReadFile(ctx.config.StateFilePath)
	require.NoError(t, err)
	var state LastSignState
	err = cmtjson.Unmarshal(stateFileBytes, &state)
	require.NoError(t, err)
	require.Equal(t, stepNone, state.Step)
}

func TestLoadFileCryptoProvider(t *testing.T) {
	ctx := setupTestContext(t)
	defer ctx.cleanup()

	// First create a new provider to generate the files
	originalProvider, err := NewFileCryptoProvider(ctx.config)
	require.NoError(t, err)
	require.NotNil(t, originalProvider)

	// Store original values for comparison
	originalPubKey := originalProvider.GetPubKey()
	originalAddress := originalProvider.GetAddress()

	// Now load the existing provider
	loadedProvider, err := LoadFileCryptoProvider(ctx.config)
	require.NoError(t, err)
	require.NotNil(t, loadedProvider)

	// Verify that loaded provider has same keys as original
	require.Equal(t, originalPubKey, loadedProvider.GetPubKey())
	require.Equal(t, originalAddress, loadedProvider.GetAddress())

	// Verify the loaded state matches the initial state
	require.Equal(t, stepNone, loadedProvider.lastSignState.Step)
	require.Equal(t, int64(0), loadedProvider.lastSignState.Height)
	require.Equal(t, int32(0), loadedProvider.lastSignState.Round)

	// Verify the file paths were properly set
	require.Equal(t, ctx.config.KeyFilePath, loadedProvider.keys.filePath)
	require.Equal(t, ctx.config.StateFilePath, loadedProvider.lastSignState.filePath)
}
