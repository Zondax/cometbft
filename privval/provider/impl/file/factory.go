package file

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	config2 "github.com/cometbft/cometbft/config"

	cp "github.com/cosmos/crypto-provider/pkg/components"
	cpfactory "github.com/cosmos/crypto-provider/pkg/factory"
)

type Factory struct {
	cp.BaseFactory
}

var _ cp.CryptoProviderFactory = (*Factory)(nil)

// Register into the global factory
func init() {
	f := cpfactory.GetGlobalFactory()
	err := f.RegisterFactory(&Factory{
		BaseFactory: cp.BaseFactory{
			BaseDir: config2.DefaultConfig().RootDir, // TODO: fix this to use the correct base dir
		},
	})
	if err != nil {
		// TODO err instead of panic
		panic(fmt.Sprintf("failed to register factory: %v", err))
	}
}

func (f *Factory) Create(source cp.BuildSource) (cp.CryptoProvider, error) {
	// Validate first the build source
	if source == nil {
		return nil, fmt.Errorf("[FileFactory] source is nil")
	}
	if err := source.Validate(); err != nil {
		return nil, fmt.Errorf("build source contains invalid data. Check Validate() method: %w", err)
	}

	// Check if baseDir is set, otherwise set a temporary one
	if f.BaseDir == "" {
		f.BaseDir = os.TempDir()
		fmt.Println("WARNING: baseDir is not set. Using temporary directory: ", f.BaseDir)
	}

	switch s := source.(type) {
	case cp.BuildSourceNew:
		p, err := f.createNew(s.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to create new provider: %w", err)
		}
		err = f.Save(p)
		if err != nil {
			fmt.Printf("WARNING: failed to save provider!: %v", err)
		}
		return p, nil
	case cp.BuildSourceJson:
		return f.createFromJSON(s.JsonString)
	default:
		return nil, fmt.Errorf("unsupported build source of type: %T", source.Type())
	}
}

// createFromJSON creates a provider from JSON configuration
func (f *Factory) createFromJSON(jsonStr string) (cp.CryptoProvider, error) {
	var m cp.ProviderMetadata
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %w", err)
	}

	// Validate metadata
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid crypto provider metadata: %w", err)
	}

	// Validate provider type
	if m.Type != ProviderTypeFile {
		return nil, fmt.Errorf("invalid provider type: expected %s, got %s", ProviderTypeFile, m.Type)
	}

	// Validate version
	// TODO: add semver check and compatibility check
	if m.Version != Version {
		return nil, fmt.Errorf("invalid version: expected %s, got %s", Version, m.Version)
	}

	// Convert metadata.Config to FileProviderConfig
	configBytes, err := json.Marshal(m.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	var config FileProviderConfig
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	config.Metadata = m

	provider, err := LoadFileCryptoProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to load provider: %w", err)
	}

	return provider, nil
}

// createNew creates a new provider with default configuration
func (f *Factory) createNew(name string) (cp.CryptoProvider, error) {
	// Ensure provider directory exists
	if err := os.MkdirAll(f.BaseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create provider directory: %w", err)
	}

	keyFilePath := filepath.Join(f.BaseDir, config2.DefaultBaseConfig().PrivValidatorKey)
	stateFilePath := filepath.Join(f.BaseDir, config2.DefaultBaseConfig().PrivValidatorState)

	config := FileProviderConfig{
		KeyFilePath:   keyFilePath,
		StateFilePath: stateFilePath,
		Metadata: cp.ProviderMetadata{
			Version: Version,
			Name:    name,
			Type:    ProviderTypeFile,
			Config: cp.ProviderConfig{
				"key_file_path":   keyFilePath,
				"state_file_path": stateFilePath,
			},
		},
	}

	p, err := NewFileCryptoProvider(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create new provider: %w", err)
	}

	return p, nil
}

func (f *Factory) Type() string {
	return ProviderTypeFile
}

func (f *Factory) SupportedSources() []string {
	return []string{
		cp.BuildSourceNew{}.Type(),
		cp.BuildSourceJson{}.Type(),
	}
}
