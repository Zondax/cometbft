package provider

import (
	"encoding/json"
	"fmt"
	"github.com/cometbft/cometbft/config"
	cp "github.com/cosmos/crypto-provider/pkg/components"
	"os"
)

type CryptoProviderConfig struct {
	ProviderType string
	BuildSource  cp.BuildSourceMetadata
}

// ConvertConfig converts config.CryptoProviderConfig to CryptoProviderConfig
func ConvertConfig(config *config.CryptoProviderConfig) (*CryptoProviderConfig, error) {
	cfgFile, err := os.ReadFile(config.ProviderFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var meta cp.ProviderMetadata
	err = json.Unmarshal(cfgFile, &meta)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	if meta.Validate() != nil {
		return nil, fmt.Errorf("invalid metadata in config file: %w", err)
	}

	return &CryptoProviderConfig{
		ProviderType: meta.Type,
		BuildSource:  cp.BuildSourceMetadata{Metadata: meta},
	}, nil
}
