package provider

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/cometbft/cometbft/config"
	cp "github.com/cosmos/crypto-provider/pkg/components"
)

type CryptoProviderConfig struct {
	ProviderType string
	BuildSource  cp.BuildSourceJson
}

// LoadConfig loads the provider metadata from the config file
func LoadConfig(config *config.CryptoProviderConfig) (*CryptoProviderConfig, error) {
	cfgFile, err := os.ReadFile(config.ProviderFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var meta cp.ProviderMetadata
	err = json.Unmarshal(cfgFile, &meta)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	if err := meta.Validate(); err != nil {
		return nil, fmt.Errorf("invalid metadata in config file: %w", err)
	}

	return &CryptoProviderConfig{
		ProviderType: meta.Type,
		BuildSource: cp.BuildSourceJson{ // TODO: could just create BuildSourceMetadata
			JsonString: string(cfgFile),
		},
	}, nil
}
