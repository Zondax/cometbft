package file

import (
	"encoding/json"
	"testing"

	"github.com/cometbft/cometbft/crypto/ed25519"
	"github.com/stretchr/testify/require"
)

func TestKeysMarshalFormat(t *testing.T) {
	// Generate a new key pair
	privKey := ed25519.GenPrivKey()
	pubKey := privKey.PubKey().(ed25519.PubKey)

	// Create Keys struct
	keys := &Keys{
		Address:  pubKey.Address(),
		PubKey:   NewEd25519PubKey(pubKey),
		PrivKey:  NewEd25519PrivKey(privKey),
		filePath: "test/path",
	}

	// Marshal to JSON
	jsonBytes, err := json.Marshal(keys)
	require.NoError(t, err)

	// Unmarshal back to verify
	var newKeys Keys
	newKeys.filePath = "test/path"
	err = json.Unmarshal(jsonBytes, &newKeys)
	require.NoError(t, err)
	require.Equal(t, keys, &newKeys)
}
