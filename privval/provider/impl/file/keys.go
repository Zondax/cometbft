package file

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cometbft/cometbft/internal/tempfile"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/types"

	"github.com/cometbft/cometbft/crypto/ed25519"
	cp "github.com/cosmos/crypto-provider/pkg/components"
)

type Keys struct {
	Address types.Address   `json:"address"`
	PubKey  *Ed25519PubKey  `json:"pub_key"`
	PrivKey *Ed25519PrivKey `json:"priv_key"`

	filePath string
}

func NewKeys(filePath string) *Keys {
	privKey := GenEd25519PrivKey()
	keys := &Keys{
		Address:  privKey.PubKey().(*Ed25519PubKey).Address(),
		PubKey:   privKey.PubKey().(*Ed25519PubKey),
		PrivKey:  privKey,
		filePath: filePath,
	}

	return keys
}

// Save persists the FilePVKey to its filePath.
func (k Keys) Save() {
	outFile := k.filePath
	if outFile == "" {
		panic("cannot save key: filePath not set")
	}

	// Create output directory if it does not exist
	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		dir := filepath.Dir(outFile)
		if err := os.MkdirAll(dir, 0700); err != nil {
			panic(fmt.Errorf("failed to create directory %s: %w", dir, err))
		}
	}

	jsonBytes, err := cmtjson.MarshalIndent(k, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := tempfile.WriteFileAtomic(outFile, jsonBytes, 0o600); err != nil {
		panic(err)
	}
}

// Ed25519PubKey wraps ed25519.PubKey to implement the cp.PubKey interface
type Ed25519PubKey struct {
	key ed25519.PubKey
}

// Ed25519PrivKey wraps ed25519.PrivKey to implement the cp.PrivKey interface
type Ed25519PrivKey struct {
	key ed25519.PrivKey
}

// Ensure interfaces are implemented
var (
	_ cp.PubKey             = (*Ed25519PubKey)(nil)
	_ cp.PrivKey[cp.PubKey] = (*Ed25519PrivKey)(nil)
)

// Public Key Implementation

func NewEd25519PubKey(key ed25519.PubKey) *Ed25519PubKey {
	return &Ed25519PubKey{key: key}
}

func (pk *Ed25519PubKey) Bytes() []byte {
	return pk.key.Bytes()
}

func (pk *Ed25519PubKey) Type() string {
	return "ed25519"
}

func (pk *Ed25519PubKey) Equals(other cp.PubKey) bool {
	if other == nil {
		return false
	}
	return bytes.Equal(pk.Bytes(), other.Bytes())
}

func (pk *Ed25519PubKey) Address() []byte {
	return pk.key.Address()
}

func (pk *Ed25519PubKey) VerifySignature(msg []byte, sig cp.Signature) bool {
	return pk.key.VerifySignature(msg, sig.Bytes())
}

// MarshalJSON implements the json.Marshaler interface
func (pk Ed25519PubKey) MarshalJSON() ([]byte, error) {
	if pk.key == nil {
		return []byte("null"), nil
	}
	return json.Marshal(pk.key.Bytes())
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (pk *Ed25519PubKey) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		pk.key = nil
		return nil
	}
	var keyBytes []byte
	if err := json.Unmarshal(data, &keyBytes); err != nil {
		return err
	}
	pk.key = ed25519.PubKey(keyBytes)
	return nil
}

// Private Key Implementation

func NewEd25519PrivKey(key ed25519.PrivKey) *Ed25519PrivKey {
	return &Ed25519PrivKey{key: key}
}

func GenEd25519PrivKey() *Ed25519PrivKey {
	privKey := ed25519.GenPrivKey()
	return NewEd25519PrivKey(privKey)
}

func GenEd25519PrivKeyFromSecret(secret []byte) (*Ed25519PrivKey, error) {
	seed := sha256.Sum256(secret)
	privKey := ed25519.GenPrivKeyFromSecret(seed[:])
	return NewEd25519PrivKey(privKey), nil
}

func (pk *Ed25519PrivKey) Bytes() []byte {
	return pk.key.Bytes()
}

func (pk *Ed25519PrivKey) Type() string {
	return "ed25519"
}

func (pk *Ed25519PrivKey) Equals(other cp.PrivKey[cp.PubKey]) bool {
	if other == nil {
		return false
	}
	return bytes.Equal(pk.Bytes(), other.Bytes())
}

func (pk *Ed25519PrivKey) PubKey() cp.PubKey {
	pubKey := pk.key.PubKey().(ed25519.PubKey)
	return NewEd25519PubKey(pubKey)
}

// MarshalJSON implements the json.Marshaler interface
func (pk Ed25519PrivKey) MarshalJSON() ([]byte, error) {
	if pk.key == nil {
		return []byte("null"), nil
	}
	return json.Marshal(pk.key.Bytes())
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (pk *Ed25519PrivKey) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		pk.key = nil
		return nil
	}
	var keyBytes []byte
	if err := json.Unmarshal(data, &keyBytes); err != nil {
		return err
	}
	pk.key = ed25519.PrivKey(keyBytes)
	return nil
}

// Helper functions for key conversion

func PubKeyFromBytes(bz []byte) (*Ed25519PubKey, error) {
	if len(bz) != ed25519.PubKeySize {
		return nil, fmt.Errorf("invalid pubkey size: got %d, want %d", len(bz), ed25519.PubKeySize)
	}
	return NewEd25519PubKey(ed25519.PubKey(bz)), nil
}

func PubKeyFromHex(hexStr string) (*Ed25519PubKey, error) {
	bz, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	return PubKeyFromBytes(bz)
}

func PrivKeyFromBytes(bz []byte) (*Ed25519PrivKey, error) {
	if len(bz) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid privkey size: got %d, want %d", len(bz), ed25519.PrivateKeySize)
	}
	return NewEd25519PrivKey(ed25519.PrivKey(bz)), nil
}

func PrivKeyFromHex(hexStr string) (*Ed25519PrivKey, error) {
	bz, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex: %w", err)
	}
	return PrivKeyFromBytes(bz)
}
