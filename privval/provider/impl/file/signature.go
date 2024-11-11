package file

import (
	"bytes"

	cp "github.com/cosmos/crypto-provider/pkg/components"
)

// ByteSignature wraps a byte slice to implement the components.Signature interface
type ByteSignature []byte

// Bytes returns the underlying bytes of the signature
func (s ByteSignature) Bytes() []byte {
	return s
}

// Equals compares this signature with another signature
func (s ByteSignature) Equals(other cp.Signature) bool {
	return bytes.Equal(s.Bytes(), other.Bytes())
}
