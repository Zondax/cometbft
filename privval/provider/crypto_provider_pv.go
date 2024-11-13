package provider

import (
	"bytes"
	"fmt"

	"github.com/cometbft/cometbft/config"
	"github.com/cometbft/cometbft/privval"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cosmos/crypto-provider/pkg/factory"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/types"
	cp "github.com/cosmos/crypto-provider/pkg/components"

	// Add all provider packages here
	_ "github.com/cometbft/cometbft/privval/provider/impl/file"
)

// CryptoProviderPV implements PrivValidator interface
var _ types.PrivValidator = (*CryptoProviderPV)(nil)

// CryptoProviderPV is the implementation of PrivValidator using CryptoProvider's methods
type CryptoProviderPV struct {
	provider cp.CryptoProvider
	pubKey   PubKeyAdapter
}

// NewCryptoProviderPV creates a new instance of CryptoProviderPV
func NewCryptoProviderPV(config *config.CryptoProviderConfig) (*CryptoProviderPV, error) {
	if !config.Enabled {
		return nil, nil // TODO return err?
	}

	cpConfig, err := ConvertConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to convert config: %w", err)
	}

	f := factory.GetGlobalFactory()
	provider, err := f.CreateCryptoProvider(cpConfig.ProviderType, cpConfig.BuildSource)
	if err != nil {
		return nil, fmt.Errorf("failed to load crypto provider: %w", err)
	}

	return &CryptoProviderPV{
		provider: provider,
		pubKey:   NewPubkeyAdapter(provider.GetPubKey(), provider)}, nil
}

func (pv *CryptoProviderPV) GetPubKey() (crypto.PubKey, error) {
	return &PubKeyAdapter{
		providerPubKey: pv.provider.GetPubKey(),
		provider:       pv.provider,
	}, nil
}

// SignVote signs a canonical representation of the vote. If signExtension is true, it also signs the vote extension.
func (pv *CryptoProviderPV) SignVote(chainID string, vote *cmtproto.Vote, signExtension bool) error {
	signer := pv.provider.GetSigner()

	// Calculate voteBytes
	voteBytes := types.VoteSignBytes(chainID, vote)

	// The underlying signer needs these parameters so we pass them through SignerOpts
	options := cp.SignerOpts{
		privval.SignOpKey:        privval.SignOpVote,
		privval.ChainIdKey:       chainID,
		privval.VoteKey:          vote,
		privval.SignExtensionKey: signExtension,
	}

	sig, err := signer.Sign(voteBytes, options)
	if err != nil {
		return err
	}
	vote.Signature = sig.Bytes()
	return nil
}

// SignProposal signs a canonical representation of the proposal
func (pv *CryptoProviderPV) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	signer := pv.provider.GetSigner()

	// Calculate proposalBytes
	proposalBytes := types.ProposalSignBytes(chainID, proposal)

	// The underlying signer needs these parameters so we pass them through SignerOpts
	options := cp.SignerOpts{
		privval.SignOpKey:   privval.SignOpProp,
		privval.ChainIdKey:  chainID,
		privval.ProposalKey: proposal,
	}

	sig, err := signer.Sign(proposalBytes, options)
	if err != nil {
		return err
	}
	proposal.Signature = sig.Bytes()
	return nil
}

// SignBytes signs an arbitrary array of bytes
func (pv *CryptoProviderPV) SignBytes(bytes []byte) ([]byte, error) {
	signer := pv.provider.GetSigner()
	options := cp.SignerOpts{
		privval.SignOpKey: privval.SignOpBytes,
	}

	sig, err := signer.Sign(bytes, options)
	return sig.Bytes(), err
}

// Ensure PubKeyAdapter satisfies the crypto.PubKey interface
var _ crypto.PubKey = (*PubKeyAdapter)(nil)

// PubKeyAdapter adapts the provider's PublicKey to CometBFT's crypto.PubKey interface
type PubKeyAdapter struct {
	providerPubKey cp.PubKey
	provider       cp.CryptoProvider
}

func NewPubkeyAdapter(pubkey cp.PubKey, provider cp.CryptoProvider) PubKeyAdapter {
	return PubKeyAdapter{
		providerPubKey: pubkey,
		provider:       provider,
	}
}

func (p *PubKeyAdapter) Address() crypto.Address {
	return crypto.AddressHash(p.Bytes())
}

func (p *PubKeyAdapter) Bytes() []byte {
	return p.providerPubKey.Bytes()
}

func (p *PubKeyAdapter) VerifySignature(msg []byte, sig []byte) bool {
	if p.provider == nil || len(sig) == 0 {
		return false
	}

	signature := &SignatureAdapter{sigBytes: sig}
	ok, err := p.provider.GetVerifier().Verify(signature, msg, cp.VerifierOpts{})
	if err != nil {
		return false
	}
	return ok
}

func (p *PubKeyAdapter) Equals(other crypto.PubKey) bool {
	if other == nil {
		return false
	}
	return bytes.Equal(p.Bytes(), other.Bytes())
}

func (p *PubKeyAdapter) Type() string {
	return p.providerPubKey.Type()
}

// SignatureAdapter implements the cp.Signature interface
type SignatureAdapter struct {
	sigBytes []byte
}

func (s *SignatureAdapter) Equals(other cp.Signature) bool {
	//TODO implement me
	panic("implement me")
}

func (s *SignatureAdapter) Bytes() []byte {
	return s.sigBytes
}
