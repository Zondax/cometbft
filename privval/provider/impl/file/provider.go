package file

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	cp "github.com/cosmos/crypto-provider/pkg/components"
	"github.com/cosmos/gogoproto/proto"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/privval/provider"
	"github.com/cometbft/cometbft/types"
	cmttime "github.com/cometbft/cometbft/types/time"
)

// check that this type implements CryptoProvider interface
var _ cp.CryptoProvider = &CryptoProviderFile{}

const (
	ProviderTypeFile = "file"
	Version          = "v1.0.0"
)

// FileProviderConfig contains all the configuration needed to create a new File Crypto Provider
type FileProviderConfig struct {
	Metadata      cp.ProviderMetadata
	KeyFilePath   string `json:"key_file_path"`
	StateFilePath string `json:"state_file_path"`
}

// Validate checks if the FileProviderConfig is valid
func (c FileProviderConfig) Validate() error {
	if c.KeyFilePath == "" {
		return errors.New("missing key file path")
	}
	if c.StateFilePath == "" {
		return errors.New("missing state file path")
	}

	return nil
}

// CryptoProviderFile implements PrivValidator using data persisted to disk
// to prevent double signing.
// NOTE: the directories containing pv.Key.filePath and pv.lastSignState.filePath must already exist.
// It includes the LastSignature and LastSignBytes so we don't lose the signature
// if the process crashes after signing but before the resulting consensus message is processed.
type CryptoProviderFile struct {
	keys          *Keys
	lastSignState LastSignState
	config        FileProviderConfig
}

// LoadFileCryptoProvider creates a new File Crypto Provider
func LoadFileCryptoProvider(config FileProviderConfig) (*CryptoProviderFile, error) {
	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid file provider config: %w", err)
	}

	p := &CryptoProviderFile{
		config: config,
		lastSignState: LastSignState{
			Step:     stepNone,
			filePath: config.StateFilePath,
		},
	}

	// Load the last sign state
	if err := p.lastSignState.Load(); err != nil {
		return nil, fmt.Errorf("failed to load last sign state: %w", err)
	}

	// Initialize the provider keys
	if err := p.InitializeKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	return p, nil
}

// NewFileCryptoProvider creates a new File Crypto Provider with no state
func NewFileCryptoProvider(config FileProviderConfig) (*CryptoProviderFile, error) {
	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid file provider config: %w", err)
	}

	// Create provider with empty state
	p := &CryptoProviderFile{
		config: config,
		lastSignState: LastSignState{
			Step:     stepNone,
			filePath: config.StateFilePath,
		},
	}

	// Load or create new keys
	if err := p.InitializeKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize keys: %w", err)
	}

	// Update public key in metadata
	config.Metadata.PublicKey = p.keys.PubKey.key.String()

	// Save initial state
	p.Save()
	return p, nil
}

// InitializeKeys initializes the provider's keys
func (pv *CryptoProviderFile) InitializeKeys() error {
	if pv.config.KeyFilePath == "" {
		return errors.New("missing key file path")
	}

	// Create key file if it doesn't exist
	if _, err := os.Stat(pv.config.KeyFilePath); os.IsNotExist(err) {
		dir := filepath.Dir(pv.config.KeyFilePath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			panic(fmt.Errorf("failed to create directory %s: %w", dir, err))
		}
		if _, err := os.Create(pv.config.KeyFilePath); err != nil {
			panic(fmt.Errorf("failed to create file %s: %w", pv.config.KeyFilePath, err))
		}
	}

	keyJSONBytes, err := os.ReadFile(pv.config.KeyFilePath)
	if err != nil {
		return fmt.Errorf("failed to read key file %s: %w", pv.config.KeyFilePath, err)
	}

	// Generate new keys if file is empty
	if len(keyJSONBytes) == 0 {
		keys := NewKeys(pv.config.KeyFilePath)
		pv.keys = keys
		pv.keys.Save()
		return nil
	}

	// Load and validate existing keys
	var keys Keys
	keys.filePath = pv.config.KeyFilePath
	err = cmtjson.Unmarshal(keyJSONBytes, &keys)
	if err != nil {
		return fmt.Errorf("error reading PrivValidator key from %v: %w", pv.config.KeyFilePath, err)
	}

	pv.keys = &keys

	return nil
}

//// GetAddress returns the address of the validator.
//func (pv *CryptoProviderFile) GetAddress() types.Address {
//	return pv.Key.Address
//}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (pv *CryptoProviderFile) GetPubKey() cp.PubKey {
	return pv.keys.PubKey
}

// GetSigner returns the signer instance
func (pv *CryptoProviderFile) GetSigner() cp.Signer {
	return pv
}

func (pv *CryptoProviderFile) Sign(signDoc []byte, options cp.SignerOpts) (cp.Signature, error) {
	signOp, ok := options[provider.SignOpKey].(string)
	if !ok {
		return nil, errors.New("missing sign operation")
	}

	chainId, ok := options[provider.ChainIdKey].(string)
	if !ok {
		return nil, errors.New("missing chain ID")
	}

	switch signOp {
	case provider.SignOpVote:
		vote, ok := options[provider.VoteKey].(*cmtproto.Vote)
		if !ok {
			return nil, errors.New("bad vote data")
		}

		err := pv.SignVote(chainId, vote, true)
		if err != nil {
			return nil, fmt.Errorf("failed to sign vote: %w", err)
		}
		return ByteSignature(vote.Signature), nil
	}

	// Handle raw bytes signing
	sig, err := pv.SignBytes(signDoc)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (pv *CryptoProviderFile) SignVote(chainID string, vote *cmtproto.Vote, signExtension bool) error {
	if err := pv.signVote(chainID, vote, signExtension); err != nil {
		return fmt.Errorf("error signing vote: %v", err)
	}
	return nil
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (pv *CryptoProviderFile) SignProposal(chainID string, proposal *cmtproto.Proposal) error {
	if err := pv.signProposal(chainID, proposal); err != nil {
		return fmt.Errorf("error signing proposal: %v", err)
	}
	return nil
}

// SignBytes signs the given bytes. Implements PrivValidator.
func (pv *CryptoProviderFile) SignBytes(bytes []byte) (ByteSignature, error) {
	sig, err := pv.GetSigner().Sign(bytes, nil)
	if err != nil {
		return nil, err
	}
	return sig.Bytes(), nil
}

// Save persists the CryptoProviderFile to disk.
func (pv *CryptoProviderFile) Save() {
	pv.lastSignState.Save()
	pv.keys.Save()
}

// Reset resets all fields in the CryptoProviderFile.
// NOTE: Unsafe!
func (pv *CryptoProviderFile) Reset() {
	pv.lastSignState.reset()
	pv.Save()
}

// String returns a string representation of the CryptoProviderFile.
func (pv *CryptoProviderFile) String() string {
	return fmt.Sprintf(
		"PrivValidator{%v LH:%v, LR:%v, LS:%v}",
		pv.GetAddress(),
		pv.lastSignState.Height,
		pv.lastSignState.Round,
		pv.lastSignState.Step,
	)
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (pv *CryptoProviderFile) GetAddress() types.Address {
	return pv.keys.Address
}

func (pv *CryptoProviderFile) GetVerifier() cp.Verifier {
	//TODO implement me
	panic("implement me")
}

func (pv *CryptoProviderFile) GetHasher() cp.Hasher {
	//TODO implement me
	panic("implement me")
}

func (pv *CryptoProviderFile) Metadata() cp.ProviderMetadata {
	return pv.config.Metadata
}

// ------------------------------------------------------------------------------------

// getInternalConfig extracts FileProviderConfig from ProviderMetadata
func getInternalConfig(meta cp.ProviderMetadata) (FileProviderConfig, error) {
	var config FileProviderConfig
	configBytes, err := json.Marshal(meta.Config)
	if err != nil {
		return FileProviderConfig{}, fmt.Errorf("failed to marshal metadata config: %w", err)
	}

	if err := json.Unmarshal(configBytes, &config); err != nil {
		return FileProviderConfig{}, fmt.Errorf("failed to parse provider config: %w", err)
	}

	// Validate the extracted config
	if err := config.Validate(); err != nil {
		return FileProviderConfig{}, fmt.Errorf("invalid provider config: %w", err)
	}

	return config, nil
}

// signVote checks if the vote is good to sign and sets the vote signature.
// It may need to set the timestamp as well if the vote is otherwise the same as
// a previously signed vote (ie. we crashed after signing but before the vote hit the WAL).
// Extension signatures are always signed for non-nil precommits (even if the data is empty).
func (pv *CryptoProviderFile) signVote(chainID string, vote *cmtproto.Vote, signExtension bool) error {
	height, round, step := vote.Height, vote.Round, voteToStep(vote)

	lss := pv.lastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return err
	}

	signBytes := types.VoteSignBytes(chainID, vote)

	if signExtension {
		// Vote extensions are non-deterministic, so it is possible that an
		// application may have created a different extension. We therefore always
		// re-sign the vote extensions of precommits. For prevotes and nil
		// precommits, the extension signature will always be empty.
		// Even if the signed over data is empty, we still add the signature
		var extSig cp.Signature
		if vote.Type == types.PrecommitType && !types.ProtoBlockIDIsNil(&vote.BlockID) {
			extSignBytes := types.VoteExtensionSignBytes(chainID, vote)
			extSig, err = pv.GetSigner().Sign(extSignBytes, nil)
			if err != nil {
				return err
			}

			if extSig == nil {
				return errors.New("unexpected nil vote extension signature")
			}

		} else if len(vote.Extension) > 0 {
			return errors.New("unexpected vote extension - extensions are only allowed in non-nil precommits")
		}

		vote.ExtensionSignature = extSig.Bytes()
	}

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			vote.Signature = lss.Signature
		} else if timestamp, ok := checkVotesOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
			// Compares the canonicalized votes (i.e. without vote extensions
			// or vote extension signatures).
			vote.Timestamp = timestamp
			vote.Signature = lss.Signature
		} else {
			err = errors.New("conflicting data")
		}

		return err
	}

	// It passed the checks. Sign the vote
	sig, err := pv.GetSigner().Sign(signBytes, nil)
	if err != nil {
		return err
	}
	pv.saveSigned(height, round, step, signBytes, sig.Bytes())
	vote.Signature = sig.Bytes()

	return nil
}

// signProposal checks if the proposal is good to sign and sets the proposal signature.
// It may need to set the timestamp as well if the proposal is otherwise the same as
// a previously signed proposal ie. we crashed after signing but before the proposal hit the WAL).
func (pv *CryptoProviderFile) signProposal(chainID string, proposal *cmtproto.Proposal) error {
	height, round, step := proposal.Height, proposal.Round, stepPropose

	lss := pv.lastSignState

	sameHRS, err := lss.CheckHRS(height, round, step)
	if err != nil {
		return err
	}

	signBytes := types.ProposalSignBytes(chainID, proposal)

	// We might crash before writing to the wal,
	// causing us to try to re-sign for the same HRS.
	// If signbytes are the same, use the last signature.
	// If they only differ by timestamp, use last timestamp and signature
	// Otherwise, return error
	if sameHRS {
		if bytes.Equal(signBytes, lss.SignBytes) {
			proposal.Signature = lss.Signature
		} else if timestamp, ok := checkProposalsOnlyDifferByTimestamp(lss.SignBytes, signBytes); ok {
			proposal.Timestamp = timestamp
			proposal.Signature = lss.Signature
		} else {
			err = errors.New("conflicting data")
		}
		return err
	}

	// It passed the checks. Sign the proposal
	sig, err := pv.GetSigner().Sign(signBytes, nil)
	if err != nil {
		return err
	}
	pv.saveSigned(height, round, step, signBytes, sig.Bytes())
	proposal.Signature = sig.Bytes()
	return nil
}

// Persist height/round/step and signature.
func (pv *CryptoProviderFile) saveSigned(height int64, round int32, step int8,
	signBytes []byte, sig ByteSignature,
) {
	pv.lastSignState.Height = height
	pv.lastSignState.Round = round
	pv.lastSignState.Step = step
	pv.lastSignState.Signature = sig
	pv.lastSignState.SignBytes = signBytes
	pv.lastSignState.Save()
}

// -----------------------------------------------------------------------------------------

// Returns the timestamp from the lastSignBytes.
// Returns true if the only difference in the votes is their timestamp.
// Performs these checks on the canonical votes (excluding the vote extension
// and vote extension signatures).
func checkVotesOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastVote, newVote cmtproto.CanonicalVote
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastVote); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into vote: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newVote); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into vote: %v", err))
	}

	lastTime := lastVote.Timestamp
	// set the times to the same value and check equality
	now := cmttime.Now()
	lastVote.Timestamp = now
	newVote.Timestamp = now

	return lastTime, proto.Equal(&newVote, &lastVote)
}

// returns the timestamp from the lastSignBytes.
// returns true if the only difference in the proposals is their timestamp.
func checkProposalsOnlyDifferByTimestamp(lastSignBytes, newSignBytes []byte) (time.Time, bool) {
	var lastProposal, newProposal cmtproto.CanonicalProposal
	if err := protoio.UnmarshalDelimited(lastSignBytes, &lastProposal); err != nil {
		panic(fmt.Sprintf("LastSignBytes cannot be unmarshalled into proposal: %v", err))
	}
	if err := protoio.UnmarshalDelimited(newSignBytes, &newProposal); err != nil {
		panic(fmt.Sprintf("signBytes cannot be unmarshalled into proposal: %v", err))
	}

	lastTime := lastProposal.Timestamp
	// set the times to the same value and check equality
	now := cmttime.Now()
	lastProposal.Timestamp = now
	newProposal.Timestamp = now

	return lastTime, proto.Equal(&newProposal, &lastProposal)
}

// -----------------------------------------------------------------------------------------
