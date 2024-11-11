package file

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	cmtproto "github.com/cometbft/cometbft/api/cometbft/types/v1"
	"github.com/cometbft/cometbft/internal/tempfile"
	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/types"
)

const (
	stepNone      int8 = 0 // Used to distinguish the initial state
	stepPropose   int8 = 1
	stepPrevote   int8 = 2
	stepPrecommit int8 = 3
)

// A vote is either stepPrevote or stepPrecommit.
func voteToStep(vote *cmtproto.Vote) int8 {
	switch vote.Type {
	case types.PrevoteType:
		return stepPrevote
	case types.PrecommitType:
		return stepPrecommit
	default:
		panic(fmt.Sprintf("Unknown vote type: %v", vote.Type))
	}
}

// LastSignState stores the file crypto provider state
type LastSignState struct {
	Height    int64             `json:"height"`
	Round     int32             `json:"round"`
	Step      int8              `json:"step"`
	Signature []byte            `json:"signature,omitempty"`
	SignBytes cmtbytes.HexBytes `json:"signbytes,omitempty"`

	filePath string
}

func (lss *LastSignState) reset() {
	lss.Height = 0
	lss.Round = 0
	lss.Step = 0
	lss.Signature = nil
	lss.SignBytes = nil
}

// CheckHRS checks the given height, round, step (HRS) against that of the
// FilePVLastSignState. It returns an error if the arguments constitute a regression,
// or if they match but the SignBytes are empty.
// The returned boolean indicates whether the last Signature should be reused -
// it returns true if the HRS matches the arguments and the SignBytes are not empty (indicating
// we have already signed for this HRS, and can reuse the existing signature).
// It panics if the HRS matches the arguments, there's a SignBytes, but no Signature.
func (lss *LastSignState) CheckHRS(height int64, round int32, step int8) (bool, error) {
	if lss.Height > height {
		return false, fmt.Errorf("height regression. Got %v, last height %v", height, lss.Height)
	}

	if lss.Height != height {
		return false, nil
	}

	if lss.Round > round {
		return false, fmt.Errorf("round regression at height %v. Got %v, last round %v", height, round, lss.Round)
	}

	if lss.Round != round {
		return false, nil
	}

	if lss.Step > step {
		return false, fmt.Errorf(
			"step regression at height %v round %v. Got %v, last step %v",
			height,
			round,
			step,
			lss.Step,
		)
	}

	if lss.Step < step {
		return false, nil
	}

	if lss.SignBytes == nil {
		return false, errors.New("no SignBytes found")
	}

	if lss.Signature == nil {
		panic("pv: Signature is nil but SignBytes is not!")
	}
	return true, nil
}

// Save persists the FilePvLastSignState to its filePath.
func (lss *LastSignState) Save() {
	outFile := lss.filePath
	if outFile == "" {
		panic("cannot save FilePVLastSignState: filePath not set")
	}
	// Create state file if it doesn't exist
	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		dir := filepath.Dir(outFile)
		if err := os.MkdirAll(dir, 0700); err != nil {
			panic(fmt.Errorf("failed to create directory %s: %w", dir, err))
		}
		if _, err := os.Create(outFile); err != nil {
			panic(fmt.Errorf("failed to create file %s: %w", outFile, err))
		}
	}

	// Marshal state
	jsonBytes, err := cmtjson.MarshalIndent(lss, "", "  ")
	if err != nil {
		panic(err)
	}
	err = tempfile.WriteFileAtomic(outFile, jsonBytes, 0o600)
	if err != nil {
		panic(err)
	}
}

// Load loads the LastSignState from its filePath.
// Returns an error if the file cannot be read or if the contents cannot be unmarshaled.
func (lss *LastSignState) Load() error {
	if lss.filePath == "" {
		return errors.New("cannot load LastSignState: filePath not set")
	}

	stateJSONBytes, err := os.ReadFile(lss.filePath)
	if err != nil {
		return fmt.Errorf("error reading state file: %w", err)
	}

	err = cmtjson.Unmarshal(stateJSONBytes, lss)
	if err != nil {
		return fmt.Errorf("error unmarshaling state: %w", err)
	}

	return nil
}
