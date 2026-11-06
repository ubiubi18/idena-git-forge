package idena

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

type Scanner struct {
	Client          *Client
	ProofSource     IdentityProofSource
	Store           *content.Store
	BindingVerifier protocol.BindingVerifier
	MaxScan         uint64
}

type ScanResult struct {
	Input       protocol.CheckpointInput
	Complete    bool
	MissingCIDs []string
}

func (scanner *Scanner) ScanLatest(
	ctx context.Context,
) (*ScanResult, error) {
	if scanner.Client == nil {
		return nil, errors.New("Idena RPC client is required")
	}
	if scanner.Store == nil {
		return nil, errors.New("content store is required")
	}
	if scanner.BindingVerifier == nil {
		return nil, errors.New("Radicle/Idena binding verifier is required")
	}
	if scanner.MaxScan == 0 {
		scanner.MaxScan = 250_000
	}
	checkpoint, err := scanner.latestCheckpoint(ctx)
	if err != nil {
		return nil, err
	}
	stateEpoch, epochProof, err := scanner.checkpointEpoch(ctx, checkpoint)
	if err != nil {
		return nil, err
	}
	if stateEpoch == 0 {
		return nil, errors.New("cannot settle before the first epoch transition")
	}
	settlementEpoch := stateEpoch - 1
	start, err := scanner.previousCheckpointHeight(ctx, checkpoint.Height)
	if err != nil {
		return nil, err
	}

	result := &ScanResult{}
	result.Input = protocol.CheckpointInput{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint: protocol.CheckpointBlock{
			Epoch:      settlementEpoch,
			Height:     checkpoint.Height,
			Hash:       checkpoint.Hash,
			StateRoot:  checkpoint.Root,
			Time:       checkpoint.Timestamp,
			EpochProof: epochProof,
		},
		Actions: []protocol.OnChainAction{},
		Proofs:  make(map[string]protocol.IdentityProof),
	}
	if settlementEpoch > 0xffff-2 {
		return nil, errors.New("epoch cannot be extended by the pinning lease")
	}
	pinUntil := settlementEpoch + 2

	for height := start; height <= checkpoint.Height; height++ {
		block, err := scanner.Client.BlockAt(ctx, height)
		if err != nil {
			return nil, err
		}
		for txIndex, txHash := range block.Transactions {
			transaction, err := scanner.Client.Transaction(ctx, txHash)
			if err != nil {
				return nil, err
			}
			if !strings.EqualFold(transaction.Hash, txHash) || !strings.EqualFold(transaction.BlockHash, block.Hash) {
				return nil, fmt.Errorf("transaction %s is not bound to block %s", txHash, block.Hash)
			}
			if transaction.Type != ForgeActionTxType {
				continue
			}
			payload, err := decodeHex(transaction.Payload)
			if err != nil {
				return nil, fmt.Errorf("decode transaction %s payload: %w", txHash, err)
			}
			actionBytes, recognized, payloadErr := DecodeForgeActionPayload(payload)
			if !recognized {
				continue
			}
			action := protocol.OnChainAction{
				Height:      height,
				BlockHash:   block.Hash,
				TxHash:      transaction.Hash,
				TxIndex:     uint32(txIndex),
				TxType:      transaction.Type,
				TxSender:    transaction.From,
				TxRecipient: transaction.To,
				TxEpoch:     transaction.Epoch,
				ActionBytes: actionBytes,
			}
			if payloadErr == nil {
				contentCID, err := content.CIDForBytes(actionBytes)
				if err != nil {
					return nil, err
				}
				action.ActionCID = contentCID
			}
			result.Input.Actions = append(result.Input.Actions, action)
		}
	}
	// Action discovery is complete from canonical block payloads. Every signed
	// canonical author must have authenticated checkpoint membership evidence;
	// a proof-source absence error cannot silently remove a voter.
	for _, author := range protocol.ExpectedIdentityProofAuthors(result.Input) {
		proofSource := scanner.ProofSource
		if proofSource == nil {
			proofSource = scanner.Client
		}
		proof, err := proofSource.IdentityProof(ctx, settlementEpoch, checkpoint.Height, checkpoint.Hash, checkpoint.Root, author)
		if err != nil {
			return nil, fmt.Errorf("identity proof for %s: %w", author, err)
		}
		if err := protocol.VerifyIdentityProof(proof, checkpoint.Root); err != nil {
			return nil, fmt.Errorf("verify identity proof for %s: %w", author, err)
		}
		result.Input.Proofs[author] = proof
	}
	if err := protocol.VerifyIdentityProofCoverage(result.Input); err != nil {
		return nil, err
	}

	recognized, _, err := protocol.RecognizeActions(result.Input, scanner.BindingVerifier)
	if err != nil {
		return nil, err
	}
	checkedContent := make(map[string]struct{})
	for _, action := range recognized {
		storedCID, err := scanner.Store.Put(action.Order.ActionBytes, pinUntil)
		if err != nil {
			return nil, err
		}
		if storedCID != action.Order.ActionCID {
			return nil, fmt.Errorf("stored action CID %s differs from canonical CID %s", storedCID, action.Order.ActionCID)
		}
		for _, contentCID := range ContentCIDs(action.Payload) {
			if _, checked := checkedContent[contentCID]; checked {
				continue
			}
			checkedContent[contentCID] = struct{}{}
			if scanner.Store.Has(contentCID) {
				if err := scanner.Store.Pin(contentCID, pinUntil); err != nil {
					return nil, err
				}
				continue
			}
			data, err := scanner.Client.IPFSGet(ctx, contentCID)
			if err != nil || len(data) == 0 {
				result.MissingCIDs = append(result.MissingCIDs, contentCID)
				continue
			}
			calculated, err := content.CIDForBytes(data)
			if err != nil || calculated != contentCID {
				result.MissingCIDs = append(result.MissingCIDs, contentCID)
				continue
			}
			if _, err := scanner.Store.Put(data, pinUntil); err != nil {
				return nil, err
			}
		}
	}
	result.Complete = len(result.MissingCIDs) == 0
	return result, nil
}

func (scanner *Scanner) checkpointEpoch(ctx context.Context, checkpoint *Block) (uint16, protocol.StateValueProof, error) {
	proof, err := scanner.Client.EpochCheckpoint(ctx, checkpoint.Height, checkpoint.Hash)
	if err == nil {
		if proof.Height != checkpoint.Height || !strings.EqualFold(proof.BlockHash, checkpoint.Hash) ||
			!strings.EqualFold(proof.StateRoot, checkpoint.Root) {
			return 0, protocol.StateValueProof{}, errors.New("node checkpoint proof differs from canonical block")
		}
		if err := protocol.VerifyEpochProof(proof.EpochProof, checkpoint.Root, proof.Epoch); err != nil {
			return 0, protocol.StateValueProof{}, fmt.Errorf("verify checkpoint epoch proof: %w", err)
		}
		return proof.Epoch, proof.EpochProof, nil
	}

	if !rpcMethodUnavailable(err) {
		return 0, protocol.StateValueProof{}, fmt.Errorf("authenticate checkpoint epoch: %w", err)
	}

	// Stock nodes do not yet expose historical state epochs. For the latest
	// ValidationFinished block only, the live epoch is exactly the committed
	// post-transition epoch. Saved historical checkpoints require the read-only
	// dna_epochCheckpoint extension.
	epoch, liveErr := scanner.Client.Epoch(ctx)
	if liveErr != nil {
		return 0, protocol.StateValueProof{}, fmt.Errorf("checkpoint epoch RPC unavailable: %v; live epoch fallback failed: %w", err, liveErr)
	}
	if epoch.Epoch == 0 {
		return 0, protocol.StateValueProof{}, errors.New("node returned epoch zero for a finalized checkpoint")
	}
	return epoch.Epoch, protocol.StateValueProof{}, nil
}

func ContentCIDs(payload any) []string {
	switch typed := payload.(type) {
	case protocol.RepositoryPayload:
		return []string{typed.Bundle}
	case protocol.CommitPayload:
		return []string{typed.Bundle}
	case protocol.IssuePayload:
		return []string{typed.Bundle}
	case protocol.PullRequestPayload:
		return []string{typed.Bundle, typed.Diff}
	case protocol.CommentPayload:
		return []string{typed.Bundle}
	case protocol.VotePayload:
		return []string{typed.Bundle}
	case protocol.MergeRequestPayload:
		return []string{typed.Bundle}
	default:
		return nil
	}
}

func (scanner *Scanner) latestCheckpoint(ctx context.Context) (*Block, error) {
	head, err := scanner.Client.LastBlock(ctx)
	if err != nil {
		return nil, err
	}
	lowest := uint64(0)
	if head.Height > scanner.MaxScan {
		lowest = head.Height - scanner.MaxScan
	}
	for height := head.Height; height > lowest; height-- {
		block, err := scanner.Client.BlockAt(ctx, height)
		if err != nil {
			return nil, err
		}
		if hasFlag(block.Flags, protocol.CheckpointFlagName) {
			return block, nil
		}
	}
	return nil, errors.New("no ValidationFinished checkpoint in the scan window")
}

func (scanner *Scanner) previousCheckpointHeight(ctx context.Context, checkpointHeight uint64) (uint64, error) {
	if checkpointHeight <= 1 {
		return 1, nil
	}
	lowest := uint64(1)
	if checkpointHeight-1 > scanner.MaxScan {
		lowest = checkpointHeight - 1 - scanner.MaxScan
	}
	for height := checkpointHeight - 1; height >= lowest; height-- {
		block, err := scanner.Client.BlockAt(ctx, height)
		if err != nil {
			return 0, err
		}
		if hasFlag(block.Flags, protocol.CheckpointFlagName) {
			return height + 1, nil
		}
		if height == 1 {
			break
		}
	}
	if lowest == 1 {
		return 1, nil
	}
	return 0, errors.New("previous checkpoint is outside the configured scan window")
}

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if flag == want {
			return true
		}
	}
	return false
}
