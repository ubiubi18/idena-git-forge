package idena

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

type ChainVerification struct {
	CheckpointMode string `json:"checkpointMode"`
	Actions        int    `json:"actions"`
}

// VerifyCheckpointInput authenticates a reducer input against the canonical
// chain exposed by a local Idena node. Action bytes are compared with the
// inline transaction payload, so an input cannot invent, omit, reorder, or
// replace a recognized action.
func (client *Client) VerifyCheckpointInput(
	ctx context.Context,
	input protocol.CheckpointInput,
	maxScan uint64,
) (ChainVerification, error) {
	if err := protocol.ValidateCheckpointInputPolicy(input); err != nil {
		return ChainVerification{}, err
	}
	if len(input.PreviousHeads) != 0 || len(input.PreviousDeletions) != 0 {
		return ChainVerification{}, errors.New("checkpoint input contains unproven prior repository state; replay authenticated checkpoint history instead")
	}
	if maxScan == 0 {
		maxScan = 250_000
	}
	checkpoint, err := client.BlockAt(ctx, input.Checkpoint.Height)
	if err != nil {
		return ChainVerification{}, err
	}
	if checkpoint.Height != input.Checkpoint.Height ||
		!strings.EqualFold(checkpoint.Hash, input.Checkpoint.Hash) ||
		!strings.EqualFold(checkpoint.Root, input.Checkpoint.StateRoot) ||
		checkpoint.Timestamp != input.Checkpoint.Time ||
		!hasFlag(checkpoint.Flags, protocol.CheckpointFlagName) {
		return ChainVerification{}, errors.New("checkpoint does not match the canonical ValidationFinished block")
	}

	mode, err := client.verifyCheckpointEpoch(ctx, input.Checkpoint, maxScan)
	if err != nil {
		return ChainVerification{}, err
	}

	scanner := Scanner{Client: client, MaxScan: maxScan}
	start, err := scanner.previousCheckpointHeight(ctx, checkpoint.Height)
	if err != nil {
		return ChainVerification{}, err
	}
	var previousHash string
	if start > 1 {
		previous, err := client.BlockAt(ctx, start-1)
		if err != nil {
			return ChainVerification{}, err
		}
		previousHash = previous.Hash
	}

	canonical := make([]protocol.OnChainAction, 0, len(input.Actions))
	for height := start; height <= checkpoint.Height; height++ {
		block, err := client.BlockAt(ctx, height)
		if err != nil {
			return ChainVerification{}, err
		}
		if block.Height != height {
			return ChainVerification{}, fmt.Errorf("node returned height %d for requested block %d", block.Height, height)
		}
		if previousHash != "" && !strings.EqualFold(block.ParentHash, previousHash) {
			return ChainVerification{}, fmt.Errorf("block %d does not extend the preceding canonical block", height)
		}
		previousHash = block.Hash
		for txIndex, txHash := range block.Transactions {
			transaction, err := client.Transaction(ctx, txHash)
			if err != nil {
				return ChainVerification{}, err
			}
			if !strings.EqualFold(transaction.Hash, txHash) || !strings.EqualFold(transaction.BlockHash, block.Hash) {
				return ChainVerification{}, fmt.Errorf("transaction %s is not bound to block %s", txHash, block.Hash)
			}
			if transaction.Type != ForgeActionTxType {
				continue
			}
			payload, err := decodeHex(transaction.Payload)
			if err != nil {
				return ChainVerification{}, fmt.Errorf("decode transaction %s payload: %w", txHash, err)
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
				action.ActionCID, err = content.CIDForBytes(actionBytes)
				if err != nil {
					return ChainVerification{}, err
				}
			}
			canonical = append(canonical, action)
		}
	}
	if len(canonical) != len(input.Actions) {
		return ChainVerification{}, fmt.Errorf("checkpoint input has %d actions, canonical chain has %d", len(input.Actions), len(canonical))
	}
	for index := range canonical {
		if !sameOnChainAction(canonical[index], input.Actions[index]) {
			return ChainVerification{}, fmt.Errorf("checkpoint action %d does not match canonical chain data", index)
		}
	}
	if err := protocol.VerifyIdentityProofCoverage(input); err != nil {
		return ChainVerification{}, fmt.Errorf("checkpoint identity coverage: %w", err)
	}
	return ChainVerification{CheckpointMode: mode, Actions: len(canonical)}, nil
}

// VerifyCheckpointReplica authenticates checkpoint chain data through another
// configured node view
// and requires this node to reproduce every archived identity membership proof
// needed by the checkpoint. The proof comparison ignores transport-source and
// optional state-epoch annotations, but not any committed proof bytes.
func (client *Client) VerifyCheckpointReplica(
	ctx context.Context,
	input protocol.CheckpointInput,
	maxScan uint64,
) (ChainVerification, error) {
	if err := protocol.ValidateCheckpointInputPolicy(input); err != nil {
		return ChainVerification{}, err
	}
	peerCheckpoint, err := client.EpochCheckpoint(ctx, input.Checkpoint.Height, input.Checkpoint.Hash)
	if err != nil {
		return ChainVerification{}, fmt.Errorf("retrieve peer checkpoint epoch proof: %w", err)
	}
	if peerCheckpoint.Height != input.Checkpoint.Height ||
		!strings.EqualFold(peerCheckpoint.BlockHash, input.Checkpoint.Hash) ||
		!strings.EqualFold(peerCheckpoint.StateRoot, input.Checkpoint.StateRoot) ||
		peerCheckpoint.Epoch != input.Checkpoint.Epoch+1 {
		return ChainVerification{}, errors.New("peer checkpoint epoch response differs from archived checkpoint")
	}
	if err := protocol.VerifyEpochProof(peerCheckpoint.EpochProof, input.Checkpoint.StateRoot, peerCheckpoint.Epoch); err != nil {
		return ChainVerification{}, fmt.Errorf("verify peer checkpoint epoch proof: %w", err)
	}
	if !reflect.DeepEqual(peerCheckpoint.EpochProof, input.Checkpoint.EpochProof) {
		return ChainVerification{}, errors.New("peer checkpoint epoch proof differs from archived proof")
	}
	verification, err := client.VerifyCheckpointInput(ctx, input, maxScan)
	if err != nil {
		return ChainVerification{}, err
	}
	for _, address := range protocol.ExpectedIdentityProofAuthors(input) {
		archived := input.Proofs[address]
		if err := protocol.VerifyIdentityProof(archived, input.Checkpoint.StateRoot); err != nil {
			return ChainVerification{}, fmt.Errorf("verify archived identity proof for %s: %w", address, err)
		}
		peer, err := client.IdentityProof(
			ctx,
			input.Checkpoint.Epoch,
			input.Checkpoint.Height,
			input.Checkpoint.Hash,
			input.Checkpoint.StateRoot,
			archived.Address,
		)
		if err != nil {
			return ChainVerification{}, fmt.Errorf("retrieve peer identity proof for %s: %w", address, err)
		}
		if err := protocol.VerifyIdentityProof(peer, input.Checkpoint.StateRoot); err != nil {
			return ChainVerification{}, fmt.Errorf("verify peer identity proof for %s: %w", address, err)
		}
		if !sameIdentityProof(archived, peer) {
			return ChainVerification{}, fmt.Errorf("peer identity proof for %s differs from archived proof", address)
		}
	}
	return verification, nil
}

func sameIdentityProof(left, right protocol.IdentityProof) bool {
	left.Source = ""
	right.Source = ""
	left.StateEpoch = 0
	right.StateEpoch = 0
	return reflect.DeepEqual(left, right)
}

func (client *Client) verifyCheckpointEpoch(
	ctx context.Context,
	checkpoint protocol.CheckpointBlock,
	maxScan uint64,
) (string, error) {
	if checkpoint.Epoch == ^uint16(0) {
		return "", errors.New("checkpoint epoch cannot have a post-transition epoch")
	}
	if checkpoint.EpochProof.Value != "" || checkpoint.EpochProof.Leaf.Key != "" || len(checkpoint.EpochProof.Path) != 0 {
		if err := protocol.VerifyEpochProof(checkpoint.EpochProof, checkpoint.StateRoot, checkpoint.Epoch+1); err != nil {
			return "", fmt.Errorf("authenticate archived checkpoint epoch: %w", err)
		}
		return "archived-state-proof", nil
	}
	committed, err := client.EpochCheckpoint(ctx, checkpoint.Height, checkpoint.Hash)
	if err == nil {
		if committed.Height != checkpoint.Height ||
			!strings.EqualFold(committed.BlockHash, checkpoint.Hash) ||
			!strings.EqualFold(committed.StateRoot, checkpoint.StateRoot) ||
			committed.Epoch != checkpoint.Epoch+1 {
			return "", errors.New("historical checkpoint epoch proof does not match reducer input")
		}
		if committed.EpochProof.Value != "" || committed.EpochProof.Leaf.Key != "" || len(committed.EpochProof.Path) != 0 {
			if err := protocol.VerifyEpochProof(committed.EpochProof, checkpoint.StateRoot, committed.Epoch); err != nil {
				return "", fmt.Errorf("authenticate historical checkpoint epoch proof: %w", err)
			}
		}
		return "historical-rpc-proof", nil
	}
	if !rpcMethodUnavailable(err) {
		return "", fmt.Errorf("authenticate checkpoint epoch: %w", err)
	}

	// Compatibility path for an unpatched node: this is sound only while the
	// checkpoint is still the latest ValidationFinished block.
	scanner := Scanner{Client: client, MaxScan: maxScan}
	latest, latestErr := scanner.latestCheckpoint(ctx)
	if latestErr != nil {
		return "", fmt.Errorf("historical checkpoint RPC unavailable: %v; latest checkpoint lookup failed: %w", err, latestErr)
	}
	if latest.Height != checkpoint.Height || !strings.EqualFold(latest.Hash, checkpoint.Hash) {
		return "", errors.New("historical checkpoint verification requires the dna_epochCheckpoint node extension")
	}
	epoch, liveErr := client.Epoch(ctx)
	if liveErr != nil {
		return "", fmt.Errorf("historical checkpoint RPC unavailable: %v; live epoch lookup failed: %w", err, liveErr)
	}
	if epoch.Epoch != checkpoint.Epoch+1 {
		return "", errors.New("live node epoch does not match the latest checkpoint")
	}
	return "latest-checkpoint-fallback", nil
}

func sameOnChainAction(left, right protocol.OnChainAction) bool {
	return left.Height == right.Height &&
		strings.EqualFold(left.BlockHash, right.BlockHash) &&
		strings.EqualFold(left.TxHash, right.TxHash) &&
		left.TxIndex == right.TxIndex &&
		left.TxType == right.TxType &&
		strings.EqualFold(left.TxSender, right.TxSender) &&
		strings.EqualFold(left.TxRecipient, right.TxRecipient) &&
		left.TxEpoch == right.TxEpoch &&
		left.ActionCID == right.ActionCID &&
		bytes.Equal(left.ActionBytes, right.ActionBytes)
}

func rpcMethodUnavailable(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "-32601") || strings.Contains(message, "method not found")
}
