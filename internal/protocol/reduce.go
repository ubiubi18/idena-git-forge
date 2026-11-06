package protocol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"idena-git-forge/internal/canonicaljson"
	"idena-git-forge/internal/content"
)

type FastForwardVerifier func(bundleCID, base, head string) error

// CheckpointAuthenticator must authenticate the checkpoint header and the
// complete ordered action list against one canonical Idena chain view.
type CheckpointAuthenticator func(context.Context, CheckpointInput) error

// AuthenticatedCheckpointInput is a capability produced only after a
// CheckpointAuthenticator accepts the raw input. Its seal also prevents the
// caller from mutating shared slices or maps between authentication and use.
// The zero value is deliberately unusable.
type AuthenticatedCheckpointInput struct {
	input         CheckpointInput
	seal          [sha256.Size]byte
	authenticated bool
}

// AuthenticateCheckpointInput turns caller-supplied JSON into reducer input
// only after the supplied canonical-chain verifier accepts it.
func AuthenticateCheckpointInput(
	ctx context.Context,
	input CheckpointInput,
	authenticate CheckpointAuthenticator,
) (AuthenticatedCheckpointInput, error) {
	if err := ValidateCheckpointInputPolicy(input); err != nil {
		return AuthenticatedCheckpointInput{}, err
	}
	if len(input.PreviousHeads) != 0 || len(input.PreviousDeletions) != 0 {
		return AuthenticatedCheckpointInput{}, errors.New("serialized checkpoint input cannot supply prior repository state; use authenticated replay")
	}
	if authenticate == nil {
		return AuthenticatedCheckpointInput{}, errors.New("canonical checkpoint authenticator is required")
	}
	if err := authenticate(ctx, input); err != nil {
		return AuthenticatedCheckpointInput{}, fmt.Errorf("authenticate canonical checkpoint: %w", err)
	}
	if err := VerifyIdentityProofCoverage(input); err != nil {
		return AuthenticatedCheckpointInput{}, fmt.Errorf("authenticate checkpoint identity coverage: %w", err)
	}
	seal, err := checkpointInputSeal(input)
	if err != nil {
		return AuthenticatedCheckpointInput{}, err
	}
	return AuthenticatedCheckpointInput{input: input, seal: seal, authenticated: true}, nil
}

// ExpectedIdentityProofAuthors derives the complete identity-proof query set
// from canonical signed action bytes. It deliberately does not use the proof
// map: a proof source must not gain governance weight by omitting an author.
func ExpectedIdentityProofAuthors(input CheckpointInput) []string {
	authors := make(map[string]struct{})
	for _, item := range input.Actions {
		envelope, err := ParseEnvelope(item.ActionBytes)
		if err != nil || item.TxType != "send" || item.ActionCID == "" {
			continue
		}
		calculatedCID, err := content.CIDForBytes(item.ActionBytes)
		if err != nil || calculatedCID != item.ActionCID {
			continue
		}
		sender, err := normalizeAddressProtocol(item.TxSender)
		if err != nil || sender != envelope.Author {
			continue
		}
		recipient, err := normalizeAddressProtocol(item.TxRecipient)
		if err != nil || recipient != sender {
			continue
		}
		if item.TxEpoch != input.Checkpoint.Epoch || envelope.Epoch != item.TxEpoch {
			continue
		}
		authors[sender] = struct{}{}
	}
	result := make([]string, 0, len(authors))
	for author := range authors {
		result = append(result, author)
	}
	sort.Strings(result)
	return result
}

// VerifyIdentityProofCoverage requires one root-authenticated membership proof
// for every canonical signed author. Until the node protocol supplies portable
// non-membership proofs, an unavailable proof must leave settlement pending;
// unauthenticated absence errors are never accepted as governance evidence.
func VerifyIdentityProofCoverage(input CheckpointInput) error {
	proofs := make(map[string]IdentityProof, len(input.Proofs))
	for key, proof := range input.Proofs {
		normalizedKey, err := normalizeAddressProtocol(key)
		if err != nil {
			return fmt.Errorf("invalid identity proof map key %q", key)
		}
		if _, exists := proofs[normalizedKey]; exists {
			return fmt.Errorf("duplicate identity proof for %s", normalizedKey)
		}
		proofAddress, err := normalizeAddressProtocol(proof.Address)
		if err != nil || proofAddress != normalizedKey {
			return fmt.Errorf("identity proof map key %s differs from proof address", normalizedKey)
		}
		if proof.Height != input.Checkpoint.Height || !strings.EqualFold(proof.BlockHash, input.Checkpoint.Hash) {
			return fmt.Errorf("identity proof for %s is for another block", normalizedKey)
		}
		if proof.Epoch != input.Checkpoint.Epoch || (proof.StateEpoch != 0 && proof.StateEpoch != input.Checkpoint.Epoch+1) {
			return fmt.Errorf("identity proof for %s is for another epoch", normalizedKey)
		}
		if err := VerifyIdentityProof(proof, input.Checkpoint.StateRoot); err != nil {
			return fmt.Errorf("verify identity proof for %s: %w", normalizedKey, err)
		}
		proofs[normalizedKey] = proof
	}
	for _, author := range ExpectedIdentityProofAuthors(input) {
		if _, exists := proofs[author]; !exists {
			return fmt.Errorf("canonical action author %s has no authenticated identity membership proof", author)
		}
	}
	return nil
}

func (input AuthenticatedCheckpointInput) verifiedInput() (CheckpointInput, error) {
	if !input.authenticated {
		return CheckpointInput{}, errors.New("checkpoint input was not authenticated against a canonical Idena chain")
	}
	seal, err := checkpointInputSeal(input.input)
	if err != nil {
		return CheckpointInput{}, err
	}
	if seal != input.seal {
		return CheckpointInput{}, errors.New("checkpoint input changed after canonical-chain authentication")
	}
	return input.input, nil
}

func checkpointInputSeal(input CheckpointInput) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(input)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("seal checkpoint input: %w", err)
	}
	return sha256.Sum256(encoded), nil
}

type admittedAction struct {
	order       OnChainAction
	envelope    Envelope
	actionID    string
	proof       IdentityProof
	stake       *big.Int
	weight      *big.Int
	payload     any
	sequenceKey string
}

// RecognizedAction passed every chain-, identity-, binding-, payload-, and
// quota-level check that is independent of local Radicle content. Content
// availability and Git/Radicle validity are deliberately checked later so
// two clients cannot assign different quota slots because their caches differ.
type RecognizedAction struct {
	Order    OnChainAction
	Envelope Envelope
	ActionID string
	Proof    IdentityProof
	Payload  any
	Subject  RadicleSubject
	stake    *big.Int
	weight   *big.Int
	sequence string
}

// ReduceReplay applies an already ordered, gap-free checkpoint history from an
// empty state and carries verified repository heads and deletions forward.
// Serialized inputs cannot seed or override that state.
func ReduceReplay(inputs []AuthenticatedCheckpointInput, verifyFastForward FastForwardVerifier, verifyBinding BindingVerifier, verifyRadicle RadicleVerifier) ([]CheckpointResult, error) {
	if len(inputs) == 0 {
		return nil, errors.New("checkpoint replay requires at least one input")
	}
	ordered := make([]CheckpointInput, len(inputs))
	for index := range inputs {
		verified, err := inputs[index].verifiedInput()
		if err != nil {
			return nil, fmt.Errorf("checkpoint replay input %d: %w", index, err)
		}
		ordered[index] = verified
	}
	if ordered[0].Checkpoint.Epoch != MainnetActivationEpoch {
		return nil, fmt.Errorf("checkpoint replay must start at mainnet activation epoch %d", MainnetActivationEpoch)
	}
	results := make([]CheckpointResult, 0, len(ordered))
	heads := make(map[string]string)
	deletions := make(map[string]RepositoryDeletion)
	var previousEpoch uint16
	for index := range ordered {
		if index > 0 && (previousEpoch == ^uint16(0) || ordered[index].Checkpoint.Epoch != previousEpoch+1) {
			return nil, errors.New("checkpoint replay must be ordered and contain every consecutive epoch")
		}
		ordered[index].PreviousHeads = cloneHeads(heads)
		ordered[index].PreviousDeletions = cloneDeletions(deletions)
		result, err := reduceDeterministic(ordered[index], verifyFastForward, verifyBinding, verifyRadicle)
		if err != nil {
			return nil, err
		}
		for _, repository := range result.Repositories {
			heads[repository.Repository] = repository.CanonicalHead
			if repository.Deleted {
				if _, exists := deletions[repository.Repository]; !exists {
					deletions[repository.Repository] = RepositoryDeletion{
						Epoch:           ordered[index].Checkpoint.Epoch,
						PruneAfterEpoch: repository.PruneAfterEpoch,
					}
				}
			}
		}
		results = append(results, *result)
		previousEpoch = ordered[index].Checkpoint.Epoch
	}
	return results, nil
}

// Reduce accepts only a sealed input that already passed canonical-chain
// authentication. Callers cannot reduce deserialized checkpoint JSON directly.
func Reduce(input AuthenticatedCheckpointInput, verifyFastForward FastForwardVerifier, verifyBinding BindingVerifier, verifyRadicle RadicleVerifier) (*CheckpointResult, error) {
	verified, err := input.verifiedInput()
	if err != nil {
		return nil, err
	}
	if verified.Checkpoint.Epoch != MainnetActivationEpoch {
		return nil, fmt.Errorf("single-checkpoint reduction is valid only at mainnet activation epoch %d; replay authenticated history for later epochs", MainnetActivationEpoch)
	}
	return reduceDeterministic(verified, verifyFastForward, verifyBinding, verifyRadicle)
}

// ReduceFixture intentionally bypasses canonical-chain authentication. It is
// only for explicitly labelled local UI fixtures and reducer unit tests; no
// checkpoint produced through this function is valid protocol evidence.
func ReduceFixture(input CheckpointInput, verifyFastForward FastForwardVerifier, verifyBinding BindingVerifier, verifyRadicle RadicleVerifier) (*CheckpointResult, error) {
	if input.ReducerPolicy == "" {
		input.ReducerPolicy = CurrentReducerPolicy()
	}
	return reduceDeterministic(input, verifyFastForward, verifyBinding, verifyRadicle)
}

func reduceDeterministic(input CheckpointInput, verifyFastForward FastForwardVerifier, verifyBinding BindingVerifier, verifyRadicle RadicleVerifier) (*CheckpointResult, error) {
	if err := ValidateCheckpointInputPolicy(input); err != nil {
		return nil, err
	}
	if input.Checkpoint.Epoch == 0 {
		return nil, errors.New("checkpoint epoch must be positive")
	}
	if input.Checkpoint.Epoch > 0xffff-2 {
		return nil, errors.New("checkpoint epoch cannot be extended by the deletion grace period")
	}
	if input.Checkpoint.Height == 0 {
		return nil, errors.New("checkpoint height must be positive")
	}
	if _, err := decodeFixedHex(input.Checkpoint.Hash, 32, "checkpoint hash"); err != nil {
		return nil, err
	}
	if _, err := decodeFixedHex(input.Checkpoint.StateRoot, 32, "checkpoint state root"); err != nil {
		return nil, err
	}

	result := &CheckpointResult{
		ReducerPolicy: input.ReducerPolicy,
		Checkpoint:    input.Checkpoint,
		Repositories:  []RepositoryResult{},
		Rejected:      []Rejection{},
	}
	admitted, rejected, err := admitActions(input, verifyBinding, verifyRadicle)
	if err != nil {
		return nil, err
	}
	result.Rejected = append(result.Rejected, rejected...)
	current := admitted

	repositories := make(map[string]string)
	for name, head := range input.PreviousHeads {
		normalized, err := normalizeRepository(name)
		if err != nil {
			return nil, err
		}
		if !validGitObject(head) {
			return nil, fmt.Errorf("invalid previous head for %s", normalized)
		}
		repositories[normalized] = strings.ToLower(head)
	}
	for _, action := range current {
		if action.envelope.Kind != KindRepository {
			continue
		}
		if _, exists := repositories[action.envelope.Repository]; exists {
			result.Rejected = append(result.Rejected, Rejection{
				ActionID: action.actionID,
				TxHash:   action.order.TxHash,
				Reason:   "repository already has a canonical history",
			})
			continue
		}
		payload := action.payload.(RepositoryPayload)
		repositories[action.envelope.Repository] = strings.ToLower(payload.Head)
	}

	type openPR struct {
		repository string
		payload    PullRequestPayload
		revision   string
		author     string
		actionID   string
		actionCID  string
		order      OnChainAction
	}
	pullRequests := make(map[string]openPR)
	mergeRequests := make(map[string]admittedAction)
	votes := make(map[string]map[string]admittedAction)
	for _, action := range current {
		switch action.envelope.Kind {
		case KindPullRequest:
			payload := action.payload.(PullRequestPayload)
			revision, err := Revision(payload)
			if err != nil {
				return nil, err
			}
			key := prKey(action.envelope.Repository, payload.Patch, revision)
			if _, exists := pullRequests[key]; exists {
				result.Rejected = append(result.Rejected, Rejection{
					ActionID: action.actionID,
					TxHash:   action.order.TxHash,
					Reason:   "duplicate PR revision",
				})
				continue
			}
			pullRequests[key] = openPR{
				repository: action.envelope.Repository,
				payload:    payload,
				revision:   revision,
				author:     action.envelope.Author,
				actionID:   action.actionID,
				actionCID:  action.order.ActionCID,
				order:      action.order,
			}
		case KindMergeRequest:
			payload := action.payload.(MergeRequestPayload)
			key := prKey(action.envelope.Repository, payload.Patch, payload.Revision)
			if _, exists := mergeRequests[key]; !exists {
				mergeRequests[key] = action
			}
		case KindVote:
			payload := action.payload.(VotePayload)
			key := prKey(action.envelope.Repository, payload.Patch, payload.Revision)
			if votes[key] == nil {
				votes[key] = make(map[string]admittedAction)
			}
			// current is already in canonical order, so assignment leaves the
			// latest vote from each identity.
			votes[key][action.envelope.Author] = action
		}
	}

	threshold, _ := new(big.Int).SetString(DecisionStakeThreshold, 10)
	prsByRepo := make(map[string][]*PRResult)
	for key, pr := range pullRequests {
		prResult := &PRResult{
			Repository:       pr.repository,
			PR:               pr.payload.Patch,
			Revision:         pr.revision,
			Title:            pr.payload.Title,
			Author:           pr.payload.ActorDID,
			IdenaAuthor:      pr.order.TxSender,
			Base:             strings.ToLower(pr.payload.Base),
			Head:             strings.ToLower(pr.payload.Head),
			DiffCID:          pr.payload.Diff,
			BundleCID:        pr.payload.Bundle,
			ActionCID:        pr.actionCID,
			MergeRequested:   false,
			Approved:         false,
			Eligible:         false,
			Ballots:          []Ballot{},
			CombinedStake:    "0",
			ApprovalStake:    "0",
			RejectionStake:   "0",
			ApprovalWeight:   "0",
			RejectionWeight:  "0",
			CombinedWeight:   "0",
			NetWeight:        "0",
			DeleteRepository: pr.payload.DeleteRepository,
		}

		combinedStake := new(big.Int)
		approvalStake := new(big.Int)
		rejectionStake := new(big.Int)
		approvalWeight := new(big.Int)
		rejectionWeight := new(big.Int)
		approvalVoters := 0
		voters := make([]string, 0, len(votes[key]))
		for voter := range votes[key] {
			voters = append(voters, voter)
		}
		sort.Strings(voters)
		for _, voter := range voters {
			action := votes[key][voter]
			payload := action.payload.(VotePayload)
			ballot := Ballot{
				Voter:    voter,
				State:    IdentityStateName(action.proof.State),
				Decision: payload.Decision,
				Stake:    action.stake.String(),
				Weight:   action.weight.String(),
				ActionID: action.actionID,
				TxHash:   action.order.TxHash,
			}
			prResult.Ballots = append(prResult.Ballots, ballot)
			combinedStake.Add(combinedStake, action.stake)
			if payload.Decision == DecisionApprove {
				approvalVoters++
				approvalStake.Add(approvalStake, action.stake)
				approvalWeight.Add(approvalWeight, action.weight)
			} else {
				rejectionStake.Add(rejectionStake, action.stake)
				rejectionWeight.Add(rejectionWeight, action.weight)
			}
		}
		prResult.UniqueVoters = len(voters)
		prResult.ApprovalVoters = approvalVoters
		prResult.IdentityMajority = approvalVoters*2 > len(voters)
		prResult.CombinedStake = combinedStake.String()
		prResult.ApprovalStake = approvalStake.String()
		prResult.RejectionStake = rejectionStake.String()
		prResult.ApprovalWeight = approvalWeight.String()
		prResult.RejectionWeight = rejectionWeight.String()
		combinedWeight := new(big.Int).Add(approvalWeight, rejectionWeight)
		prResult.CombinedWeight = combinedWeight.String()
		prResult.NetWeight = new(big.Int).Sub(approvalWeight, rejectionWeight).String()
		prResult.StakeMajority = combinedWeight.Sign() > 0 &&
			new(big.Int).Lsh(approvalWeight, 1).Cmp(combinedWeight) > 0

		if mergeRequest, exists := mergeRequests[key]; exists {
			prResult.MergeRequested = true
			prResult.MergeRequestTx = mergeRequest.order.TxHash
			prResult.MergeRequestOrder = canonicalOrderValue(mergeRequest.order)
		}
		gatePassed := len(voters) >= MinDecisionVoters &&
			approvalVoters >= MinApprovalVoters &&
			combinedStake.Cmp(threshold) >= 0 &&
			prResult.StakeMajority
		prResult.Approved = gatePassed

		switch {
		case !prResult.MergeRequested:
			prResult.Reason = "no merge request for this exact revision"
		case len(voters) < MinDecisionVoters:
			prResult.Reason = "fewer than three eligible voters"
		case combinedStake.Cmp(threshold) < 0:
			prResult.Reason = "combined stake below 500000 iDNA"
		case approvalVoters < MinApprovalVoters:
			prResult.Reason = "fewer than two approval identities"
		case !prResult.StakeMajority:
			prResult.Reason = "approval weight is not a majority of combined stake"
		default:
			prResult.Reason = "ballot passed"
			prResult.Eligible = true
		}

		if prResult.Eligible {
			previousHead, exists := repositories[pr.repository]
			if !exists {
				prResult.Eligible = false
				prResult.Reason = "repository has no canonical genesis"
			} else if previousHead != pr.payload.Base {
				prResult.Eligible = false
				prResult.Reason = "PR base is not the canonical repository head"
			} else if verifyFastForward == nil {
				prResult.Eligible = false
				prResult.Reason = "cannot verify Git ancestry without the PR bundle"
			} else if err := verifyFastForward(pr.payload.Bundle, pr.payload.Base, pr.payload.Head); err != nil {
				if errors.Is(err, ErrContentUnavailable) {
					return nil, fmt.Errorf("%w: verify fast-forward for PR %s: %v", ErrContentUnavailable, pr.payload.Patch, err)
				}
				prResult.Eligible = false
				prResult.Reason = "PR does not fast-forward: " + err.Error()
			}
		}
		prsByRepo[pr.repository] = append(prsByRepo[pr.repository], prResult)
	}

	repositoryNames := make([]string, 0, len(repositories))
	for name := range repositories {
		repositoryNames = append(repositoryNames, name)
	}
	for name := range prsByRepo {
		if _, exists := repositories[name]; !exists {
			repositories[name] = ""
		}
	}
	for name := range repositories {
		if _, exists := prsByRepo[name]; !exists {
			prsByRepo[name] = []*PRResult{}
		}
	}
	repositoryNames = repositoryNames[:0]
	for name := range repositories {
		repositoryNames = append(repositoryNames, name)
	}
	sort.Strings(repositoryNames)

	for _, repository := range repositoryNames {
		previousHead := repositories[repository]
		candidates := prsByRepo[repository]
		previousDeletion, alreadyDeleted := input.PreviousDeletions[repository]
		if alreadyDeleted {
			for _, candidate := range candidates {
				candidate.Eligible = false
				candidate.Reason = "repository was deleted at an earlier checkpoint"
			}
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			return betterPR(candidates[i], candidates[j])
		})
		var winner *PRResult
		for _, candidate := range candidates {
			if candidate.Eligible {
				winner = candidate
				break
			}
		}
		canonicalHead := previousHead
		winnerID := ""
		winnerRevision := ""
		if winner != nil {
			canonicalHead = winner.Head
			winnerID = winner.PR
			winnerRevision = winner.Revision
		}
		repositoryResult := RepositoryResult{
			Repository:     repository,
			PreviousHead:   previousHead,
			CanonicalHead:  canonicalHead,
			Winner:         winnerID,
			WinnerRevision: winnerRevision,
			PRs:            dereferencePRs(candidates),
		}
		if alreadyDeleted {
			repositoryResult.Deleted = true
			repositoryResult.PruneAfterEpoch = previousDeletion.PruneAfterEpoch
		} else if winner != nil && winner.DeleteRepository {
			repositoryResult.Deleted = true
			repositoryResult.PruneAfterEpoch = input.Checkpoint.Epoch + 2
		}
		result.Repositories = append(result.Repositories, repositoryResult)
	}

	digestInput := input
	digestInput.Checkpoint = input.Checkpoint
	canonical, err := canonicalDigestInput(digestInput)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(canonical)
	result.InputDigest = "sha256:" + hex.EncodeToString(digest[:])
	return result, nil
}

// RecognizeActions applies the one canonical action-accounting boundary used
// by scanning, restore, and reduction. A recognized action consumes one of the
// author's twenty epoch slots even if its referenced Radicle content is later
// unavailable or invalid.
func RecognizeActions(input CheckpointInput, verifyBinding BindingVerifier) ([]RecognizedAction, []Rejection, error) {
	if err := ValidateCheckpointInputPolicy(input); err != nil {
		return nil, nil, err
	}
	ordered := append([]OnChainAction(nil), input.Actions...)
	for index := range ordered {
		envelope, err := ParseEnvelope(ordered[index].ActionBytes)
		if err != nil {
			ordered[index].Action = nil
			continue
		}
		ordered[index].Action = envelope
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		leftID := ""
		rightID := ""
		if ordered[i].Action != nil {
			leftID = ordered[i].Action.ID()
		}
		if ordered[j].Action != nil {
			rightID = ordered[j].Action.ID()
		}
		return canonicalOrderKey(ordered[i], leftID) < canonicalOrderKey(ordered[j], rightID)
	})

	var recognized []RecognizedAction
	var rejected []Rejection
	quotaCount := make(map[string]int)
	seenActionIDs := make(map[string]struct{})
	for _, item := range ordered {
		envelope := item.Action
		if envelope == nil {
			rejected = append(rejected, Rejection{TxHash: item.TxHash, Reason: "invalid or non-canonical action object"})
			continue
		}
		actionID := envelope.ID()
		if item.TxType != "send" {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "transaction is not an inline Idena forge action"})
			continue
		}
		calculatedCID, err := content.CIDForBytes(item.ActionBytes)
		if err != nil || calculatedCID != item.ActionCID {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "action CID does not match action bytes"})
			continue
		}
		sender, err := normalizeAddressProtocol(item.TxSender)
		if err != nil {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "invalid transaction sender"})
			continue
		}
		if sender != envelope.Author {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "transaction sender differs from signed author"})
			continue
		}
		recipient, err := normalizeAddressProtocol(item.TxRecipient)
		if err != nil || recipient != sender {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "forge action transaction is not a self-send"})
			continue
		}
		if verifyBinding == nil {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "Radicle/Idena binding verifier is not configured"})
			continue
		}
		if err := verifyBinding(*envelope); err != nil {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "invalid Radicle/Idena binding: " + err.Error()})
			continue
		}
		if item.TxEpoch != input.Checkpoint.Epoch || envelope.Epoch != item.TxEpoch {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "action epoch does not match settlement epoch"})
			continue
		}
		proof, exists := input.Proofs[envelope.Author]
		if !exists {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "checkpoint identity proof is missing"})
			continue
		}
		if proof.Height != input.Checkpoint.Height || !strings.EqualFold(proof.BlockHash, input.Checkpoint.Hash) {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "checkpoint identity proof is for another block"})
			continue
		}
		if proof.Epoch != input.Checkpoint.Epoch || (proof.StateEpoch != 0 && proof.StateEpoch != input.Checkpoint.Epoch+1) {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "checkpoint identity proof is for another epoch"})
			continue
		}
		if err := VerifyIdentityProof(proof, input.Checkpoint.StateRoot); err != nil {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "invalid checkpoint identity proof: " + err.Error()})
			continue
		}
		proofAddress, err := normalizeAddressProtocol(proof.Address)
		if err != nil || proofAddress != envelope.Author || !IsEligibleIdentityState(proof.State) {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "author is not a valid Newbie, Verified or Human identity"})
			continue
		}
		stake, ok := new(big.Int).SetString(proof.Stake, 10)
		if !ok {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: "invalid checkpoint stake"})
			continue
		}
		payload, err := envelope.DecodePayload()
		if err != nil {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: err.Error()})
			continue
		}
		subject, err := RadicleSubjectFor(*envelope, payload)
		if err != nil {
			rejected = append(rejected, Rejection{ActionID: actionID, TxHash: item.TxHash, Reason: err.Error()})
			continue
		}
		if _, exists := seenActionIDs[actionID]; exists {
			rejected = append(rejected, Rejection{
				ActionID: actionID,
				TxHash:   item.TxHash,
				Reason:   "duplicate action object",
			})
			continue
		}
		seenActionIDs[actionID] = struct{}{}
		quotaCount[envelope.Author]++
		if quotaCount[envelope.Author] > MaxActionsPerEpoch {
			rejected = append(rejected, Rejection{
				ActionID: actionID,
				TxHash:   item.TxHash,
				Reason:   "per-epoch action quota exceeded",
			})
			continue
		}
		recognized = append(recognized, RecognizedAction{
			Order:    item,
			Envelope: *envelope,
			ActionID: actionID,
			Proof:    proof,
			Payload:  payload,
			Subject:  subject,
			stake:    stake,
			weight:   StakeWeight(stake),
			sequence: canonicalOrderKey(item, actionID),
		})
	}
	return recognized, rejected, nil
}

func admitActions(input CheckpointInput, verifyBinding BindingVerifier, verifyRadicle RadicleVerifier) ([]admittedAction, []Rejection, error) {
	recognized, rejected, err := RecognizeActions(input, verifyBinding)
	if err != nil {
		return nil, nil, err
	}
	admitted := make([]admittedAction, 0, len(recognized))
	for _, action := range recognized {
		if verifyRadicle == nil {
			rejected = append(rejected, Rejection{ActionID: action.ActionID, TxHash: action.Order.TxHash, Reason: "Radicle action verifier is not configured"})
			continue
		}
		if err := verifyRadicle(action.Subject); err != nil {
			if errors.Is(err, ErrContentUnavailable) {
				return nil, nil, fmt.Errorf("%w: action %s: %v", ErrContentUnavailable, action.ActionID, err)
			}
			rejected = append(rejected, Rejection{ActionID: action.ActionID, TxHash: action.Order.TxHash, Reason: "invalid Radicle action: " + err.Error()})
			continue
		}
		admitted = append(admitted, admittedAction{
			order:       action.Order,
			envelope:    action.Envelope,
			actionID:    action.ActionID,
			proof:       action.Proof,
			stake:       action.stake,
			weight:      action.weight,
			payload:     action.Payload,
			sequenceKey: action.sequence,
		})
	}
	return admitted, rejected, nil
}

func betterPR(left, right *PRResult) bool {
	if left.Eligible != right.Eligible {
		return left.Eligible
	}
	// Distinct-identity counts are only participation and deliberation floors.
	// They must not outrank checkpoint stake when two passing revisions
	// compete, because identities are not intended to provide Sybil weight.
	leftNet, _ := new(big.Int).SetString(left.NetWeight, 10)
	rightNet, _ := new(big.Int).SetString(right.NetWeight, 10)
	if comparison := leftNet.Cmp(rightNet); comparison != 0 {
		return comparison > 0
	}
	leftApproval, _ := new(big.Int).SetString(left.ApprovalWeight, 10)
	rightApproval, _ := new(big.Int).SetString(right.ApprovalWeight, 10)
	if comparison := leftApproval.Cmp(rightApproval); comparison != 0 {
		return comparison > 0
	}
	leftStake, _ := new(big.Int).SetString(left.CombinedStake, 10)
	rightStake, _ := new(big.Int).SetString(right.CombinedStake, 10)
	if comparison := leftStake.Cmp(rightStake); comparison != 0 {
		return comparison > 0
	}
	if left.MergeRequestOrder != right.MergeRequestOrder {
		return left.MergeRequestOrder < right.MergeRequestOrder
	}
	if left.Revision != right.Revision {
		return left.Revision < right.Revision
	}
	return left.PR < right.PR
}

func canonicalOrderKey(action OnChainAction, actionID string) string {
	return fmt.Sprintf("%020d:%010d:%s:%s", action.Height, action.TxIndex, strings.ToLower(action.TxHash), actionID)
}

func canonicalOrderValue(action OnChainAction) uint64 {
	if action.Height > 0xffff_ffff {
		return ^uint64(0)
	}
	return (action.Height << 32) | uint64(action.TxIndex)
}

func prKey(repository, pr, revision string) string {
	return repository + "\x00" + pr + "\x00" + revision
}

func normalizeRepository(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !radicleRIDPattern.MatchString(value) {
		return "", errors.New("invalid Radicle repository identifier")
	}
	return value, nil
}

func RadicleSubjectFor(envelope Envelope, payload any) (RadicleSubject, error) {
	subject := RadicleSubject{
		RID:      envelope.Repository,
		ActorDID: envelope.RadicleDID,
		Kind:     envelope.Kind,
	}
	switch typed := payload.(type) {
	case RepositoryPayload:
		subject.BundleCID = typed.Bundle
		subject.Head = typed.Head
		subject.CobType = "xyz.radicle.id"
	case CommitPayload:
		subject.BundleCID = typed.Bundle
		subject.Head = typed.Head
		subject.Ref = typed.Ref
	case IssuePayload:
		subject.CobType = "xyz.radicle.issue"
		subject.CobID = typed.Issue
		subject.ActionOID = typed.Action
		subject.BundleCID = typed.Bundle
	case PullRequestPayload:
		subject.BundleCID = typed.Bundle
		subject.CobType = "xyz.radicle.patch"
		subject.CobID = typed.Patch
		subject.ActionOID = typed.Revision
		subject.PatchID = typed.Patch
		subject.RevisionID = typed.Revision
		subject.Base = typed.Base
		subject.Head = typed.Head
	case CommentPayload:
		if typed.TargetType == "issue" {
			subject.CobType = "xyz.radicle.issue"
		} else {
			subject.CobType = "xyz.radicle.patch"
		}
		subject.CobID = typed.TargetID
		subject.ActionOID = typed.Comment
		subject.BundleCID = typed.Bundle
	case VotePayload:
		subject.CobType = "xyz.radicle.patch"
		subject.CobID = typed.Patch
		subject.PatchID = typed.Patch
		subject.RevisionID = typed.Revision
		subject.ReviewID = typed.Review
		subject.ActionOID = typed.ActionOID
		subject.Verdict = typed.Decision
		subject.BundleCID = typed.Bundle
	case MergeRequestPayload:
		subject.CobType = "xyz.radicle.patch"
		subject.CobID = typed.Patch
		subject.PatchID = typed.Patch
		subject.RevisionID = typed.Revision
		subject.ActionOID = typed.LabelAction
		subject.Label = typed.Label
		subject.BundleCID = typed.Bundle
	default:
		return RadicleSubject{}, errors.New("unknown Radicle action subject")
	}
	return subject, nil
}

func validGitObject(value string) bool {
	return gitObjectPattern.MatchString(value)
}

func dereferencePRs(values []*PRResult) []PRResult {
	result := make([]PRResult, 0, len(values))
	for _, value := range values {
		result = append(result, *value)
	}
	return result
}

func canonicalDigestInput(input CheckpointInput) ([]byte, error) {
	normalized := input
	if input.Proofs != nil {
		normalized.Proofs = make(map[string]IdentityProof, len(input.Proofs))
		for address, proof := range input.Proofs {
			proof.Source = ""
			normalized.Proofs[address] = proof
		}
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func cloneHeads(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for name, head := range input {
		output[name] = head
	}
	return output
}

func cloneDeletions(input map[string]RepositoryDeletion) map[string]RepositoryDeletion {
	output := make(map[string]RepositoryDeletion, len(input))
	for name, deletion := range input {
		output[name] = deletion
	}
	return output
}
