package protocol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"idena-git-forge/internal/content"
)

func TestReduceMergesOnlyWhenGateAndApprovalPass(t *testing.T) {
	checkpoint := testCheckpoint(12)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 250_000, 8},
		{voterB, 150_000, 3},
		{voterC, 100_000, 7},
	})
	checkpoint.StateRoot = stateRoot

	pr := testPullRequest(t, voterA, 12, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-1")
	revision, err := Revision(pr.payload)
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 64)
	base := strings.Repeat("b", 64)
	pr.payload.Base = base
	pr.payload.Head = head
	pr = resignPullRequest(t, voterA, 12, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", pr.payload)
	revision, _ = Revision(pr.payload)

	actions := []OnChainAction{
		makeOnChain(t, pr.envelope, 1, voterA, 12),
		makeOnChain(t, voteEnvelope(t, voterA, 12, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-1", revision, DecisionApprove, 1), 2, voterA, 12),
		makeOnChain(t, voteEnvelope(t, voterB, 12, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-1", revision, DecisionApprove, 3), 3, voterB, 12),
		makeOnChain(t, voteEnvelope(t, voterC, 12, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-1", revision, DecisionReject, 4), 4, voterC, 12),
		makeOnChain(t, mergeEnvelope(t, voterA, 12, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-1", revision, 5), 5, voterA, 12),
	}
	actions[0].ActionBytes = pr.envelopeBytes
	actions[0].ActionCID, _ = content.CIDForBytes(pr.envelopeBytes)

	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint:    checkpoint,
		Actions:       actions,
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	repo := result.Repositories[0]
	if repo.Winner != pr.payload.Patch || repo.WinnerRevision != revision || repo.CanonicalHead != head {
		t.Fatalf("unexpected merge result: %+v\nrejections: %+v", repo, result.Rejected)
	}
}

func TestBuilderNeedNotVoteWhenAnyEligibleIdentitiesReachStakeQuorum(t *testing.T) {
	checkpoint := testCheckpoint(13)
	builder := testKey(t)
	whale := testKey(t)
	secondApprover := testKey(t)
	rejecter := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{builder, 1, 8},
		{whale, 600_000, 8},
		{secondApprover, 1, 7},
		{rejecter, 1, 3},
	})
	checkpoint.StateRoot = stateRoot

	const repository = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
	base := strings.Repeat("1", 64)
	head := strings.Repeat("2", 64)
	payload := testPRPayload("permissionless-voters", base, head)
	revision, err := Revision(payload)
	if err != nil {
		t.Fatal(err)
	}
	pr := mustEnvelope(t, KindPullRequest, repository, checkpoint.Epoch, builder, nonceHex(1), payload)
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, builder, checkpoint.Epoch),
			makeOnChain(t, voteEnvelope(t, whale, checkpoint.Epoch, repository, "permissionless-voters", revision, DecisionApprove, 2), 2, whale, checkpoint.Epoch),
			makeOnChain(t, voteEnvelope(t, secondApprover, checkpoint.Epoch, repository, "permissionless-voters", revision, DecisionApprove, 3), 3, secondApprover, checkpoint.Epoch),
			makeOnChain(t, voteEnvelope(t, rejecter, checkpoint.Epoch, repository, "permissionless-voters", revision, DecisionReject, 4), 4, rejecter, checkpoint.Epoch),
			makeOnChain(t, mergeEnvelope(t, builder, checkpoint.Epoch, repository, "permissionless-voters", revision, 5), 5, builder, checkpoint.Epoch),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{repository: base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	repo := result.Repositories[0]
	if repo.Winner != payload.Patch || repo.WinnerRevision != revision {
		t.Fatalf("non-builder quorum did not select the exact revision: %+v", repo)
	}
	prResult := repo.PRs[0]
	if prResult.UniqueVoters != 3 || prResult.ApprovalVoters != 2 || !prResult.StakeMajority {
		t.Fatalf("unexpected permissionless voter quorum: %+v", prResult)
	}
	builderAddress := AddressFromPrivateKey(builder)
	for _, ballot := range prResult.Ballots {
		if ballot.Voter == builderAddress {
			t.Fatal("builder unexpectedly counted as a voter")
		}
	}
}

func TestWinnerOrderingUsesStakeBeforeIdentityCount(t *testing.T) {
	checkpoint := testCheckpoint(14)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	voterD := testKey(t)
	voterE := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 400_000, 8},
		{voterB, 400_000, 8},
		{voterC, 1, 7},
		{voterD, 1, 7},
		{voterE, 100_000, 3},
	})
	checkpoint.StateRoot = stateRoot

	const repository = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
	base := strings.Repeat("3", 64)
	countHead := strings.Repeat("4", 64)
	stakeHead := strings.Repeat("5", 64)
	countPayload := testPRPayload("identity-count-heavy", base, countHead)
	stakePayload := testPRPayload("stake-heavy", base, stakeHead)
	countRevision, _ := Revision(countPayload)
	stakeRevision, _ := Revision(stakePayload)
	countPR := mustEnvelope(t, KindPullRequest, repository, checkpoint.Epoch, voterA, nonceHex(1), countPayload)
	stakePR := mustEnvelope(t, KindPullRequest, repository, checkpoint.Epoch, voterA, nonceHex(2), stakePayload)

	actions := []OnChainAction{
		makeOnChain(t, countPR, 1, voterA, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterB, checkpoint.Epoch, repository, "identity-count-heavy", countRevision, DecisionApprove, 3), 2, voterB, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterC, checkpoint.Epoch, repository, "identity-count-heavy", countRevision, DecisionApprove, 4), 3, voterC, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterD, checkpoint.Epoch, repository, "identity-count-heavy", countRevision, DecisionApprove, 5), 4, voterD, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterE, checkpoint.Epoch, repository, "identity-count-heavy", countRevision, DecisionApprove, 6), 5, voterE, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterA, checkpoint.Epoch, repository, "identity-count-heavy", countRevision, DecisionReject, 7), 6, voterA, checkpoint.Epoch),
		makeOnChain(t, mergeEnvelope(t, voterA, checkpoint.Epoch, repository, "identity-count-heavy", countRevision, 8), 7, voterA, checkpoint.Epoch),
		makeOnChain(t, stakePR, 8, voterA, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterA, checkpoint.Epoch, repository, "stake-heavy", stakeRevision, DecisionApprove, 9), 9, voterA, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterB, checkpoint.Epoch, repository, "stake-heavy", stakeRevision, DecisionApprove, 10), 10, voterB, checkpoint.Epoch),
		makeOnChain(t, voteEnvelope(t, voterE, checkpoint.Epoch, repository, "stake-heavy", stakeRevision, DecisionReject, 11), 11, voterE, checkpoint.Epoch),
		makeOnChain(t, mergeEnvelope(t, voterA, checkpoint.Epoch, repository, "stake-heavy", stakeRevision, 12), 12, voterA, checkpoint.Epoch),
	}
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint:    checkpoint,
		Actions:       actions,
		Proofs:        proofs,
		PreviousHeads: map[string]string{repository: base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	repo := result.Repositories[0]
	if repo.Winner != stakePayload.Patch || repo.WinnerRevision != stakeRevision || repo.CanonicalHead != stakeHead {
		t.Fatalf("identity count outranked stake authority: %+v", repo)
	}
	if repo.PRs[0].ApprovalVoters >= repo.PRs[1].ApprovalVoters {
		t.Fatalf("fixture did not give the losing revision more approval identities: %+v", repo.PRs)
	}
}

func TestWinnerOrderingUsesPatchIDAsFinalTieBreak(t *testing.T) {
	left := &PRResult{
		PR: "patch-a", Revision: "same-revision", Eligible: true,
		NetWeight: "10", ApprovalWeight: "20", CombinedStake: "30", MergeRequestOrder: 40,
	}
	right := &PRResult{
		PR: "patch-b", Revision: "same-revision", Eligible: true,
		NetWeight: "10", ApprovalWeight: "20", CombinedStake: "30", MergeRequestOrder: 40,
	}
	if !betterPR(left, right) {
		t.Fatal("lexicographically smaller patch ID did not win the final tie-break")
	}
	if betterPR(right, left) {
		t.Fatal("candidate ordering is not antisymmetric for distinct patch IDs")
	}
}

func TestReduceRequiresCanonicalCheckpointAuthentication(t *testing.T) {
	raw := CheckpointInput{
		ReducerPolicy: CurrentReducerPolicy(),
		Checkpoint:    testCheckpoint(11),
		Actions:       []OnChainAction{{TxHash: "original"}},
	}
	if _, err := Reduce(AuthenticatedCheckpointInput{}, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("zero-value authentication capability was accepted: %v", err)
	}

	called := false
	if _, err := AuthenticateCheckpointInput(context.Background(), raw, func(context.Context, CheckpointInput) error {
		called = true
		return errors.New("checkpoint is absent from the canonical chain")
	}); err == nil || !strings.Contains(err.Error(), "absent from the canonical chain") {
		t.Fatalf("fabricated checkpoint reached the reducer: %v", err)
	}
	if !called {
		t.Fatal("canonical checkpoint authenticator was not called")
	}

	authenticated, err := AuthenticateCheckpointInput(context.Background(), raw, func(context.Context, CheckpointInput) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw.Actions[0].TxHash = "mutated"
	if _, err := Reduce(authenticated, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "changed after") {
		t.Fatalf("post-authentication mutation was accepted: %v", err)
	}

	legitimate := CheckpointInput{ReducerPolicy: CurrentReducerPolicy(), Checkpoint: testCheckpoint(MainnetActivationEpoch)}
	authenticated, err = AuthenticateCheckpointInput(context.Background(), legitimate, func(context.Context, CheckpointInput) error {
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reduce(authenticated, nil, nil, nil); err != nil {
		t.Fatalf("authenticated checkpoint was rejected: %v", err)
	}
}

func TestAuthenticatedCheckpointRejectsCallerSuppliedPriorState(t *testing.T) {
	input := CheckpointInput{
		ReducerPolicy: CurrentReducerPolicy(),
		Checkpoint:    testCheckpoint(MainnetActivationEpoch),
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": strings.Repeat("a", 40)},
	}
	called := false
	_, err := AuthenticateCheckpointInput(context.Background(), input, func(context.Context, CheckpointInput) error {
		called = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "cannot supply prior repository state") {
		t.Fatalf("caller-supplied prior state was accepted: %v", err)
	}
	if called {
		t.Fatal("canonical-chain verifier ran after untrusted prior state was detected")
	}
}

func TestAuthenticatedCheckpointRejectsMissingCanonicalVoterProof(t *testing.T) {
	checkpoint := testCheckpoint(23)
	voters := []*ecdsa.PrivateKey{testKey(t), testKey(t), testKey(t), testKey(t)}
	identities := make([]testIdentity, 0, len(voters))
	for _, voter := range voters {
		identities = append(identities, testIdentity{voter, 125_000, 8})
	}
	proofs, stateRoot := testProofSet(t, checkpoint, identities)
	checkpoint.StateRoot = stateRoot

	const repository = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
	actions := make([]OnChainAction, 0, len(voters))
	for index, voter := range voters {
		decision := DecisionApprove
		if index >= 2 {
			decision = DecisionReject
		}
		envelope := voteEnvelope(t, voter, checkpoint.Epoch, repository, "proof-coverage", strings.Repeat("a", 64), decision, index+1)
		actions = append(actions, makeOnChain(t, envelope, uint32(index+1), voter, checkpoint.Epoch))
	}
	omitted := AddressFromPrivateKey(voters[3])
	delete(proofs, omitted)

	_, err := AuthenticateCheckpointInput(context.Background(), CheckpointInput{
		ReducerPolicy: CurrentReducerPolicy(),
		Checkpoint:    checkpoint,
		Actions:       actions,
		Proofs:        proofs,
	}, func(context.Context, CheckpointInput) error { return nil })
	if err == nil || !strings.Contains(err.Error(), omitted) || !strings.Contains(err.Error(), "no authenticated identity membership proof") {
		t.Fatalf("canonical 2-2 voter set was allowed to become 2-1 by proof omission: %v", err)
	}
}

func TestCheckpointResultOmitsReplicaLocalAvailability(t *testing.T) {
	encoded, err := json.Marshal(CheckpointResult{
		Repositories: []RepositoryResult{{
			Repository: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
			PRs: []PRResult{{
				PR:           "patch",
				Availability: ContentAvailability{Action: true, Bundle: true, Diff: true},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"availability"`)) {
		t.Fatalf("replica-local availability leaked into canonical checkpoint JSON: %s", encoded)
	}
}

func TestTwoApprovalsPassWithOneRejectionAndRevisionIsExact(t *testing.T) {
	checkpoint := testCheckpoint(15)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 200_000, 8},
		{voterB, 200_000, 7},
		{voterC, 100_000, 3},
	})
	checkpoint.StateRoot = stateRoot

	base := strings.Repeat("1", 64)
	head := strings.Repeat("2", 64)
	payload := testPRPayload("pr-2", base, head)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 15, voterA, "10000000000000000000000000000002", payload)
	revision, _ := Revision(payload)
	otherRevision := strings.Repeat("0", 64)

	actions := []OnChainAction{
		makeOnChain(t, pr, 1, voterA, 15),
		makeOnChain(t, voteEnvelope(t, voterA, 15, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-2", revision, DecisionApprove, 1), 2, voterA, 15),
		makeOnChain(t, voteEnvelope(t, voterB, 15, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-2", revision, DecisionApprove, 3), 3, voterB, 15),
		makeOnChain(t, voteEnvelope(t, voterC, 15, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-2", revision, DecisionReject, 4), 4, voterC, 15),
		makeOnChain(t, voteEnvelope(t, voterB, 15, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-2", otherRevision, DecisionApprove, 5), 5, voterB, 15),
		makeOnChain(t, mergeEnvelope(t, voterA, 15, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-2", revision, 6), 6, voterA, 15),
	}
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint:    checkpoint,
		Actions:       actions,
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) == 0 || len(result.Repositories[0].PRs) == 0 {
		t.Fatalf("missing PR result; rejections: %+v", result.Rejected)
	}
	prResult := result.Repositories[0].PRs[0]
	if !prResult.IdentityMajority || !prResult.Approved || !prResult.Eligible {
		t.Fatalf("two approvals must pass with one rejection: %+v", prResult)
	}
	if prResult.UniqueVoters != 3 || prResult.ApprovalVoters != 2 {
		t.Fatalf("exact revision voters = %d", prResult.UniqueVoters)
	}
}

func TestTwoApprovalsFailWithoutCombinedStakeMajority(t *testing.T) {
	checkpoint := testCheckpoint(151)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 100_000, 8},
		{voterB, 100_000, 7},
		{voterC, 300_000, 3},
	})
	checkpoint.StateRoot = stateRoot

	base := strings.Repeat("a", 64)
	head := strings.Repeat("b", 64)
	payload := testPRPayload("pr-stake-majority", base, head)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 151, voterA, "10000000000000000000000000000151", payload)
	revision, err := Revision(payload)
	if err != nil {
		t.Fatal(err)
	}

	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, voterA, 151),
			makeOnChain(t, voteEnvelope(t, voterA, 151, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-stake-majority", revision, DecisionApprove, 1), 2, voterA, 151),
			makeOnChain(t, voteEnvelope(t, voterB, 151, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-stake-majority", revision, DecisionApprove, 2), 3, voterB, 151),
			makeOnChain(t, voteEnvelope(t, voterC, 151, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-stake-majority", revision, DecisionReject, 3), 4, voterC, 151),
			makeOnChain(t, mergeEnvelope(t, voterA, 151, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-stake-majority", revision, 4), 5, voterA, 151),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	prResult := result.Repositories[0].PRs[0]
	if prResult.StakeMajority || prResult.Approved || prResult.Eligible {
		t.Fatalf("identity-majority approval passed without weighted stake majority: %+v", prResult)
	}
	if prResult.Reason != "approval weight is not a majority of combined stake" {
		t.Fatalf("unexpected rejection reason: %q", prResult.Reason)
	}
}

func TestTwoOfFourApprovalsPassWithWeightedMajority(t *testing.T) {
	checkpoint := testCheckpoint(152)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	voterD := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 400_000, 8},
		{voterB, 400_000, 7},
		{voterC, 1, 3},
		{voterD, 1, 8},
	})
	checkpoint.StateRoot = stateRoot

	base := strings.Repeat("c", 64)
	head := strings.Repeat("d", 64)
	payload := testPRPayload("pr-identity-majority", base, head)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 152, voterA, "10000000000000000000000000000152", payload)
	revision, err := Revision(payload)
	if err != nil {
		t.Fatal(err)
	}

	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, voterA, 152),
			makeOnChain(t, voteEnvelope(t, voterA, 152, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-identity-majority", revision, DecisionApprove, 1), 2, voterA, 152),
			makeOnChain(t, voteEnvelope(t, voterB, 152, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-identity-majority", revision, DecisionApprove, 2), 3, voterB, 152),
			makeOnChain(t, voteEnvelope(t, voterC, 152, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-identity-majority", revision, DecisionReject, 3), 4, voterC, 152),
			makeOnChain(t, voteEnvelope(t, voterD, 152, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-identity-majority", revision, DecisionReject, 4), 5, voterD, 152),
			makeOnChain(t, mergeEnvelope(t, voterA, 152, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-identity-majority", revision, 5), 6, voterA, 152),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	prResult := result.Repositories[0].PRs[0]
	if prResult.IdentityMajority {
		t.Fatalf("two approvals among four identities unexpectedly formed a majority: %+v", prResult)
	}
	if !prResult.StakeMajority {
		t.Fatalf("test requires an approval stake-weight majority: %+v", prResult)
	}
	if !prResult.Approved || !prResult.Eligible || prResult.Reason != "ballot passed" {
		t.Fatalf("two approvals with weighted majority did not pass: %+v", prResult)
	}
}

func TestOneMillionStakeApprovalStillRequiresSecondApproval(t *testing.T) {
	checkpoint := testCheckpoint(153)
	whale := testKey(t)
	rejectorA := testKey(t)
	rejectorB := testKey(t)
	rejectorC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{whale, 1_000_000, 8},
		{rejectorA, 10_000, 7},
		{rejectorB, 10_000, 3},
		{rejectorC, 10_000, 8},
	})
	checkpoint.StateRoot = stateRoot

	base := strings.Repeat("e", 64)
	head := strings.Repeat("f", 64)
	payload := testPRPayload("pr-one-million-approval", base, head)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 153, whale, "10000000000000000000000000000153", payload)
	revision, err := Revision(payload)
	if err != nil {
		t.Fatal(err)
	}

	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, whale, 153),
			makeOnChain(t, voteEnvelope(t, whale, 153, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-million-approval", revision, DecisionApprove, 1), 2, whale, 153),
			makeOnChain(t, voteEnvelope(t, rejectorA, 153, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-million-approval", revision, DecisionReject, 2), 3, rejectorA, 153),
			makeOnChain(t, voteEnvelope(t, rejectorB, 153, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-million-approval", revision, DecisionReject, 3), 4, rejectorB, 153),
			makeOnChain(t, voteEnvelope(t, rejectorC, 153, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-million-approval", revision, DecisionReject, 4), 5, rejectorC, 153),
			makeOnChain(t, mergeEnvelope(t, whale, 153, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-million-approval", revision, 5), 6, whale, 153),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	prResult := result.Repositories[0].PRs[0]
	if !prResult.StakeMajority {
		t.Fatalf("test requires the one-million-iDNA approval to hold the weighted majority: %+v", prResult)
	}
	if prResult.UniqueVoters != 4 || prResult.ApprovalVoters != 1 || prResult.IdentityMajority {
		t.Fatalf("unexpected identity counts: %+v", prResult)
	}
	if prResult.Approved || prResult.Eligible || prResult.Reason != "fewer than two approval identities" {
		t.Fatalf("one approval bypassed the two-approval floor: %+v", prResult)
	}
}

func TestTwoVotersAndCombinedStakeGate(t *testing.T) {
	checkpoint := testCheckpoint(16)
	whale := testKey(t)
	oneVoterProof := testProof(checkpoint, whale, 700_000, 8)
	checkpoint.StateRoot = oneVoterProof.StateRoot
	base := strings.Repeat("3", 64)
	head := strings.Repeat("4", 64)
	payload := testPRPayload("pr-gate", base, head)
	revision, _ := Revision(payload)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 16, whale, "10000000000000000000000000000003", payload)
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint:    checkpoint,
		Actions:       []OnChainAction{makeOnChain(t, pr, 1, whale, 16), makeOnChain(t, voteEnvelope(t, whale, 16, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-gate", revision, DecisionApprove, 1), 2, whale, 16), makeOnChain(t, mergeEnvelope(t, whale, 16, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-gate", revision, 3), 3, whale, 16)},
		Proofs:        map[string]IdentityProof{oneVoterProof.Address: oneVoterProof},
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Repositories[0].Winner != "" {
		t.Fatal("a single voter must not pass even with more than 500000 iDNA")
	}
}

func TestThreeVotersRequireTwoApprovals(t *testing.T) {
	checkpoint := testCheckpoint(17)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 200_000, 8},
		{voterB, 200_000, 7},
		{voterC, 100_000, 3},
	})
	checkpoint.StateRoot = stateRoot
	base := strings.Repeat("1", 64)
	head := strings.Repeat("2", 64)
	payload := testPRPayload("pr-one-approval", base, head)
	revision, _ := Revision(payload)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 17, voterA, "10000000000000000000000000000011", payload)
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, voterA, 17),
			makeOnChain(t, voteEnvelope(t, voterA, 17, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-approval", revision, DecisionApprove, 1), 2, voterA, 17),
			makeOnChain(t, voteEnvelope(t, voterB, 17, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-approval", revision, DecisionReject, 2), 3, voterB, 17),
			makeOnChain(t, voteEnvelope(t, voterC, 17, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-approval", revision, DecisionReject, 3), 4, voterC, 17),
			makeOnChain(t, mergeEnvelope(t, voterA, 17, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-one-approval", revision, 4), 5, voterA, 17),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	prResult := result.Repositories[0].PRs[0]
	if prResult.Approved || prResult.Eligible || prResult.Reason != "fewer than two approval identities" {
		t.Fatalf("one approval unexpectedly passed: %+v", prResult)
	}
}

func TestInvalidIdentityIsRejected(t *testing.T) {
	checkpoint := testCheckpoint(18)
	key := testKey(t)
	proof := testProof(checkpoint, key, 600_000, 4)
	checkpoint.StateRoot = proof.StateRoot
	payload := testPRPayload("pr-invalid", strings.Repeat("5", 64), strings.Repeat("6", 64))
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 18, key, "10000000000000000000000000000004", payload)
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions:    []OnChainAction{makeOnChain(t, pr, 1, key, 18)},
		Proofs:     map[string]IdentityProof{proof.Address: proof},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rejected) == 0 || !strings.Contains(result.Rejected[0].Reason, "valid Newbie") {
		t.Fatalf("expected identity rejection, got %+v", result.Rejected)
	}
}

func TestIdentityProofTamperingIsDetected(t *testing.T) {
	checkpoint := testCheckpoint(19)
	key := testKey(t)
	proof := testProof(checkpoint, key, 600_000, 8)
	checkpoint.StateRoot = proof.StateRoot
	if err := VerifyIdentityProof(proof, checkpoint.StateRoot); err != nil {
		t.Fatal(err)
	}
	proof.Value = "0x00"
	if err := VerifyIdentityProof(proof, checkpoint.StateRoot); err == nil {
		t.Fatal("tampered proof value was accepted")
	}
}

func TestEpochProofRemainsVerifiableFromCheckpointRoot(t *testing.T) {
	const postTransitionEpoch = uint16(236)
	value := protowire.AppendTag(nil, 1, protowire.VarintType)
	value = protowire.AppendVarint(value, uint64(postTransitionEpoch))
	key := []byte{0x03}
	valueHash := sha256.Sum256(value)
	root := iavlLeafHash(key, valueHash[:], 1)
	rootHex := "0x" + hex.EncodeToString(root)
	proof := StateValueProof{
		Value: "0x" + hex.EncodeToString(value),
		Leaf: ProofLeaf{
			Key:       "0x" + hex.EncodeToString(key),
			ValueHash: "0x" + hex.EncodeToString(valueHash[:]),
			Version:   1,
		},
		Path: []ProofStep{},
	}
	if err := VerifyEpochProof(proof, rootHex, postTransitionEpoch); err != nil {
		t.Fatal(err)
	}
	if err := VerifyEpochProof(proof, rootHex, postTransitionEpoch+1); err == nil {
		t.Fatal("incorrect checkpoint epoch was accepted")
	}
	tampered := proof
	tampered.Value = "0x00"
	if err := VerifyEpochProof(tampered, rootHex, postTransitionEpoch); err == nil {
		t.Fatal("tampered global state value was accepted")
	}
}

func TestInvalidRadicleBindingsAndSubjectsAreRejected(t *testing.T) {
	checkpoint := testCheckpoint(19)
	key := testKey(t)
	proof := testProof(checkpoint, key, 600_000, 8)
	checkpoint.StateRoot = proof.StateRoot
	payload := testPRPayload("pr-binding", strings.Repeat("a", 64), strings.Repeat("b", 64))
	envelope := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 19, key, "10000000000000000000000000000010", payload)
	input := CheckpointInput{
		Checkpoint: checkpoint,
		Actions:    []OnChainAction{makeOnChain(t, envelope, 1, key, 19)},
		Proofs:     map[string]IdentityProof{proof.Address: proof},
	}
	result, err := ReduceFixture(input, func(_, _, _ string) error { return nil }, func(Envelope) error {
		return errors.New("bad binding")
	}, func(RadicleSubject) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rejected) == 0 || !strings.Contains(result.Rejected[0].Reason, "bad binding") {
		t.Fatalf("binding rejection missing: %+v", result.Rejected)
	}
	result, err = ReduceFixture(input, func(_, _, _ string) error { return nil }, func(Envelope) error { return nil }, func(RadicleSubject) error {
		return errors.New("bad Radicle COB")
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rejected) == 0 || !strings.Contains(result.Rejected[0].Reason, "bad Radicle COB") {
		t.Fatalf("Radicle rejection missing: %+v", result.Rejected)
	}
}

func TestUnavailableRadicleContentBlocksCheckpoint(t *testing.T) {
	checkpoint := testCheckpoint(20)
	key := testKey(t)
	proof := testProof(checkpoint, key, 600_000, 8)
	checkpoint.StateRoot = proof.StateRoot
	payload := testPRPayload("missing-bundle", strings.Repeat("a", 64), strings.Repeat("b", 64))
	envelope := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", checkpoint.Epoch, key, "10000000000000000000000000000012", payload)
	_, err := ReduceFixture(CheckpointInput{
		Checkpoint: checkpoint,
		Actions:    []OnChainAction{makeOnChain(t, envelope, 1, key, checkpoint.Epoch)},
		Proofs:     map[string]IdentityProof{proof.Address: proof},
	}, func(_, _, _ string) error { return nil }, func(Envelope) error { return nil }, func(RadicleSubject) error {
		return ErrContentUnavailable
	})
	if !errors.Is(err, ErrContentUnavailable) {
		t.Fatalf("unavailable consensus-relevant content did not block settlement: %v", err)
	}
}

func TestCombinedStakeBelowThresholdFailsWithQuorum(t *testing.T) {
	checkpoint := testCheckpoint(20)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 199_999, 8},
		{voterB, 150_000, 8},
		{voterC, 150_000, 8},
	})
	checkpoint.StateRoot = stateRoot
	base := strings.Repeat("a", 64)
	head := strings.Repeat("c", 64)
	payload := testPRPayload("pr-low", base, head)
	revision, _ := Revision(payload)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 20, voterA, "10000000000000000000000000000009", payload)
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, voterA, 20),
			makeOnChain(t, voteEnvelope(t, voterA, 20, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-low", revision, DecisionApprove, 1), 2, voterA, 20),
			makeOnChain(t, voteEnvelope(t, voterB, 20, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-low", revision, DecisionApprove, 3), 3, voterB, 20),
			makeOnChain(t, voteEnvelope(t, voterC, 20, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-low", revision, DecisionReject, 4), 4, voterC, 20),
			makeOnChain(t, mergeEnvelope(t, voterA, 20, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-low", revision, 5), 5, voterA, 20),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Repositories[0].Winner != "" {
		t.Fatal("combined stake below 500000 iDNA must not execute")
	}
}

func TestQuotaIsAppliedInCanonicalOrder(t *testing.T) {
	checkpoint := testCheckpoint(20)
	key := testKey(t)
	proof := testProof(checkpoint, key, 600_000, 8)
	checkpoint.StateRoot = proof.StateRoot
	actions := make([]OnChainAction, 0, MaxActionsPerEpoch+1)
	bundleCID, _ := content.CIDForBytes([]byte("issue-cob-bundle"))
	for index := 0; index < MaxActionsPerEpoch+1; index++ {
		payload := IssuePayload{
			Issue:  testObjectID("issue-" + big.NewInt(int64(index)).String()),
			Action: testObjectID("issue-action-" + big.NewInt(int64(index)).String()),
			Title:  "issue", Bundle: bundleCID, ActorDID: testDID,
		}
		env := mustEnvelope(t, KindIssue, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 20, key, nonceHex(index), payload)
		actions = append(actions, makeOnChain(t, env, uint32(index), key, 20))
	}
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions:    actions,
		Proofs:     map[string]IdentityProof{proof.Address: proof},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	quotaRejections := 0
	for _, rejection := range result.Rejected {
		if rejection.Reason == "per-epoch action quota exceeded" {
			quotaRejections++
		}
	}
	if quotaRejections != 1 {
		t.Fatalf("quota rejection count = %d, all rejections: %+v", quotaRejections, result.Rejected)
	}
}

func TestInvalidRadicleContentStillConsumesRecognizedQuota(t *testing.T) {
	checkpoint := testCheckpoint(21)
	key := testKey(t)
	proof := testProof(checkpoint, key, 600_000, 8)
	checkpoint.StateRoot = proof.StateRoot
	actions := make([]OnChainAction, 0, MaxActionsPerEpoch+1)
	bundleCID, _ := content.CIDForBytes([]byte("quota-content-bundle"))
	firstActionOID := ""
	for index := 0; index < MaxActionsPerEpoch+1; index++ {
		actionOID := testObjectID(fmt.Sprintf("quota-action-%d", index))
		if index == 0 {
			firstActionOID = actionOID
		}
		payload := IssuePayload{
			Issue:    testObjectID(fmt.Sprintf("quota-issue-%d", index)),
			Action:   actionOID,
			Title:    "quota content independence",
			Bundle:   bundleCID,
			ActorDID: testDID,
		}
		envelope := mustEnvelope(t, KindIssue, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", checkpoint.Epoch, key, nonceHex(index), payload)
		actions = append(actions, makeOnChain(t, envelope, uint32(index), key, checkpoint.Epoch))
	}
	result, err := ReduceFixture(CheckpointInput{
		Checkpoint: checkpoint,
		Actions:    actions,
		Proofs:     map[string]IdentityProof{proof.Address: proof},
	}, nil, func(Envelope) error { return nil }, func(subject RadicleSubject) error {
		if subject.ActionOID == firstActionOID {
			return errors.New("invalid Radicle action")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	quotaRejections := 0
	contentRejections := 0
	for _, rejection := range result.Rejected {
		switch {
		case rejection.Reason == "per-epoch action quota exceeded":
			quotaRejections++
		case strings.Contains(rejection.Reason, "invalid Radicle action"):
			contentRejections++
		}
	}
	if quotaRejections != 1 || contentRejections != 1 {
		t.Fatalf("quota/content rejections = %d/%d, want 1/1: %+v", quotaRejections, contentRejections, result.Rejected)
	}
}

func TestWinnerSelectionRequiresTwoApprovals(t *testing.T) {
	checkpoint := testCheckpoint(22)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 400_000, 8},
		{voterB, 100_000, 7},
		{voterC, 100_000, 3},
	})
	checkpoint.StateRoot = stateRoot
	base := strings.Repeat("7", 64)
	headA := strings.Repeat("8", 64)
	headB := strings.Repeat("9", 64)
	payloadA := testPRPayload("pr-a", base, headA)
	payloadB := testPRPayload("pr-b", base, headB)
	revA, _ := Revision(payloadA)
	revB, _ := Revision(payloadB)
	envelopeA := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 22, voterA, "10000000000000000000000000000005", payloadA)
	envelopeB := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 22, voterA, "10000000000000000000000000000006", payloadB)
	actions := []OnChainAction{
		makeOnChain(t, envelopeA, 1, voterA, 22),
		makeOnChain(t, voteEnvelope(t, voterA, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-a", revA, DecisionApprove, 1), 2, voterA, 22),
		makeOnChain(t, voteEnvelope(t, voterB, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-a", revA, DecisionReject, 2), 3, voterB, 22),
		makeOnChain(t, voteEnvelope(t, voterC, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-a", revA, DecisionReject, 3), 4, voterC, 22),
		makeOnChain(t, mergeEnvelope(t, voterA, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-a", revA, 3), 5, voterA, 22),
		makeOnChain(t, envelopeB, 6, voterA, 22),
		makeOnChain(t, voteEnvelope(t, voterA, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-b", revB, DecisionApprove, 4), 7, voterA, 22),
		makeOnChain(t, voteEnvelope(t, voterB, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-b", revB, DecisionApprove, 5), 8, voterB, 22),
		makeOnChain(t, voteEnvelope(t, voterC, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-b", revB, DecisionReject, 6), 9, voterC, 22),
		makeOnChain(t, mergeEnvelope(t, voterA, 22, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-b", revB, 7), 10, voterA, 22),
	}
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint:    checkpoint,
		Actions:       actions,
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if result.Repositories[0].Winner != payloadB.Patch || result.Repositories[0].CanonicalHead != headB {
		t.Fatalf("wrong winner: %+v", result.Repositories[0])
	}
}

func testCheckpoint(epoch uint16) CheckpointBlock {
	return CheckpointBlock{
		Epoch:     epoch,
		Height:    uint64(1000 + epoch),
		Hash:      "0x" + strings.Repeat("a", 64),
		StateRoot: "0x" + strings.Repeat("b", 64),
	}
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testProof(checkpoint CheckpointBlock, key *ecdsa.PrivateKey, units int64, state uint16) IdentityProof {
	address := AddressFromPrivateKey(key)
	addressBytes, _ := hex.DecodeString(strings.TrimPrefix(address, "0x"))
	stake := RawStakeFromUnits(units)
	value := protowire.AppendTag(nil, 1, protowire.BytesType)
	value = protowire.AppendBytes(value, stake.Bytes())
	value = protowire.AppendTag(value, 4, protowire.VarintType)
	value = protowire.AppendVarint(value, uint64(state))
	keyBytes := append([]byte{0x02}, addressBytes...)
	valueHash := sha256.Sum256(value)
	leafHash := iavlLeafHash(keyBytes, valueHash[:], 1)
	return IdentityProof{
		Epoch:      checkpoint.Epoch,
		StateEpoch: checkpoint.Epoch + 1,
		Height:     checkpoint.Height,
		BlockHash:  checkpoint.Hash,
		StateRoot:  "0x" + hex.EncodeToString(leafHash),
		Address:    address,
		Value:      "0x" + hex.EncodeToString(value),
		Stake:      stake.String(),
		State:      state,
		StateName:  IdentityStateName(state),
		Leaf: ProofLeaf{
			Key:       "0x" + hex.EncodeToString(keyBytes),
			ValueHash: "0x" + hex.EncodeToString(valueHash[:]),
			Version:   1,
		},
		Path: []ProofStep{},
	}
}

type testIdentity struct {
	key   *ecdsa.PrivateKey
	units int64
	state uint16
}

type proofTestLeaf struct {
	identity testIdentity
	address  string
	key      []byte
	value    []byte
	hash     []byte
}

type proofTestNode struct {
	height int64
	size   int64
	hash   []byte
	leaf   *proofTestLeaf
	left   *proofTestNode
	right  *proofTestNode
}

func testProofSet(t *testing.T, checkpoint CheckpointBlock, identities []testIdentity) (map[string]IdentityProof, string) {
	t.Helper()
	if len(identities) == 0 {
		t.Fatal("test proof set requires identities")
	}
	var leaves []*proofTestLeaf
	for _, item := range identities {
		address := AddressFromPrivateKey(item.key)
		addressBytes, _ := hex.DecodeString(strings.TrimPrefix(address, "0x"))
		key := append([]byte{0x02}, addressBytes...)
		stake := RawStakeFromUnits(item.units)
		value := protowire.AppendTag(nil, 1, protowire.BytesType)
		value = protowire.AppendBytes(value, stake.Bytes())
		value = protowire.AppendTag(value, 4, protowire.VarintType)
		value = protowire.AppendVarint(value, uint64(item.state))
		valueHash := sha256.Sum256(value)
		leaves = append(leaves, &proofTestLeaf{
			identity: item,
			address:  address,
			key:      key,
			value:    value,
			hash:     iavlLeafHash(key, valueHash[:], 1),
		})
	}
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i].key, leaves[j].key) < 0
	})
	var build func([]*proofTestLeaf) *proofTestNode
	build = func(items []*proofTestLeaf) *proofTestNode {
		if len(items) == 1 {
			return &proofTestNode{size: 1, hash: items[0].hash, leaf: items[0]}
		}
		middle := len(items) / 2
		left := build(items[:middle])
		right := build(items[middle:])
		height := left.height
		if right.height > height {
			height = right.height
		}
		height++
		size := left.size + right.size
		hash := iavlNodeHash(height, size, 1, left.hash, right.hash)
		return &proofTestNode{height: height, size: size, hash: hash, left: left, right: right}
	}
	root := build(leaves)
	var pathFor func(*proofTestNode, *proofTestLeaf) []ProofStep
	pathFor = func(node *proofTestNode, target *proofTestLeaf) []ProofStep {
		if node.leaf != nil {
			return []ProofStep{}
		}
		step := ProofStep{Height: int16(node.height), Size: uint64(node.size), Version: 1}
		if containsProofLeaf(node.left, target) {
			if len(node.right.hash) > 0 {
				step.Right = "0x" + hex.EncodeToString(node.right.hash)
			}
			return append([]ProofStep{step}, pathFor(node.left, target)...)
		}
		if len(node.left.hash) > 0 {
			step.Left = "0x" + hex.EncodeToString(node.left.hash)
		}
		return append([]ProofStep{step}, pathFor(node.right, target)...)
	}
	rootHex := "0x" + hex.EncodeToString(root.hash)
	proofs := make(map[string]IdentityProof, len(leaves))
	for _, current := range leaves {
		stake := RawStakeFromUnits(current.identity.units)
		valueHash := sha256.Sum256(current.value)
		proofs[current.address] = IdentityProof{
			Epoch:      checkpoint.Epoch,
			StateEpoch: checkpoint.Epoch + 1,
			Height:     checkpoint.Height,
			BlockHash:  checkpoint.Hash,
			StateRoot:  rootHex,
			Address:    current.address,
			Value:      "0x" + hex.EncodeToString(current.value),
			Stake:      stake.String(),
			State:      current.identity.state,
			StateName:  IdentityStateName(current.identity.state),
			Leaf: ProofLeaf{
				Key:       "0x" + hex.EncodeToString(current.key),
				ValueHash: "0x" + hex.EncodeToString(valueHash[:]),
				Version:   1,
			},
			Path: pathFor(root, current),
		}
	}
	for address, proof := range proofs {
		if err := VerifyIdentityProof(proof, rootHex); err != nil {
			t.Fatalf("test proof for %s is invalid: %v: %+v", address, err, proof.Path)
		}
	}
	return proofs, rootHex
}

func containsProofLeaf(node *proofTestNode, target *proofTestLeaf) bool {
	if node == nil {
		return false
	}
	if node.leaf != nil {
		return node.leaf == target
	}
	return containsProofLeaf(node.left, target) || containsProofLeaf(node.right, target)
}

type testPR struct {
	payload       PullRequestPayload
	envelope      *Envelope
	envelopeBytes []byte
}

func testPullRequest(t *testing.T, key *ecdsa.PrivateKey, epoch uint16, repository, pr string) testPR {
	t.Helper()
	payload := testPRPayload(pr, strings.Repeat("b", 64), strings.Repeat("a", 64))
	envelope := mustEnvelope(t, KindPullRequest, repository, epoch, key, "10000000000000000000000000000001", payload)
	encoded, err := envelope.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return testPR{payload: payload, envelope: envelope, envelopeBytes: encoded}
}

func resignPullRequest(t *testing.T, key *ecdsa.PrivateKey, epoch uint16, repository string, payload PullRequestPayload) testPR {
	t.Helper()
	envelope := mustEnvelope(t, KindPullRequest, repository, epoch, key, "10000000000000000000000000000007", payload)
	encoded, _ := envelope.Bytes()
	return testPR{payload: payload, envelope: envelope, envelopeBytes: encoded}
}

func testPRPayload(pr, base, head string) PullRequestPayload {
	bundle, _ := content.CIDForBytes([]byte("bundle-" + pr))
	diff, _ := content.CIDForBytes([]byte("diff-" + pr))
	return PullRequestPayload{
		Patch:    testObjectID("patch-" + pr),
		Revision: testObjectID("revision-" + pr),
		Title:    "Example " + pr,
		Base:     base,
		Head:     head,
		Bundle:   bundle,
		Diff:     diff,
		ActorDID: testDID,
	}
}

func voteEnvelope(t *testing.T, key *ecdsa.PrivateKey, epoch uint16, repository, pr, revision, decision string, nonce int) *Envelope {
	t.Helper()
	bundleCID, _ := content.CIDForBytes([]byte("review-bundle-" + pr + revision))
	reviewID := testObjectID(fmt.Sprintf("review-%s-%d", pr, nonce))
	return mustEnvelope(t, KindVote, repository, epoch, key, nonceHex(nonce), VotePayload{
		Patch:     testObjectID("patch-" + pr),
		Revision:  revision,
		Decision:  decision,
		Review:    reviewID,
		ActionOID: reviewID,
		Bundle:    bundleCID,
		ActorDID:  testDID,
	})
}

func mergeEnvelope(t *testing.T, key *ecdsa.PrivateKey, epoch uint16, repository, pr, revision string, nonce int) *Envelope {
	t.Helper()
	bundleCID, _ := content.CIDForBytes([]byte("merge-label-bundle-" + pr + revision))
	return mustEnvelope(t, KindMergeRequest, repository, epoch, key, nonceHex(nonce), MergeRequestPayload{
		Patch:       testObjectID("patch-" + pr),
		Revision:    revision,
		Label:       "idena/merge-request",
		LabelAction: testObjectID(fmt.Sprintf("merge-label-%s-%d", pr, nonce)),
		Bundle:      bundleCID,
		ActorDID:    testDID,
	})
}

func mustEnvelope(t *testing.T, kind, repository string, epoch uint16, key *ecdsa.PrivateKey, nonce string, payload any) *Envelope {
	t.Helper()
	envelope, err := NewEnvelope(kind, repository, epoch, AddressFromPrivateKey(key), testDID, testPublicKey, nonce, payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = "test-radicle-binding"
	if err := envelope.Sign(key); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func reduceForTest(t *testing.T, input CheckpointInput, verifyFastForward FastForwardVerifier) (*CheckpointResult, error) {
	t.Helper()
	return ReduceFixture(input, verifyFastForward, func(Envelope) error { return nil }, func(RadicleSubject) error { return nil })
}

func authenticateInputsForTest(t *testing.T, inputs []CheckpointInput) []AuthenticatedCheckpointInput {
	t.Helper()
	authenticated := make([]AuthenticatedCheckpointInput, len(inputs))
	for index := range inputs {
		if inputs[index].ReducerPolicy == "" {
			inputs[index].ReducerPolicy = CurrentReducerPolicy()
		}
		verified, err := AuthenticateCheckpointInput(context.Background(), inputs[index], func(context.Context, CheckpointInput) error {
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		authenticated[index] = verified
	}
	return authenticated
}

func testObjectID(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

const (
	testDID       = "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP"
	testPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o"
)

func makeOnChain(t *testing.T, envelope *Envelope, index uint32, _ *ecdsa.PrivateKey, epoch uint16) OnChainAction {
	t.Helper()
	encoded, err := envelope.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	actionCID, err := content.CIDForBytes(encoded)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(append(encoded, byte(index)))
	txHash := "0x" + hex.EncodeToString(hash[:])
	return OnChainAction{
		Height:      1000 + uint64(epoch),
		BlockHash:   "0x" + strings.Repeat("a", 64),
		TxHash:      txHash,
		TxIndex:     index,
		TxType:      "send",
		TxSender:    envelope.Author,
		TxRecipient: envelope.Author,
		TxEpoch:     epoch,
		ActionCID:   actionCID,
		ActionBytes: encoded,
		Action:      envelope,
	}
}

func nonceHex(index int) string {
	return strings.Repeat("0", 24) + fmt.Sprintf("%08x", index+1)
}

func TestFastForwardFailureMakesPRIneligible(t *testing.T) {
	checkpoint := testCheckpoint(24)
	key := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{key, 300_000, 8},
		{voterB, 150_000, 8},
		{voterC, 50_000, 8},
	})
	checkpoint.StateRoot = stateRoot
	payload := testPRPayload("pr-ff", strings.Repeat("c", 64), strings.Repeat("d", 64))
	revision, _ := Revision(payload)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 24, key, "10000000000000000000000000000008", payload)
	result, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, key, 24),
			makeOnChain(t, voteEnvelope(t, key, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-ff", revision, DecisionApprove, 1), 2, key, 24),
			makeOnChain(t, voteEnvelope(t, voterB, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-ff", revision, DecisionApprove, 3), 3, voterB, 24),
			makeOnChain(t, voteEnvelope(t, voterC, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-ff", revision, DecisionReject, 4), 4, voterC, 24),
			makeOnChain(t, mergeEnvelope(t, key, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-ff", revision, 5), 5, key, 24),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": payload.Base},
	}, func(_, _, _ string) error { return errors.New("not a fast-forward") })
	if err != nil {
		t.Fatal(err)
	}
	if result.Repositories[0].Winner != "" {
		t.Fatal("failed Git ancestry check must prevent merge")
	}
}

func TestUnavailableFastForwardBundleBlocksCheckpoint(t *testing.T) {
	checkpoint := testCheckpoint(24)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 300_000, 8},
		{voterB, 150_000, 8},
		{voterC, 50_000, 8},
	})
	checkpoint.StateRoot = stateRoot
	payload := testPRPayload("pr-missing-ff", strings.Repeat("c", 64), strings.Repeat("d", 64))
	revision, _ := Revision(payload)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 24, voterA, "10000000000000000000000000000018", payload)
	_, err := reduceForTest(t, CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, voterA, 24),
			makeOnChain(t, voteEnvelope(t, voterA, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-missing-ff", revision, DecisionApprove, 1), 2, voterA, 24),
			makeOnChain(t, voteEnvelope(t, voterB, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-missing-ff", revision, DecisionApprove, 3), 3, voterB, 24),
			makeOnChain(t, voteEnvelope(t, voterC, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-missing-ff", revision, DecisionReject, 4), 4, voterC, 24),
			makeOnChain(t, mergeEnvelope(t, voterA, 24, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "pr-missing-ff", revision, 5), 5, voterA, 24),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": payload.Base},
	}, func(_, _, _ string) error { return ErrContentUnavailable })
	if !errors.Is(err, ErrContentUnavailable) {
		t.Fatalf("missing fast-forward bundle did not block settlement: %v", err)
	}
}

func TestCheckpointReplayCarriesVerifiedHeadsForward(t *testing.T) {
	head := strings.Repeat("a", 40)
	key := testKey(t)
	firstCheckpoint := testCheckpoint(MainnetActivationEpoch)
	proof := testProof(firstCheckpoint, key, 600_000, 8)
	firstCheckpoint.StateRoot = proof.StateRoot
	secondCheckpoint := testCheckpoint(MainnetActivationEpoch + 1)
	bundleCID, err := content.CIDForBytes([]byte("repository genesis bundle"))
	if err != nil {
		t.Fatal(err)
	}
	repository := mustEnvelope(t, KindRepository, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", MainnetActivationEpoch, key, "10000000000000000000000000000030", RepositoryPayload{
		Head: head, Bundle: bundleCID, ActorDID: testDID,
	})
	inputs := []CheckpointInput{
		{
			Checkpoint: firstCheckpoint,
			Actions:    []OnChainAction{makeOnChain(t, repository, 0, key, MainnetActivationEpoch)},
			Proofs:     map[string]IdentityProof{proof.Address: proof},
		},
		{
			Checkpoint: secondCheckpoint,
		},
	}
	results, err := ReduceReplay(authenticateInputsForTest(t, inputs), func(_, _, _ string) error { return nil }, func(Envelope) error { return nil }, func(RadicleSubject) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 || results[1].Repositories[0].PreviousHead != head {
		t.Fatalf("replay did not carry verified head: %+v", results)
	}
}

func TestCheckpointReplayRejectsMissingEpoch(t *testing.T) {
	inputs := []CheckpointInput{
		{Checkpoint: testCheckpoint(MainnetActivationEpoch)},
		{Checkpoint: testCheckpoint(MainnetActivationEpoch + 2)},
	}
	_, err := ReduceReplay(authenticateInputsForTest(t, inputs), nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "every consecutive epoch") {
		t.Fatalf("checkpoint history gap was accepted: %v", err)
	}
}

func TestCheckpointReplayRejectsSuffixAfterActivation(t *testing.T) {
	inputs := []CheckpointInput{{Checkpoint: testCheckpoint(MainnetActivationEpoch + 1)}}
	_, err := ReduceReplay(authenticateInputsForTest(t, inputs), nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "activation epoch") {
		t.Fatalf("history suffix was accepted as complete state: %v", err)
	}
}

func TestRepositoryDeletionSchedulesOneEpochGraceAndSurvivesReplay(t *testing.T) {
	const firstEpoch = MainnetActivationEpoch
	const secondEpoch = MainnetActivationEpoch + 1
	firstCheckpoint := testCheckpoint(firstEpoch)
	secondCheckpoint := testCheckpoint(secondEpoch)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, firstCheckpoint, []testIdentity{
		{voterA, 250_000, 8},
		{voterB, 150_000, 7},
		{voterC, 100_000, 3},
	})
	firstCheckpoint.StateRoot = stateRoot
	base := strings.Repeat("a", 40)
	head := strings.Repeat("b", 40)
	payload := testPRPayload("delete-repository", base, head)
	payload.DeleteRepository = true
	revision, _ := Revision(payload)
	bundleCID, err := content.CIDForBytes([]byte("deletion repository bundle"))
	if err != nil {
		t.Fatal(err)
	}
	repository := mustEnvelope(t, KindRepository, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", firstEpoch, voterA, "10000000000000000000000000000019", RepositoryPayload{
		Head: base, Bundle: bundleCID, ActorDID: testDID,
	})
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", firstEpoch, voterA, "10000000000000000000000000000020", payload)
	first := CheckpointInput{
		Checkpoint: firstCheckpoint,
		Actions: []OnChainAction{
			makeOnChain(t, repository, 0, voterA, firstEpoch),
			makeOnChain(t, pr, 1, voterA, firstEpoch),
			makeOnChain(t, voteEnvelope(t, voterA, firstEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "delete-repository", revision, DecisionApprove, 1), 2, voterA, firstEpoch),
			makeOnChain(t, voteEnvelope(t, voterB, firstEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "delete-repository", revision, DecisionApprove, 2), 3, voterB, firstEpoch),
			makeOnChain(t, voteEnvelope(t, voterC, firstEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "delete-repository", revision, DecisionReject, 3), 4, voterC, firstEpoch),
			makeOnChain(t, mergeEnvelope(t, voterA, firstEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "delete-repository", revision, 4), 5, voterA, firstEpoch),
		},
		Proofs: proofs,
	}
	secondProofs, secondStateRoot := testProofSet(t, secondCheckpoint, []testIdentity{
		{voterA, 250_000, 8},
		{voterB, 150_000, 7},
		{voterC, 100_000, 3},
	})
	secondCheckpoint.StateRoot = secondStateRoot
	resurrectPayload := testPRPayload("resurrect", head, strings.Repeat("c", 40))
	resurrectRevision, _ := Revision(resurrectPayload)
	resurrectPR := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", secondEpoch, voterA, "10000000000000000000000000000021", resurrectPayload)
	inputs := []CheckpointInput{
		first,
		{
			Checkpoint: secondCheckpoint,
			Actions: []OnChainAction{
				makeOnChain(t, resurrectPR, 1, voterA, secondEpoch),
				makeOnChain(t, voteEnvelope(t, voterA, secondEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "resurrect", resurrectRevision, DecisionApprove, 1), 2, voterA, secondEpoch),
				makeOnChain(t, voteEnvelope(t, voterB, secondEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "resurrect", resurrectRevision, DecisionApprove, 2), 3, voterB, secondEpoch),
				makeOnChain(t, voteEnvelope(t, voterC, secondEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "resurrect", resurrectRevision, DecisionReject, 3), 4, voterC, secondEpoch),
				makeOnChain(t, mergeEnvelope(t, voterA, secondEpoch, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "resurrect", resurrectRevision, 4), 5, voterA, secondEpoch),
			},
			Proofs: secondProofs,
		},
	}
	results, err := ReduceReplay(authenticateInputsForTest(t, inputs), func(_, _, _ string) error { return nil }, func(Envelope) error { return nil }, func(RadicleSubject) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for index, result := range results {
		repository := result.Repositories[0]
		if !repository.Deleted || repository.PruneAfterEpoch != firstEpoch+2 {
			t.Fatalf("checkpoint %d deletion state = %+v", index, repository)
		}
	}
	if results[1].Repositories[0].Winner != "" {
		t.Fatal("a deleted repository was resurrected by a later PR")
	}
}

func TestProofProviderDoesNotChangeCheckpointResult(t *testing.T) {
	checkpoint := testCheckpoint(42)
	voterA := testKey(t)
	voterB := testKey(t)
	voterC := testKey(t)
	proofs, stateRoot := testProofSet(t, checkpoint, []testIdentity{
		{voterA, 250_000, 8},
		{voterB, 150_000, 7},
		{voterC, 100_000, 3},
	})
	checkpoint.StateRoot = stateRoot
	base := strings.Repeat("1", 40)
	head := strings.Repeat("2", 40)
	payload := testPRPayload("provider-neutral", base, head)
	revision, _ := Revision(payload)
	pr := mustEnvelope(t, KindPullRequest, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", 42, voterA, "10000000000000000000000000000022", payload)
	input := CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []OnChainAction{
			makeOnChain(t, pr, 1, voterA, 42),
			makeOnChain(t, voteEnvelope(t, voterA, 42, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "provider-neutral", revision, DecisionApprove, 1), 2, voterA, 42),
			makeOnChain(t, voteEnvelope(t, voterB, 42, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "provider-neutral", revision, DecisionApprove, 2), 3, voterB, 42),
			makeOnChain(t, voteEnvelope(t, voterC, 42, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "provider-neutral", revision, DecisionReject, 3), 4, voterC, 42),
			makeOnChain(t, mergeEnvelope(t, voterA, 42, "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", "provider-neutral", revision, 4), 5, voterA, 42),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5": base},
	}
	for address, proof := range input.Proofs {
		proof.Source = "idena-rpc"
		input.Proofs[address] = proof
	}
	rpcResult, err := reduceForTest(t, input, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	for address, proof := range input.Proofs {
		proof.Source = "idena-indexer"
		input.Proofs[address] = proof
	}
	indexerResult, err := reduceForTest(t, input, func(_, _, _ string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	rpcJSON, _ := json.Marshal(rpcResult)
	indexerJSON, _ := json.Marshal(indexerResult)
	if string(rpcJSON) != string(indexerJSON) {
		t.Fatal("proof provider changed the semantic checkpoint result")
	}
}
