package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/idena"
	"idena-git-forge/internal/protocol"
	"idena-git-forge/internal/webui"
)

type checkpointReplicaVerifierStub struct {
	calls *int
	err   error
}

func (stub checkpointReplicaVerifierStub) VerifyCheckpointReplica(context.Context, protocol.CheckpointInput, uint64) (idena.ChainVerification, error) {
	(*stub.calls)++
	return idena.ChainVerification{}, stub.err
}

func TestAcceptedRetentionObjectsExcludeRejectedActions(t *testing.T) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const repository = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
	const actorDID = "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP"
	const actorKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o"
	makeAction := func(index int, txHash, bundleCID string) protocol.OnChainAction {
		envelope, err := protocol.NewEnvelope(
			protocol.KindIssue,
			repository,
			7,
			protocol.AddressFromPrivateKey(key),
			actorDID,
			actorKey,
			strings.Repeat("0", 31)+string(rune('0'+index)),
			protocol.IssuePayload{
				Issue:    strings.Repeat(string(rune('a'+index)), 40),
				Action:   strings.Repeat(string(rune('c'+index)), 40),
				Title:    "retention test",
				Bundle:   bundleCID,
				ActorDID: actorDID,
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		envelope.Binding = "test-binding"
		if err := envelope.Sign(key); err != nil {
			t.Fatal(err)
		}
		encoded, err := envelope.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		actionCID, err := content.CIDForBytes(encoded)
		if err != nil {
			t.Fatal(err)
		}
		return protocol.OnChainAction{TxHash: txHash, ActionCID: actionCID, ActionBytes: encoded}
	}
	acceptedBundle, _ := content.CIDForBytes([]byte("accepted bundle"))
	rejectedBundle, _ := content.CIDForBytes([]byte("rejected bundle"))
	accepted := makeAction(1, "0xaccepted", acceptedBundle)
	rejected := makeAction(2, "0xrejected", rejectedBundle)
	objects, err := acceptedRetentionObjects(
		protocol.CheckpointInput{Actions: []protocol.OnChainAction{accepted, rejected}},
		protocol.CheckpointResult{Rejected: []protocol.Rejection{{TxHash: rejected.TxHash, Reason: "invalid Radicle action"}}},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{accepted.ActionCID: true, acceptedBundle: true}
	if len(objects) != len(want) {
		t.Fatalf("retention objects = %+v", objects)
	}
	for _, object := range objects {
		if !want[object.CID] || object.Repository != repository {
			t.Fatalf("unexpected retention object: %+v", object)
		}
	}
}

func TestPublishPinsSuppliedReferencedObjectWithoutPriorIPFSAvailability(t *testing.T) {
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := []byte("reviewed repository bundle")
	bundleCID, err := content.CIDForBytes(bundle)
	if err != nil {
		t.Fatal(err)
	}
	const repository = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
	const actorDID = "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP"
	const actorKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o"
	author := protocol.AddressFromPrivateKey(key)
	envelope, err := protocol.NewEnvelope(
		protocol.KindRepository,
		repository,
		7,
		author,
		actorDID,
		actorKey,
		"10000000000000000000000000000001",
		protocol.RepositoryPayload{
			Head:     strings.Repeat("a", 40),
			Bundle:   bundleCID,
			ActorDID: actorDID,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = "test-binding"
	if err := envelope.Sign(key); err != nil {
		t.Fatal(err)
	}
	action, err := envelope.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	actionCID, err := content.CIDForBytes(action)
	if err != nil {
		t.Fatal(err)
	}
	estimatedHash := "0x" + strings.Repeat("a", 64)

	root := t.TempDir()
	actionPath := filepath.Join(root, "action.json")
	bundlePath := filepath.Join(root, "repository.bundle")
	if err := os.WriteFile(actionPath, append(action, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	var added []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var rpc struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch rpc.Method {
		case "dna_epoch":
			result = map[string]any{"epoch": 7}
		case "dna_getCoinbaseAddr":
			result = author
		case "bcn_estimateTx":
			result = idena.ForgeActionEstimate{TxHash: estimatedHash, TxFee: "1.25"}
		case "ipfs_cid", "ipfs_add":
			var encoded string
			if err := json.Unmarshal(rpc.Params[0], &encoded); err != nil {
				t.Error(err)
				return
			}
			object, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
			if err != nil {
				t.Error(err)
				return
			}
			contentCID, err := content.CIDForBytes(object)
			if err != nil {
				t.Error(err)
				return
			}
			if rpc.Method == "ipfs_add" {
				added = append(added, contentCID)
			}
			result = contentCID
		case "ipfs_get":
			t.Error("publish should use the supplied local bundle")
			result = ""
		default:
			t.Errorf("unexpected method %s", rpc.Method)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID, "result": result,
		})
	}))
	defer server.Close()

	if err := runPublish(context.Background(), []string{
		"--rpc", server.URL,
		"--action", actionPath,
		"--object", bundlePath,
		"--nonce", "10",
		"--max-fee", "5",
		"--expected-tx-hash", estimatedHash,
		"--expected-tx-fee", "1.25",
	}); err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 || added[0] != bundleCID || added[1] != actionCID {
		t.Fatalf("pinned CIDs = %v, want [%s %s]", added, bundleCID, actionCID)
	}
	added = nil
	err = runPublish(context.Background(), []string{
		"--rpc", server.URL,
		"--action", actionPath,
		"--object", bundlePath,
		"--nonce", "10",
		"--max-fee", "5",
		"--expected-tx-hash", "0x" + strings.Repeat("b", 64),
		"--expected-tx-fee", "1.25",
	})
	if err == nil || !strings.Contains(err.Error(), "differs from approved hash") {
		t.Fatalf("drift error = %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("estimate drift pinned content: %v", added)
	}
}

func TestPublishBroadcastRequiresMaxFeeBeforeReadingAction(t *testing.T) {
	err := runPublish(context.Background(), []string{
		"--action", filepath.Join(t.TempDir(), "missing-action.json"),
		"--broadcast",
	})
	if err == nil || !strings.Contains(err.Error(), "--max-fee is required with --broadcast") {
		t.Fatalf("error = %v", err)
	}
}

func TestPublishBroadcastRequiresReviewedEstimateBeforeReadingAction(t *testing.T) {
	err := runPublish(context.Background(), []string{
		"--action", filepath.Join(t.TempDir(), "missing-action.json"),
		"--max-fee", "5",
		"--broadcast",
	})
	if err == nil || !strings.Contains(err.Error(), "--expected-tx-hash and --expected-tx-fee are required with --broadcast") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidatePositiveDecimal(t *testing.T) {
	for _, value := range []string{"5", "0.00001", " 1.25 "} {
		if err := validatePositiveDecimal(value); err != nil {
			t.Errorf("%q: %v", value, err)
		}
	}
	for _, value := range []string{"", "0", "-1", ".5", "5.", "1/2", "1e3"} {
		if err := validatePositiveDecimal(value); err == nil {
			t.Errorf("%q was accepted", value)
		}
	}
}

func TestReplicaAPIKeysRequireUnambiguousNodePairing(t *testing.T) {
	unset := make(map[string]bool)
	lookup := func(name string) (string, bool) {
		values := map[string]string{"NODE_2_KEY": "key-2", "NODE_3_KEY": "key-3"}
		value, exists := values[name]
		return value, exists
	}
	unsetEnvironment := func(name string) error {
		unset[name] = true
		return nil
	}
	keys, err := replicaAPIKeys([]string{"node-2"}, nil, "environment-key", lookup, unsetEnvironment)
	if err != nil || len(keys) != 1 || keys[0] != "environment-key" {
		t.Fatalf("single replica fallback = %v, %v", keys, err)
	}
	keys, err = replicaAPIKeys([]string{"node-2", "node-3"}, []string{"NODE_2_KEY", "NODE_3_KEY"}, "ignored", lookup, unsetEnvironment)
	if err != nil || !reflect.DeepEqual(keys, []string{"key-2", "key-3"}) {
		t.Fatalf("environment replica key pairing = %v, %v", keys, err)
	}
	if !unset["NODE_2_KEY"] || !unset["NODE_3_KEY"] {
		t.Fatalf("replica API-key environments were not removed before child processes: %v", unset)
	}
	if _, err := replicaAPIKeys([]string{"node-2", "node-3"}, nil, "one-key", lookup, unsetEnvironment); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous multi-replica key was accepted: %v", err)
	}
	if _, err := replicaAPIKeys([]string{"node-2", "node-3"}, []string{"NODE_2_KEY"}, "", lookup, unsetEnvironment); err == nil || !strings.Contains(err.Error(), "exactly once") {
		t.Fatalf("mismatched replica key environments were accepted: %v", err)
	}
	if _, err := replicaAPIKeys([]string{"node-2", "node-3"}, []string{"NODE_2_KEY", "MISSING"}, "", lookup, unsetEnvironment); err == nil || !strings.Contains(err.Error(), "unset or empty") {
		t.Fatalf("missing replica environment was accepted: %v", err)
	}
}

func TestSecretEnvironmentResolutionRemovesChildInheritance(t *testing.T) {
	values := map[string]string{"FORGE_TEST_SECRET": "sentinel-secret"}
	unset := false
	value, err := resolveSecretEnvironmentWith(
		"FORGE_TEST_SECRET",
		func(name string) (string, bool) {
			result, exists := values[name]
			return result, exists
		},
		func(name string) error {
			delete(values, name)
			unset = true
			return nil
		},
	)
	if err != nil || value != "sentinel-secret" || !unset {
		t.Fatalf("secret resolution = %q, unset=%v, err=%v", value, unset, err)
	}
	if _, exists := values["FORGE_TEST_SECRET"]; exists {
		t.Fatal("secret environment remained available for child processes")
	}
	if _, err := resolveSecretEnvironmentWith("BAD-NAME", func(string) (string, bool) { return "", false }, func(string) error { return nil }); err == nil {
		t.Fatal("invalid secret environment name was accepted")
	}
}

func TestScanHelpDoesNotExposeOrAcceptSigningPassphrase(t *testing.T) {
	const apiSentinel = "api-key-sentinel-never-print"
	const passphraseSentinel = "passphrase-sentinel-never-print"
	t.Setenv("IDENA_API_KEY", apiSentinel)
	t.Setenv("RAD_PASSPHRASE", passphraseSentinel)

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = writeEnd
	runErr := runScan(context.Background(), []string{"-h"})
	_ = writeEnd.Close()
	os.Stderr = originalStderr
	output, readErr := io.ReadAll(readEnd)
	_ = readEnd.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !errors.Is(runErr, flag.ErrHelp) {
		t.Fatalf("scan help error = %v, want flag.ErrHelp", runErr)
	}
	if bytes.Contains(output, []byte(apiSentinel)) || bytes.Contains(output, []byte(passphraseSentinel)) {
		t.Fatalf("scan help disclosed a secret environment value: %s", output)
	}
	if !bytes.Contains(output, []byte("api-key-env")) {
		t.Fatalf("scan help omitted the Idena API-key source flag: %s", output)
	}
	if bytes.Contains(output, []byte("rad-passphrase-env")) {
		t.Fatalf("read-only scan still accepts a Radicle signing passphrase: %s", output)
	}
}

func TestVerifyCheckpointReplicasFailsClosedOnThirdView(t *testing.T) {
	calls := 0
	replicas := []checkpointReplicaVerifier{
		checkpointReplicaVerifierStub{calls: &calls},
		checkpointReplicaVerifierStub{calls: &calls},
		checkpointReplicaVerifierStub{calls: &calls, err: errors.New("divergent proof")},
	}
	err := verifyCheckpointReplicas(context.Background(), replicas, protocol.CheckpointInput{ReducerPolicy: protocol.CurrentReducerPolicy()}, 100)
	if err == nil || !strings.Contains(err.Error(), "verification 3") || !strings.Contains(err.Error(), "divergent proof") {
		t.Fatalf("third replica divergence was not reported: %v", err)
	}
	if calls != 3 {
		t.Fatalf("verified %d replica views, want 3", calls)
	}
}

func TestVerifyForgeActionEstimateFailsClosedOnDrift(t *testing.T) {
	estimate := idena.ForgeActionEstimate{
		TxHash: "0x" + strings.Repeat("a", 64),
		TxFee:  "1.25",
	}
	if err := verifyForgeActionEstimate(estimate, "0x"+strings.Repeat("a", 64), "1.25"); err != nil {
		t.Fatal(err)
	}
	if err := verifyForgeActionEstimate(estimate, "0x"+strings.Repeat("b", 64), "1.25"); err == nil {
		t.Fatal("changed estimated transaction hash was accepted")
	}
	if err := verifyForgeActionEstimate(estimate, "0x"+strings.Repeat("a", 64), "1.26"); err == nil {
		t.Fatal("changed estimated transaction fee was accepted")
	}
}

func TestDoubleDecimalSum(t *testing.T) {
	got, err := doubleDecimalSum("0.001234", "0.000066")
	if err != nil {
		t.Fatal(err)
	}
	if got != "0.0026" {
		t.Fatalf("fee = %q, want 0.0026", got)
	}
}

func TestAnchorDirectBroadcastIsDisabledBeforeAnyRPC(t *testing.T) {
	err := runAnchor(context.Background(), []string{"--broadcast"})
	if err == nil || !strings.Contains(err.Error(), "direct anchor broadcast is disabled") {
		t.Fatalf("direct anchor broadcast was not rejected: %v", err)
	}
}

func TestAnchorPrepareOnlyPatchRequiresLocalDiffOutput(t *testing.T) {
	err := runAnchor(context.Background(), []string{
		"--rpc", "http://127.0.0.1:1",
		"--rid", "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
		"--kind", protocol.KindPullRequest,
		"--prepare-only",
		"--out", filepath.Join(t.TempDir(), "action.json"),
		"--bundle-out", filepath.Join(t.TempDir(), "bundle"),
	})
	if err == nil || !strings.Contains(err.Error(), "requires --diff-out") {
		t.Fatalf("prepare-only patch omitted its exact diff: %v", err)
	}
}

func TestExactWinnerRevisionSelectsOnlyTheDeclaredRevision(t *testing.T) {
	repository := protocol.RepositoryResult{
		Repository:     "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
		CanonicalHead:  strings.Repeat("b", 40),
		Winner:         strings.Repeat("a", 40),
		WinnerRevision: strings.Repeat("2", 40),
		PRs: []protocol.PRResult{
			{
				PR: strings.Repeat("a", 40), Revision: strings.Repeat("1", 40),
				Head: strings.Repeat("c", 40), Eligible: true,
			},
			{
				PR: strings.Repeat("a", 40), Revision: strings.Repeat("2", 40),
				Head: strings.Repeat("b", 40), BundleCID: "winner-bundle", Eligible: true,
			},
		},
	}
	winner, ok, err := exactWinnerRevision(repository)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || winner.Revision != repository.WinnerRevision || winner.BundleCID != "winner-bundle" {
		t.Fatalf("wrong exact winner: %+v, ok=%t", winner, ok)
	}
}

func TestExactWinnerRevisionFailsClosedOnAmbiguity(t *testing.T) {
	base := protocol.RepositoryResult{
		Repository:     "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
		CanonicalHead:  strings.Repeat("b", 40),
		Winner:         strings.Repeat("a", 40),
		WinnerRevision: strings.Repeat("2", 40),
		PRs: []protocol.PRResult{{
			PR: strings.Repeat("a", 40), Revision: strings.Repeat("2", 40),
			Head: strings.Repeat("b", 40), Eligible: true,
		}},
	}

	missingRevision := base
	missingRevision.WinnerRevision = ""
	if _, _, err := exactWinnerRevision(missingRevision); err == nil || !strings.Contains(err.Error(), "no exact winner revision") {
		t.Fatalf("missing exact revision was accepted: %v", err)
	}

	duplicate := base
	duplicate.PRs = append(duplicate.PRs, duplicate.PRs[0])
	if _, _, err := exactWinnerRevision(duplicate); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate exact revision was accepted: %v", err)
	}

	wrongHead := base
	wrongHead.CanonicalHead = strings.Repeat("c", 40)
	if _, _, err := exactWinnerRevision(wrongHead); err == nil || !strings.Contains(err.Error(), "differs from canonical") {
		t.Fatalf("wrong canonical head was accepted: %v", err)
	}
}

func TestPrepareContentCIDLocalOnlyMakesNoRPCRequest(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	data := []byte("reviewed local content")
	got, err := prepareContentCID(context.Background(), idena.NewClient(server.URL, ""), data, true)
	if err != nil {
		t.Fatal(err)
	}
	want, err := content.CIDForBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || requests != 0 {
		t.Fatalf("local CID = %s, requests = %d; want %s and zero requests", got, requests, want)
	}
}

func TestRunGCUsesCanonicalNodeEpoch(t *testing.T) {
	root := t.TempDir()
	store, err := content.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.Put([]byte("expired"), protocol.MainnetActivationEpoch+1)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.Put([]byte("retained"), protocol.MainnetActivationEpoch+2)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var rpc struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
		}
		if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
			t.Error(err)
			return
		}
		if rpc.Method != "dna_epoch" {
			t.Errorf("unexpected method %s", rpc.Method)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID,
			"result": map[string]any{"epoch": protocol.MainnetActivationEpoch + 1},
		})
	}))
	defer server.Close()
	if err := runGC(context.Background(), []string{"--content", root, "--rpc", server.URL}); err != nil {
		t.Fatal(err)
	}
	if store.Has(expired) || !store.Has(retained) {
		t.Fatalf("canonical-epoch GC removed the wrong objects: expired=%t retained=%t", store.Has(expired), store.Has(retained))
	}
}

func TestCheckpointHistoryMustStartAtPublishedActivation(t *testing.T) {
	inputs := []protocol.CheckpointInput{{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    protocol.CheckpointBlock{Epoch: protocol.MainnetActivationEpoch + 1},
	}}
	_, _, err := authenticateCheckpointHistory(context.Background(), idena.NewClient("http://127.0.0.1:1", ""), inputs, 1)
	if err == nil || !strings.Contains(err.Error(), "activation epoch") {
		t.Fatalf("incomplete checkpoint history reached RPC authentication: %v", err)
	}
}

func TestScanRejectsLegacyHistoryBeforeContentMutation(t *testing.T) {
	root := t.TempDir()
	historyPath := filepath.Join(root, "legacy-history.json")
	if err := writeJSON(historyPath, []protocol.CheckpointInput{{
		Checkpoint: protocol.CheckpointBlock{Epoch: protocol.MainnetActivationEpoch},
	}}); err != nil {
		t.Fatal(err)
	}
	contentPath := filepath.Join(root, "content")
	err := runScan(context.Background(), []string{
		"--history", historyPath,
		"--history-out", filepath.Join(root, "history.json"),
		"--content", contentPath,
		"--out", filepath.Join(root, "checkpoint-input.json"),
	})
	if err == nil || !strings.Contains(err.Error(), "reducer policy") {
		t.Fatalf("legacy history did not fail at the policy boundary: %v", err)
	}
	if _, statErr := os.Stat(contentPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("content store was mutated before policy rejection: %v", statErr)
	}
}

func TestAppendCheckpointHistoryIsGapFreeAndIdempotent(t *testing.T) {
	first := protocol.CheckpointInput{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint: protocol.CheckpointBlock{
			Epoch:  protocol.MainnetActivationEpoch,
			Height: 100,
			Hash:   "0x" + strings.Repeat("a", 64),
		},
		Actions: []protocol.OnChainAction{},
		Proofs:  map[string]protocol.IdentityProof{},
	}
	history, added, err := appendCheckpointHistory(nil, first)
	if err != nil || !added || len(history) != 1 {
		t.Fatalf("activation append = %d, %t, %v", len(history), added, err)
	}
	history, added, err = appendCheckpointHistory(history, first)
	if err != nil || added || len(history) != 1 {
		t.Fatalf("idempotent append = %d, %t, %v", len(history), added, err)
	}
	conflict := first
	conflict.Checkpoint.Hash = "0x" + strings.Repeat("b", 64)
	if _, _, err := appendCheckpointHistory(history, conflict); err == nil || !strings.Contains(err.Error(), "different record") {
		t.Fatalf("conflicting epoch was accepted: %v", err)
	}
	gap := first
	gap.Checkpoint.Epoch += 2
	gap.Checkpoint.Height++
	if _, _, err := appendCheckpointHistory(history, gap); err == nil || !strings.Contains(err.Error(), "not consecutive") {
		t.Fatalf("history gap was accepted: %v", err)
	}
	next := first
	next.Checkpoint.Epoch++
	next.Checkpoint.Height++
	next.Checkpoint.Hash = "0x" + strings.Repeat("c", 64)
	history, added, err = appendCheckpointHistory(history, next)
	if err != nil || !added || len(history) != 2 {
		t.Fatalf("consecutive append = %d, %t, %v", len(history), added, err)
	}
}

func TestWriteJSONAtomicReplacesCompleteDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-history.json")
	if err := os.WriteFile(path, []byte("truncated"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := []protocol.CheckpointInput{{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    protocol.CheckpointBlock{Epoch: protocol.MainnetActivationEpoch},
		Actions:       []protocol.OnChainAction{},
		Proofs:        map[string]protocol.IdentityProof{},
	}}
	if err := writeJSONAtomic(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := readCheckpointHistory(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("atomic history = %+v, want %+v", got, want)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".checkpoint-history.json.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain after atomic write: %v", matches)
	}
}

func TestShareUIIPinsAndPlansWithoutBroadcast(t *testing.T) {
	root := t.TempDir()
	contentDir := filepath.Join(root, "content")
	store, err := content.Open(contentDir)
	if err != nil {
		t.Fatal(err)
	}
	diffCID, err := store.Put([]byte("+new\n"), 2)
	if err != nil {
		t.Fatal(err)
	}
	_ = diffCID
	checkpointBlock := protocol.CheckpointBlock{
		Epoch:     protocol.MainnetActivationEpoch,
		Height:    20,
		Hash:      "0x" + strings.Repeat("a", 64),
		StateRoot: "0x" + strings.Repeat("b", 64),
		Time:      100,
	}
	input := protocol.CheckpointInput{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    checkpointBlock,
		Actions:       []protocol.OnChainAction{},
		Proofs:        map[string]protocol.IdentityProof{},
	}
	expected, err := protocol.ReduceFixture(input, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	inputPath := filepath.Join(root, "input.json")
	if err := writeJSON(inputPath, input); err != nil {
		t.Fatal(err)
	}
	checkpointPath := filepath.Join(root, "checkpoint.json")
	if err := writeJSON(checkpointPath, expected); err != nil {
		t.Fatal(err)
	}
	radHome := filepath.Join(root, "rad-home")
	if err := os.MkdirAll(filepath.Join(radHome, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{
		filepath.Join(radHome, "config.json"):         "{}\n",
		filepath.Join(radHome, "keys", "radicle.pub"): "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6Ul/D+P0I/Hl1JVOWGS8Z589us9FqKQXWv8OMOpKCh verifier\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	contractCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var rpc struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch rpc.Method {
		case "bcn_blockAt":
			var height uint64
			_ = json.Unmarshal(rpc.Params[0], &height)
			switch height {
			case 18:
				result = map[string]any{"hash": "0x" + strings.Repeat("8", 64), "height": 18, "timestamp": int64(80), "root": "0x" + strings.Repeat("7", 64), "flags": []string{"ValidationFinished"}}
			case 19:
				result = map[string]any{"hash": "0x" + strings.Repeat("9", 64), "parentHash": "0x" + strings.Repeat("8", 64), "height": 19, "timestamp": int64(90), "root": "0x" + strings.Repeat("6", 64), "flags": []string{}}
			case 20:
				result = map[string]any{"hash": checkpointBlock.Hash, "parentHash": "0x" + strings.Repeat("9", 64), "height": 20, "timestamp": checkpointBlock.Time, "root": checkpointBlock.StateRoot, "flags": []string{"ValidationFinished"}}
			default:
				t.Errorf("unexpected block %d", height)
			}
		case "dna_epochCheckpoint":
			result = map[string]any{"height": 20, "blockHash": checkpointBlock.Hash, "stateRoot": checkpointBlock.StateRoot, "epoch": protocol.MainnetActivationEpoch + 1}
		case "ipfs_add":
			result = "bafkreitest"
		case "dna_getCoinbaseAddr":
			result = "0x1"
		case "contract_estimateCall":
			result = map[string]any{"success": true, "txFee": "0.001", "gasCost": "0.0001"}
		case "contract_call":
			contractCalls++
			result = "0xpost"
		default:
			t.Errorf("unexpected method %s", rpc.Method)
			result = map[string]any{}
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID, "result": result,
		})
	}))
	defer server.Close()

	outputPath := filepath.Join(root, "preview.html")
	err = runShareUI(context.Background(), []string{
		"--rpc", server.URL,
		"--input", inputPath,
		"--checkpoint", checkpointPath,
		"--content", contentDir,
		"--out", outputPath,
		"--rad-home", radHome,
	})
	if err != nil {
		t.Fatal(err)
	}
	var plan webui.SocialPostPlan
	if err := readJSON(outputPath+".social.json", &plan); err != nil {
		t.Fatal(err)
	}
	if plan.TxHash != "" || plan.From != "0x1" || plan.MaxFee != "0.0022" ||
		!strings.Contains(plan.Message, "idena-radicle://bafkreitest") ||
		!strings.Contains(plan.Argument, `"channelId":"r/idena"`) {
		t.Fatalf("unexpected post plan: %+v", plan)
	}

	broadcastPath := filepath.Join(root, "broadcast.html")
	err = runShareUI(context.Background(), []string{
		"--rpc", server.URL,
		"--input", inputPath,
		"--checkpoint", checkpointPath,
		"--content", contentDir,
		"--out", broadcastPath,
		"--rad-home", radHome,
		"--broadcast",
		"--max-fee", "0.003",
	})
	if err == nil || !strings.Contains(err.Error(), "direct share-ui broadcast is disabled") {
		t.Fatalf("direct social broadcast was not rejected: %v", err)
	}
	if contractCalls != 0 {
		t.Fatalf("share-ui made %d contract call(s)", contractCalls)
	}
}
