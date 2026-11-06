package radicle_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/gitutil"
	"idena-git-forge/internal/protocol"
	radicleforge "idena-git-forge/internal/radicle"
)

func TestGovernedRadicleCheckpointWithThreeIdentityQuorum(t *testing.T) {
	binary := os.Getenv("RAD_BIN")
	if binary == "" {
		t.Skip("set RAD_BIN to the reviewed Idena Heartwood CLI to run this integration test")
	}
	ctx := context.Background()
	root := t.TempDir()
	alice := setupProfile(t, binary, root, "alice", "abababababababababababababababababababababababababababababababab")
	bob := setupProfile(t, binary, root, "bob", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
	charlie := setupProfile(t, binary, root, "charlie", "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef")
	repository, rid, base := setupRepository(t, binary, root, alice)
	identityJSON := alice.command(t, repository, binary, "inspect", "--identity", rid)
	var identityDocument map[string]any
	if err := json.Unmarshal([]byte(identityJSON), &identityDocument); err != nil {
		t.Fatal(err)
	}
	if identityDocument["version"] != float64(3) || identityDocument["initializer"] != alice.did || identityDocument["delegates"] != nil || identityDocument["threshold"] != nil {
		t.Fatalf("repository identity still embeds delegate authority: %s", identityJSON)
	}

	copyTree(t, filepath.Join(alice.home, "storage", strings.TrimPrefix(rid, "rad:")), filepath.Join(bob.home, "storage", strings.TrimPrefix(rid, "rad:")))
	copyTree(t, filepath.Join(alice.home, "storage", strings.TrimPrefix(rid, "rad:")), filepath.Join(charlie.home, "storage", strings.TrimPrefix(rid, "rad:")))

	// Bob has no identity-document authority, but can still publish a patch.
	patchID, revisionID, head := createPatch(t, repository, bob, rid)
	fetchNamespace(t, alice.home, bob.home, rid)
	fetchNamespace(t, charlie.home, bob.home, rid)
	aliceClient := radicleforge.Client{
		Binary:               binary,
		Home:                 alice.home,
		Passphrase:           alice.passphrase,
		ExpectedBinarySHA256: binarySHA256ForTest(t, binary),
	}
	if err := aliceClient.VerifySubject(ctx, protocol.RadicleSubject{
		RID: rid, ActorDID: alice.did, Kind: protocol.KindRepository, Head: base,
	}); err != nil {
		t.Fatalf("initializer repository action was rejected: %v", err)
	}
	if err := aliceClient.VerifySubject(ctx, protocol.RadicleSubject{
		RID: rid, ActorDID: bob.did, Kind: protocol.KindRepository, Head: head,
	}); err == nil {
		t.Fatalf("foreign actor captured repository initialization: %v", err)
	}
	alice.rad(t, repository, "patch", "cache", "--repo", rid, "--storage")
	charlie.rad(t, repository, "patch", "cache", "--repo", rid, "--storage")

	bob.rad(t, repository, "patch", "review", patchID, "--accept", "--message", "Bob accepts the exact Radicle revision.", "--no-announce", "--repo", rid)
	alice.rad(t, repository, "patch", "review", patchID, "--accept", "--no-message", "--no-announce", "--repo", rid)
	charlie.rad(t, repository, "patch", "review", patchID, "--reject", "--message", "Charlie rejects the exact Radicle revision.", "--no-announce", "--repo", rid)
	alice.rad(t, repository, "patch", "label", patchID, "--add", "idena/merge-request", "--no-announce", "--repo", rid)
	fetchNamespace(t, alice.home, bob.home, rid)
	fetchNamespace(t, alice.home, charlie.home, rid)

	entries, err := aliceClient.CobLog(ctx, rid, radicleforge.PatchType, patchID)
	if err != nil {
		t.Fatal(err)
	}
	var aliceReview, bobReview, charlieReview, mergeLabel string
	for _, entry := range entries {
		for _, raw := range entry.Actions {
			var action radicleforge.CobAction
			if err := json.Unmarshal(raw, &action); err != nil {
				t.Fatal(err)
			}
			switch action.Type {
			case "review":
				if entry.Author == strings.TrimPrefix(alice.did, "did:key:") {
					aliceReview = entry.ID
				}
				if entry.Author == strings.TrimPrefix(bob.did, "did:key:") {
					bobReview = entry.ID
				}
				if entry.Author == strings.TrimPrefix(charlie.did, "did:key:") {
					charlieReview = entry.ID
				}
			case "label":
				for _, label := range action.Labels {
					if label == radicleforge.MergeRequestLabel {
						mergeLabel = entry.ID
					}
				}
			}
		}
	}
	if aliceReview == "" || bobReview == "" || charlieReview == "" || mergeLabel == "" {
		t.Fatalf("missing Radicle operations: alice=%q bob=%q charlie=%q label=%q", aliceReview, bobReview, charlieReview, mergeLabel)
	}

	bundle, err := aliceClient.ExportBundle(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	replicaClient := radicleforge.Client{
		Binary:               binary,
		Home:                 filepath.Join(root, "replica"),
		ExpectedBinarySHA256: binarySHA256ForTest(t, binary),
	}
	if err := replicaClient.ImportBundle(ctx, rid, alice.did, bundle); err != nil {
		t.Fatalf("import signed delegate-free bundle: %v", err)
	}
	replicaStorage := filepath.Join(replicaClient.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	if output, err := exec.Command("git", "-C", replicaStorage, "for-each-ref", "--format=%(refname)", "refs/idena").CombinedOutput(); err != nil {
		t.Fatal(err)
	} else if strings.TrimSpace(string(output)) != "" {
		t.Fatalf("bundle imported protected Idena authority refs: %s", output)
	}
	if err := replicaClient.WriteGenesisHead(ctx, rid, base); err != nil {
		t.Fatal(err)
	}
	store, err := content.Open(filepath.Join(root, "content"))
	if err != nil {
		t.Fatal(err)
	}
	bundleCID, err := store.Put(bundle, 11)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinRepository(bundleCID, rid); err != nil {
		t.Fatal(err)
	}
	diff := []byte(alice.command(t, repository, binary, "patch", "diff", patchID, "--quiet", "--no-announce", "--repo", rid))
	diffCID, err := store.Put(diff, 11)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinRepository(diffCID, rid); err != nil {
		t.Fatal(err)
	}

	idenaA := newIdenaKey(t)
	idenaB := newIdenaKey(t)
	idenaC := newIdenaKey(t)
	proofs, stateRoot := identityProofSet(t, []identityStake{
		{idenaA, 250_000, 8},
		{idenaB, 150_000, 3},
		{idenaC, 100_000, 7},
	})
	checkpointHashBytes := sha256.Sum256([]byte("radicle-governed-" + stateRoot))
	checkpoint := protocol.CheckpointBlock{
		Epoch:     9,
		Height:    900,
		Hash:      "0x" + hex.EncodeToString(checkpointHashBytes[:]),
		StateRoot: stateRoot,
	}
	for address, proof := range proofs {
		proof.Height, proof.BlockHash = checkpoint.Height, checkpoint.Hash
		proof.Epoch, proof.StateEpoch, proof.Source = checkpoint.Epoch, checkpoint.Epoch+1, "idena-rpc"
		proofs[address] = proof
	}

	contentMap := map[string]bool{bundleCID: true, diffCID: true}
	patchEnvelope := makeAnchor(t, bob, idenaB, rid, protocol.KindPullRequest, "00000000000000000000000000000001", protocol.PullRequestPayload{
		Patch: patchID, Revision: revisionID, Title: "Radicle governed patch",
		Base: base, Head: head, Bundle: bundleCID, Diff: diffCID, ActorDID: bob.did,
	}, store, 11, contentMap)
	aliceVote := makeAnchor(t, alice, idenaA, rid, protocol.KindVote, "00000000000000000000000000000002", protocol.VotePayload{
		Patch: patchID, Revision: revisionID, Decision: protocol.DecisionApprove,
		Review: aliceReview, ActionOID: aliceReview, Bundle: bundleCID, ActorDID: alice.did,
	}, store, 11, contentMap)
	bobVote := makeAnchor(t, bob, idenaB, rid, protocol.KindVote, "00000000000000000000000000000003", protocol.VotePayload{
		Patch: patchID, Revision: revisionID, Decision: protocol.DecisionApprove,
		Review: bobReview, ActionOID: bobReview, Bundle: bundleCID, ActorDID: bob.did,
	}, store, 11, contentMap)
	charlieVote := makeAnchor(t, charlie, idenaC, rid, protocol.KindVote, "00000000000000000000000000000005", protocol.VotePayload{
		Patch: patchID, Revision: revisionID, Decision: protocol.DecisionReject,
		Review: charlieReview, ActionOID: charlieReview, Bundle: bundleCID, ActorDID: charlie.did,
	}, store, 11, contentMap)
	mergeLabelAnchor := makeAnchor(t, alice, idenaA, rid, protocol.KindMergeRequest, "00000000000000000000000000000004", protocol.MergeRequestPayload{
		Patch: patchID, Revision: revisionID, Label: radicleforge.MergeRequestLabel,
		LabelAction: mergeLabel, Bundle: bundleCID, ActorDID: alice.did,
	}, store, 11, contentMap)

	input := protocol.CheckpointInput{
		Checkpoint: checkpoint,
		Actions: []protocol.OnChainAction{
			onChain(t, patchEnvelope, 0),
			onChain(t, aliceVote, 1),
			onChain(t, bobVote, 2),
			onChain(t, charlieVote, 3),
			onChain(t, mergeLabelAnchor, 4),
		},
		Proofs:        proofs,
		PreviousHeads: map[string]string{rid: base},
	}
	radicleVerifier := radicleforge.ContentVerifier{Client: radicleforge.VerificationClient{
		Binary:               aliceClient.Binary,
		Home:                 aliceClient.Home,
		ExpectedBinarySHA256: aliceClient.ExpectedBinarySHA256,
	}, Store: store}
	result, err := protocol.ReduceFixture(input, func(bundleID, base, head string) error {
		data, err := store.Get(bundleID)
		if err != nil {
			return err
		}
		return gitutil.VerifyBundleAndFastForward(ctx, data, base, head)
	}, func(envelope protocol.Envelope) error {
		return radicleforge.VerifyBinding(ctx, envelope)
	}, func(subject protocol.RadicleSubject) error {
		return radicleVerifier.Verify(ctx, subject)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Repositories) != 1 || result.Repositories[0].Winner != patchID {
		t.Fatalf("unexpected checkpoint: %+v", result)
	}
	if result.Repositories[0].CanonicalHead != head {
		t.Fatalf("canonical head = %s, want %s", result.Repositories[0].CanonicalHead, head)
	}
	if outputDirectory := os.Getenv("RAD_FIXTURE_OUT"); outputDirectory != "" {
		if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
			t.Fatal(err)
		}
		writeJSONFile(t, filepath.Join(outputDirectory, "checkpoint-input.json"), input)
		writeJSONFile(t, filepath.Join(outputDirectory, "checkpoint.json"), result)
		copyTree(t, filepath.Join(root, "content"), filepath.Join(outputDirectory, "content"))
	}
	if err := aliceClient.WriteGovernanceHead(ctx, rid, checkpoint.Epoch, head); err != nil {
		t.Fatal(err)
	}
	ref := fmt.Sprintf("refs/idena/epoch/%d/canonical", checkpoint.Epoch)
	storage := filepath.Join(alice.home, "storage", strings.TrimPrefix(rid, "rad:"))
	actual := strings.TrimSpace(alice.command(t, storage, "git", "rev-parse", ref))
	if actual != head {
		t.Fatalf("governance ref = %s, want %s", actual, head)
	}
	genesisHead := strings.TrimSpace(alice.command(t, storage, "git", "rev-parse", "refs/idena/genesis/canonical"))
	if genesisHead != base {
		t.Fatalf("bootstrap head changed through governance: %s", genesisHead)
	}
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

type profile struct {
	home       string
	passphrase string
	did        string
	binary     string
	env        []string
}

func setupProfile(t *testing.T, binary, root, name, seed string) profile {
	t.Helper()
	home := filepath.Join(root, "rad-"+name)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	passphrase := "radicle-" + name
	env := append(os.Environ(),
		"RAD_HOME="+home,
		"RAD_PASSPHRASE="+passphrase,
		"RAD_KEYGEN_SEED="+seed,
		"PATH="+filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	runCommand(t, env, root, binary, "auth", "--alias", name)
	publicKey, err := os.ReadFile(filepath.Join(home, "keys", "radicle.pub"))
	if err != nil {
		t.Fatal(err)
	}
	did, _, err := radicleforge.DIDForKey(string(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	return profile{home: home, passphrase: passphrase, did: did, binary: binary, env: env}
}

func setupRepository(t *testing.T, binary, root string, actor profile) (string, string, string) {
	t.Helper()
	repository := filepath.Join(root, "source")
	if err := os.MkdirAll(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	runCommand(t, actor.env, repository, "git", "init", "-b", "main")
	runCommand(t, actor.env, repository, "git", "config", "user.name", "Radicle Governance")
	runCommand(t, actor.env, repository, "git", "config", "user.email", "radicle@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("# governed Radicle\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runCommand(t, actor.env, repository, "git", "add", "README.md")
	runCommand(t, actor.env, repository, "git", "commit", "-m", "Initial")
	base := strings.TrimSpace(runCommand(t, actor.env, repository, "git", "rev-parse", "HEAD"))
	output := runCommand(t, actor.env, repository, binary, "init", "--name", "governed", "--description", "Idena governed repository", "--default-branch", "main", "--public", "--no-seed", "--no-confirm", "--setup-signing")
	rid := mustMatch(t, `rad:z[1-9A-HJ-NP-Za-km-z]+`, output)
	return repository, rid, base
}

func createPatch(t *testing.T, repository string, actor profile, rid string) (patchID, revisionID, head string) {
	t.Helper()
	remoteURL := fmt.Sprintf("rad://%s/%s", strings.TrimPrefix(rid, "rad:"), strings.TrimPrefix(actor.did, "did:key:"))
	runCommand(t, actor.env, repository, "git", "config", "remote.rad.pushurl", remoteURL)
	runCommand(t, actor.env, repository, "git", "checkout", "-b", "feature/governed")
	if err := os.WriteFile(filepath.Join(repository, "change.txt"), []byte("governed change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runCommand(t, actor.env, repository, "git", "add", "change.txt")
	runCommand(t, actor.env, repository, "git", "commit", "-m", "Governed change")
	head = strings.TrimSpace(runCommand(t, actor.env, repository, "git", "rev-parse", "HEAD"))
	output := runCommand(t, actor.env, repository, "git", "push", "-o", "patch.message=Radicle governed patch", "rad", "HEAD:refs/patches")
	patchID = mustMatch(t, `[0-9a-f]{40}`, output)
	client := radicleforge.Client{
		Binary:               actor.binary,
		Home:                 actor.home,
		ExpectedBinarySHA256: binarySHA256ForTest(t, actor.binary),
	}
	entries, err := client.CobLog(context.Background(), rid, radicleforge.PatchType, patchID)
	if err != nil {
		t.Fatal(err)
	}
	revisionID = patchID
	for _, entry := range entries {
		for _, raw := range entry.Actions {
			var action radicleforge.CobAction
			if json.Unmarshal(raw, &action) == nil && action.Type == "revision" {
				revisionID = entry.ID
				head = action.OID
				return patchID, revisionID, head
			}
		}
	}
	return patchID, revisionID, head
}

func fetchNamespace(t *testing.T, aliceHome, bobHome, rid string) {
	t.Helper()
	aliceStorage := filepath.Join(aliceHome, "storage", strings.TrimPrefix(rid, "rad:"))
	bobStorage := filepath.Join(bobHome, "storage", strings.TrimPrefix(rid, "rad:"))
	pattern := fmt.Sprintf("refs/namespaces/%s/*:refs/namespaces/%s/*", strings.TrimPrefix(bobDID(t, bobHome), "did:key:"), strings.TrimPrefix(bobDID(t, bobHome), "did:key:"))
	command := exec.Command("git", "-C", aliceStorage, "fetch", bobStorage, pattern)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fetch Bob namespace: %v: %s", err, output)
	}
}

func bobDID(t *testing.T, home string) string {
	t.Helper()
	publicKey, err := os.ReadFile(filepath.Join(home, "keys", "radicle.pub"))
	if err != nil {
		t.Fatal(err)
	}
	did, _, err := radicleforge.DIDForKey(string(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	return did
}

func copyTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("cp", "-R", source, destination)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("copy Radicle storage: %v: %s", err, output)
	}
}

func (actor profile) rad(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	return runCommand(t, actor.env, directory, actor.binary, arguments...)
}

func (actor profile) command(t *testing.T, directory, name string, arguments ...string) string {
	t.Helper()
	return runCommand(t, actor.env, directory, name, arguments...)
}

func makeAnchor(t *testing.T, actor profile, idenaKey *ecdsa.PrivateKey, rid, kind, nonce string, payload any, store *content.Store, pinUntil uint16, contentMap map[string]bool) protocol.Envelope {
	t.Helper()
	publicKey, err := os.ReadFile(filepath.Join(actor.home, "keys", "radicle.pub"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.NewEnvelope(kind, rid, 9, protocol.AddressFromPrivateKey(idenaKey), actor.did, string(publicKey), nonce, payload)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := radicleforge.SignBinding(context.Background(), filepath.Join(actor.home, "keys", "radicle"), envelope.RadicleBindingMessage())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = binding
	if err := envelope.Sign(idenaKey); err != nil {
		t.Fatal(err)
	}
	encoded, err := envelope.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	actionCID, err := store.Put(encoded, pinUntil)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PinRepository(actionCID, rid); err != nil {
		t.Fatal(err)
	}
	contentMap[actionCID] = true
	return *envelope
}

func onChain(t *testing.T, envelope protocol.Envelope, index uint32) protocol.OnChainAction {
	t.Helper()
	encoded, err := envelope.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	actionCID, _ := content.CIDForBytes(encoded)
	hash := sha256.Sum256(encoded)
	return protocol.OnChainAction{
		Height:      899,
		BlockHash:   "0x" + strings.Repeat("a", 64),
		TxHash:      "0x" + hex.EncodeToString(hash[:]),
		TxIndex:     index,
		TxType:      "send",
		TxSender:    envelope.Author,
		TxRecipient: envelope.Author,
		TxEpoch:     9,
		ActionCID:   actionCID,
		ActionBytes: encoded,
	}
}

func newIdenaKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type identityStake struct {
	key   *ecdsa.PrivateKey
	units int64
	state uint16
}

type identityProofLeaf struct {
	identity identityStake
	address  string
	key      []byte
	value    []byte
	hash     []byte
}

type identityProofNode struct {
	height int64
	size   int64
	hash   []byte
	leaf   *identityProofLeaf
	left   *identityProofNode
	right  *identityProofNode
}

func identityProofSet(t *testing.T, identities []identityStake) (map[string]protocol.IdentityProof, string) {
	t.Helper()
	var leaves []*identityProofLeaf
	for _, identity := range identities {
		address := protocol.AddressFromPrivateKey(identity.key)
		addressBytes, _ := hex.DecodeString(strings.TrimPrefix(address, "0x"))
		keyBytes := append([]byte{0x02}, addressBytes...)
		stake := protocol.RawStakeFromUnits(identity.units)
		value := protowire.AppendTag(nil, 1, protowire.BytesType)
		value = protowire.AppendBytes(value, stake.Bytes())
		value = protowire.AppendTag(value, 4, protowire.VarintType)
		value = protowire.AppendVarint(value, uint64(identity.state))
		valueHash := sha256.Sum256(value)
		leaves = append(leaves, &identityProofLeaf{
			identity: identity,
			address:  address,
			key:      keyBytes,
			value:    value,
			hash:     testIAVLLeafHash(keyBytes, valueHash[:], 1),
		})
	}
	sort.Slice(leaves, func(i, j int) bool {
		return bytes.Compare(leaves[i].key, leaves[j].key) < 0
	})
	var build func([]*identityProofLeaf) *identityProofNode
	build = func(items []*identityProofLeaf) *identityProofNode {
		if len(items) == 1 {
			return &identityProofNode{size: 1, hash: items[0].hash, leaf: items[0]}
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
		return &identityProofNode{
			height: height,
			size:   size,
			hash:   testIAVLNodeHash(height, size, 1, left.hash, right.hash),
			left:   left,
			right:  right,
		}
	}
	root := build(leaves)
	var pathFor func(*identityProofNode, *identityProofLeaf) []protocol.ProofStep
	pathFor = func(node *identityProofNode, target *identityProofLeaf) []protocol.ProofStep {
		if node.leaf != nil {
			return []protocol.ProofStep{}
		}
		step := protocol.ProofStep{Height: int16(node.height), Size: uint64(node.size), Version: 1}
		if identityLeafIn(node.left, target) {
			step.Right = "0x" + hex.EncodeToString(node.right.hash)
			return append([]protocol.ProofStep{step}, pathFor(node.left, target)...)
		}
		step.Left = "0x" + hex.EncodeToString(node.left.hash)
		return append([]protocol.ProofStep{step}, pathFor(node.right, target)...)
	}
	rootHex := "0x" + hex.EncodeToString(root.hash)
	proofs := make(map[string]protocol.IdentityProof, len(leaves))
	for _, current := range leaves {
		valueHash := sha256.Sum256(current.value)
		proofs[current.address] = protocol.IdentityProof{
			Height: 900, StateRoot: rootHex, Address: current.address,
			Value: "0x" + hex.EncodeToString(current.value),
			Stake: protocol.RawStakeFromUnits(current.identity.units).String(),
			State: current.identity.state, StateName: protocol.IdentityStateName(current.identity.state),
			Leaf: protocol.ProofLeaf{Key: "0x" + hex.EncodeToString(current.key), ValueHash: "0x" + hex.EncodeToString(valueHash[:]), Version: 1},
			Path: pathFor(root, current),
		}
	}
	for address, proof := range proofs {
		if err := protocol.VerifyIdentityProof(proof, rootHex); err != nil {
			t.Fatalf("test proof for %s is invalid: %v", address, err)
		}
	}
	return proofs, rootHex
}

func identityLeafIn(node *identityProofNode, target *identityProofLeaf) bool {
	if node == nil {
		return false
	}
	if node.leaf != nil {
		return node.leaf == target
	}
	return identityLeafIn(node.left, target) || identityLeafIn(node.right, target)
}

func testIAVLLeafHash(key, valueHash []byte, version int64) []byte {
	var buffer bytes.Buffer
	writeVarint(&buffer, 0)
	writeVarint(&buffer, 1)
	writeVarint(&buffer, version)
	writeBytes(&buffer, key)
	writeBytes(&buffer, valueHash)
	hash := sha256.Sum256(buffer.Bytes())
	return hash[:]
}

func testIAVLNodeHash(height, size, version int64, left, right []byte) []byte {
	var buffer bytes.Buffer
	writeVarint(&buffer, height)
	writeVarint(&buffer, size)
	writeVarint(&buffer, version)
	writeBytes(&buffer, left)
	writeBytes(&buffer, right)
	hash := sha256.Sum256(buffer.Bytes())
	return hash[:]
}

func writeVarint(buffer *bytes.Buffer, value int64) {
	var scratch [binary.MaxVarintLen64]byte
	length := binary.PutVarint(scratch[:], value)
	buffer.Write(scratch[:length])
}

func writeBytes(buffer *bytes.Buffer, value []byte) {
	var scratch [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(scratch[:], uint64(len(value)))
	buffer.Write(scratch[:length])
	buffer.Write(value)
}

func binarySHA256ForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
