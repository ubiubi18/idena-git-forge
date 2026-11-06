package demo

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"google.golang.org/protobuf/encoding/protowire"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/gitutil"
	"idena-git-forge/internal/protocol"
)

type Result struct {
	Root           string `json:"root"`
	InputPath      string `json:"inputPath"`
	CheckpointPath string `json:"checkpointPath"`
	ContentDir     string `json:"contentDir"`
}

func Run(ctx context.Context, root string) (*Result, error) {
	if root == "" {
		return nil, errors.New("demo output directory is required")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	root = absoluteRoot
	if _, err := os.Stat(root); err == nil {
		return nil, errors.New("demo output already exists; choose a new directory")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}

	source := filepath.Join(root, "source")
	if err := os.MkdirAll(source, 0o755); err != nil {
		return nil, err
	}
	if err := initializeGit(ctx, source); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(source, "README.md"), []byte("# Idena Forge Demo\n\nA signed PR settled from an epoch checkpoint.\n"), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello\n"), 0o644); err != nil {
		return nil, err
	}
	if err := git(ctx, source, "add", "README.md", "hello.txt"); err != nil {
		return nil, err
	}
	if err := git(ctx, source, "commit", "-m", "Add forge demo"); err != nil {
		return nil, err
	}
	base, err := gitOutput(ctx, source, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	base = strings.TrimSpace(base)
	if err := os.WriteFile(filepath.Join(source, "hello.txt"), []byte("hello from Idena\n"), 0o644); err != nil {
		return nil, err
	}
	if err := git(ctx, source, "commit", "-am", "Make the demo message identity aware"); err != nil {
		return nil, err
	}
	head, err := gitOutput(ctx, source, "rev-parse", "HEAD")
	if err != nil {
		return nil, err
	}
	head = strings.TrimSpace(head)

	bundlePath := filepath.Join(root, "pr.bundle")
	if err := gitutil.CreateBundle(ctx, source, "HEAD", bundlePath); err != nil {
		return nil, err
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, err
	}
	diff, err := gitutil.CreateDiff(ctx, source, base, head)
	if err != nil {
		return nil, err
	}

	store, err := content.Open(filepath.Join(root, "content"))
	if err != nil {
		return nil, err
	}
	const epoch = uint16(42)
	pinUntil := epoch + 2
	bundleCID, err := store.Put(bundle, pinUntil)
	if err != nil {
		return nil, err
	}
	diffCID, err := store.Put(diff, pinUntil)
	if err != nil {
		return nil, err
	}
	for _, contentCID := range []string{bundleCID, diffCID} {
		if err := store.PinRepository(contentCID, demoRID); err != nil {
			return nil, err
		}
	}
	authorKey, secondVoterKey, thirdVoterKey, err := demoKeys()
	if err != nil {
		return nil, err
	}
	author := protocol.AddressFromPrivateKey(authorKey)
	secondVoter := protocol.AddressFromPrivateKey(secondVoterKey)
	thirdVoter := protocol.AddressFromPrivateKey(thirdVoterKey)
	repositoryEnvelope, err := protocol.NewEnvelope(protocol.KindRepository, demoRID, epoch, author, demoDID, demoPublicKey, "00000000000000000000000000000000", protocol.RepositoryPayload{
		Head: base, Bundle: bundleCID, ActorDID: demoDID,
	})
	if err != nil {
		return nil, err
	}
	repositoryEnvelope.Binding = "demo-binding"
	if err := repositoryEnvelope.Sign(authorKey); err != nil {
		return nil, err
	}
	prPayload := protocol.PullRequestPayload{
		Patch:    strings.Repeat("c", 64),
		Revision: strings.Repeat("d", 64),
		Title:    "Make first contact deterministic",
		Base:     base,
		Head:     head,
		Bundle:   bundleCID,
		Diff:     diffCID,
		ActorDID: demoDID,
	}
	revision, err := protocol.Revision(prPayload)
	if err != nil {
		return nil, err
	}

	prEnvelope, err := protocol.NewEnvelope(protocol.KindPullRequest, demoRID, epoch, author, demoDID, demoPublicKey, "00000000000000000000000000000001", prPayload)
	if err != nil {
		return nil, err
	}
	prEnvelope.Binding = "demo-binding"
	if err := prEnvelope.Sign(authorKey); err != nil {
		return nil, err
	}
	voteA, err := protocol.NewEnvelope(protocol.KindVote, demoRID, epoch, author, demoDID, demoPublicKey, "00000000000000000000000000000002", protocol.VotePayload{Patch: prPayload.Patch, Revision: revision, Decision: protocol.DecisionApprove, Review: strings.Repeat("e", 64), ActionOID: strings.Repeat("e", 64), Bundle: bundleCID, ActorDID: demoDID})
	if err != nil {
		return nil, err
	}
	voteA.Binding = "demo-binding"
	if err := voteA.Sign(authorKey); err != nil {
		return nil, err
	}
	voteB, err := protocol.NewEnvelope(protocol.KindVote, demoRID, epoch, secondVoter, demoDID, demoPublicKey, "00000000000000000000000000000003", protocol.VotePayload{Patch: prPayload.Patch, Revision: revision, Decision: protocol.DecisionApprove, Review: strings.Repeat("f", 64), ActionOID: strings.Repeat("f", 64), Bundle: bundleCID, ActorDID: demoDID})
	if err != nil {
		return nil, err
	}
	voteB.Binding = "demo-binding"
	if err := voteB.Sign(secondVoterKey); err != nil {
		return nil, err
	}
	voteC, err := protocol.NewEnvelope(protocol.KindVote, demoRID, epoch, thirdVoter, demoDID, demoPublicKey, "00000000000000000000000000000005", protocol.VotePayload{Patch: prPayload.Patch, Revision: revision, Decision: protocol.DecisionReject, Review: strings.Repeat("9", 64), ActionOID: strings.Repeat("9", 64), Bundle: bundleCID, ActorDID: demoDID})
	if err != nil {
		return nil, err
	}
	voteC.Binding = "demo-binding"
	if err := voteC.Sign(thirdVoterKey); err != nil {
		return nil, err
	}
	mergeRequest, err := protocol.NewEnvelope(protocol.KindMergeRequest, demoRID, epoch, author, demoDID, demoPublicKey, "00000000000000000000000000000004", protocol.MergeRequestPayload{Patch: prPayload.Patch, Revision: revision, Label: "idena/merge-request", LabelAction: strings.Repeat("a", 64), Bundle: bundleCID, ActorDID: demoDID})
	if err != nil {
		return nil, err
	}
	mergeRequest.Binding = "demo-binding"
	if err := mergeRequest.Sign(authorKey); err != nil {
		return nil, err
	}

	consensusInput := protocol.CheckpointInput{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Actions:       []protocol.OnChainAction{},
		Proofs:        make(map[string]protocol.IdentityProof),
	}
	envelopes := []*protocol.Envelope{repositoryEnvelope, prEnvelope, voteA, voteB, voteC, mergeRequest}
	for index, envelope := range envelopes {
		encoded, err := envelope.Bytes()
		if err != nil {
			return nil, err
		}
		actionCID, err := store.Put(encoded, pinUntil)
		if err != nil {
			return nil, err
		}
		if err := store.PinRepository(actionCID, demoRID); err != nil {
			return nil, err
		}
		txHash := sha256.Sum256(append(encoded, byte(index)))
		consensusInput.Actions = append(consensusInput.Actions, protocol.OnChainAction{
			Height:      123456,
			BlockHash:   "",
			TxHash:      "0x" + hex.EncodeToString(txHash[:]),
			TxIndex:     uint32(index),
			TxType:      "send",
			TxSender:    envelope.Author,
			TxRecipient: envelope.Author,
			TxEpoch:     epoch,
			ActionCID:   actionCID,
			ActionBytes: encoded,
		})
	}
	proofs, stateRoot, err := identityProofSet([]demoIdentity{
		{authorKey, author, 250_000, 8},
		{secondVoterKey, secondVoter, 150_000, 7},
		{thirdVoterKey, thirdVoter, 100_000, 3},
	}, epoch)
	if err != nil {
		return nil, err
	}
	checkpointHash := sha256.Sum256([]byte("demo-checkpoint:" + stateRoot))
	consensusInput.Checkpoint = protocol.CheckpointBlock{
		Epoch:     epoch,
		Height:    123457,
		Hash:      "0x" + hex.EncodeToString(checkpointHash[:]),
		StateRoot: stateRoot,
		Time:      time.Now().Unix(),
	}
	for index := range consensusInput.Actions {
		consensusInput.Actions[index].BlockHash = consensusInput.Checkpoint.Hash
	}
	for address, proof := range proofs {
		consensusInput.Proofs[address] = proof
	}

	result, err := protocol.ReduceFixture(consensusInput, func(bundleContentCID, base, head string) error {
		data, err := store.Get(bundleContentCID)
		if err != nil {
			return err
		}
		return gitutil.VerifyBundleAndFastForward(ctx, data, base, head)
	}, func(protocol.Envelope) error { return nil }, func(protocol.RadicleSubject) error { return nil })
	if err != nil {
		return nil, err
	}
	if len(result.Repositories) != 1 || len(result.Repositories[0].PRs) != 1 || result.Repositories[0].Winner != prPayload.Patch {
		return nil, fmt.Errorf("demo reducer did not select the PR")
	}
	inputPath := filepath.Join(root, "checkpoint-input.json")
	if err := writeJSON(inputPath, consensusInput); err != nil {
		return nil, err
	}
	checkpointPath := filepath.Join(root, "checkpoint.json")
	if err := writeJSON(checkpointPath, result); err != nil {
		return nil, err
	}
	return &Result{
		Root:           root,
		InputPath:      inputPath,
		CheckpointPath: checkpointPath,
		ContentDir:     filepath.Join(root, "content"),
	}, nil
}

const (
	demoRID       = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"
	demoDID       = "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP"
	demoPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o"
)

func initializeGit(ctx context.Context, directory string) error {
	if err := git(ctx, directory, "init", "-b", "main"); err != nil {
		return err
	}
	if err := git(ctx, directory, "config", "user.name", "Idena Forge Demo"); err != nil {
		return err
	}
	return git(ctx, directory, "config", "user.email", "forge@example.invalid")
}

func git(ctx context.Context, directory string, arguments ...string) error {
	_, err := gitOutput(ctx, directory, arguments...)
	return err
}

func gitOutput(ctx context.Context, directory string, arguments ...string) (string, error) {
	output, err := gitutil.Output(ctx, directory, arguments...)
	if err != nil {
		return "", fmt.Errorf("git %v: %w", arguments, err)
	}
	return string(output), nil
}

func demoKeys() (*ecdsa.PrivateKey, *ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	first, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	second, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	third, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	return first, second, third, nil
}

type demoIdentity struct {
	key     *ecdsa.PrivateKey
	address string
	units   int64
	state   uint16
}

type demoLeaf struct {
	identity demoIdentity
	address  string
	keyBytes []byte
	value    []byte
	hash     []byte
}

type demoProofNode struct {
	height int64
	size   int64
	hash   []byte
	leaf   *demoLeaf
	left   *demoProofNode
	right  *demoProofNode
}

func identityProofSet(identities []demoIdentity, epoch uint16) (map[string]protocol.IdentityProof, string, error) {
	var leaves []*demoLeaf
	for _, identity := range identities {
		addressBytes, err := hex.DecodeString(strings.TrimPrefix(identity.address, "0x"))
		if err != nil {
			return nil, "", err
		}
		keyBytes := append([]byte{0x02}, addressBytes...)
		stake := protocol.RawStakeFromUnits(identity.units)
		value := protowire.AppendTag(nil, 1, protowire.BytesType)
		value = protowire.AppendBytes(value, stake.Bytes())
		value = protowire.AppendTag(value, 4, protowire.VarintType)
		value = protowire.AppendVarint(value, uint64(identity.state))
		valueHash := sha256.Sum256(value)
		leaves = append(leaves, &demoLeaf{
			identity: identity,
			address:  identity.address,
			keyBytes: keyBytes,
			value:    value,
			hash:     iavlLeafHash(keyBytes, valueHash[:], 1),
		})
	}
	sort.Slice(leaves, func(i, j int) bool { return bytes.Compare(leaves[i].keyBytes, leaves[j].keyBytes) < 0 })
	var build func([]*demoLeaf) *demoProofNode
	build = func(items []*demoLeaf) *demoProofNode {
		if len(items) == 1 {
			return &demoProofNode{size: 1, hash: items[0].hash, leaf: items[0]}
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
		return &demoProofNode{
			height: height,
			size:   size,
			hash:   demoNodeHash(height, size, 1, left.hash, right.hash),
			left:   left,
			right:  right,
		}
	}
	root := build(leaves)
	stateRoot := "0x" + hex.EncodeToString(root.hash)
	checkpointHash := sha256.Sum256([]byte("demo-checkpoint:" + stateRoot))
	var pathFor func(*demoProofNode, *demoLeaf) []protocol.ProofStep
	pathFor = func(node *demoProofNode, target *demoLeaf) []protocol.ProofStep {
		if node.leaf != nil {
			return []protocol.ProofStep{}
		}
		step := protocol.ProofStep{Height: int16(node.height), Size: uint64(node.size), Version: 1}
		if demoLeafIn(node.left, target) {
			step.Right = "0x" + hex.EncodeToString(node.right.hash)
			return append([]protocol.ProofStep{step}, pathFor(node.left, target)...)
		}
		step.Left = "0x" + hex.EncodeToString(node.left.hash)
		return append([]protocol.ProofStep{step}, pathFor(node.right, target)...)
	}
	proofs := make(map[string]protocol.IdentityProof, len(leaves))
	for _, leaf := range leaves {
		valueHash := sha256.Sum256(leaf.value)
		proofs[leaf.address] = protocol.IdentityProof{
			Epoch:      epoch,
			StateEpoch: epoch + 1,
			Source:     "demo",
			Height:     123457,
			BlockHash:  "0x" + hex.EncodeToString(checkpointHash[:]),
			StateRoot:  stateRoot,
			Address:    leaf.address,
			Value:      "0x" + hex.EncodeToString(leaf.value),
			Stake:      protocol.RawStakeFromUnits(leaf.identity.units).String(),
			State:      leaf.identity.state,
			StateName:  protocol.IdentityStateName(leaf.identity.state),
			Leaf: protocol.ProofLeaf{
				Key:       "0x" + hex.EncodeToString(leaf.keyBytes),
				ValueHash: "0x" + hex.EncodeToString(valueHash[:]),
				Version:   1,
			},
			Path: pathFor(root, leaf),
		}
	}
	for address, proof := range proofs {
		if err := protocol.VerifyIdentityProof(proof, stateRoot); err != nil {
			return nil, "", fmt.Errorf("demo proof for %s: %w", address, err)
		}
	}
	return proofs, stateRoot, nil
}

func demoLeafIn(node *demoProofNode, target *demoLeaf) bool {
	if node == nil {
		return false
	}
	if node.leaf != nil {
		return node.leaf == target
	}
	return demoLeafIn(node.left, target) || demoLeafIn(node.right, target)
}

func iavlLeafHash(key, valueHash []byte, version int64) []byte {
	buffer := new(bytes.Buffer)
	writeVarint(buffer, 0)
	writeVarint(buffer, 1)
	writeVarint(buffer, version)
	writeBytes(buffer, key)
	writeBytes(buffer, valueHash)
	hash := sha256.Sum256(buffer.Bytes())
	return hash[:]
}

func demoNodeHash(height, size, version int64, left, right []byte) []byte {
	buffer := new(bytes.Buffer)
	writeVarint(buffer, height)
	writeVarint(buffer, size)
	writeVarint(buffer, version)
	writeBytes(buffer, left)
	writeBytes(buffer, right)
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

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644)
}
