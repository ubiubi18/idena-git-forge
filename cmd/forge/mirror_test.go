package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/multiformats/go-multibase"
	"golang.org/x/crypto/ssh"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/idena"
	"idena-git-forge/internal/identity"
	"idena-git-forge/internal/protocol"
	radicleforge "idena-git-forge/internal/radicle"
)

const (
	mirrorTestTxHash     = "0x1111111111111111111111111111111111111111111111111111111111111111"
	mirrorTestBlockHash  = "0x2222222222222222222222222222222222222222222222222222222222222222"
	mirrorTestHeight     = uint64(42)
	mirrorTestHeightText = "42"
)

func TestMirrorVerifiesBeforeExplicitPin(t *testing.T) {
	t.Setenv("IDENA_API_KEY", "test-key")
	fixture := newMirrorRPCFixture(t, false)
	server := httptest.NewServer(fixture)
	defer server.Close()
	radHome := filepath.Join(t.TempDir(), "no-radicle-profile-needed")
	receiptPath := filepath.Join(t.TempDir(), "mirror-receipt.json")

	if err := runMirror(context.Background(), []string{
		"--rpc", server.URL,
		"--action-cid", fixture.actionCID,
		"--tx-hash", mirrorTestTxHash,
		"--tx-height", mirrorTestHeightText,
		"--block-hash", mirrorTestBlockHash,
		"--rad-home", radHome,
		"--out", receiptPath,
	}); err != nil {
		t.Fatal(err)
	}
	if fixture.addCount() != 0 {
		t.Fatalf("verify-only mirror made %d permanent IPFS mutation(s)", fixture.addCount())
	}
	var receipt mirrorReceipt
	if err := readJSON(receiptPath, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Schema != mirrorReceiptSchema || receipt.Pinned || receipt.Action.CID != fixture.actionCID || len(receipt.Content) != 1 {
		t.Fatalf("unexpected verify-only receipt: %+v", receipt)
	}
	if receipt.Action.Pinned || receipt.Content[0].Pinned {
		t.Fatalf("verify-only receipt claimed pinned objects: %+v", receipt)
	}
}

func TestMirrorPinsOnlyFullyVerifiedPublication(t *testing.T) {
	t.Setenv("IDENA_API_KEY", "test-key")
	fixture := newMirrorRPCFixture(t, false)
	server := httptest.NewServer(fixture)
	defer server.Close()
	radHome := mirrorRadHome(t)
	contentDirectory := filepath.Join(t.TempDir(), "content")
	receiptPath := filepath.Join(t.TempDir(), "mirror-receipt.json")

	if err := runMirror(context.Background(), []string{
		"--rpc", server.URL,
		"--action-cid", fixture.actionCID,
		"--tx-hash", mirrorTestTxHash,
		"--tx-height", mirrorTestHeightText,
		"--block-hash", mirrorTestBlockHash,
		"--rad-home", radHome,
		"--content", contentDirectory,
		"--out", receiptPath,
		"--pin",
	}); err != nil {
		t.Fatal(err)
	}
	if fixture.addCount() != 2 {
		t.Fatalf("pinned %d objects, want action plus bundle", fixture.addCount())
	}
	var receipt mirrorReceipt
	if err := readJSON(receiptPath, &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.Pinned || !receipt.Action.Pinned || len(receipt.Content) != 1 || !receipt.Content[0].Pinned {
		t.Fatalf("unexpected pinned receipt: %+v", receipt)
	}
	store, err := content.Open(contentDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Has(fixture.actionCID) || !store.Has(fixture.bundleCID) {
		t.Fatal("verified mirror objects were not retained in the local content store")
	}
}

func TestMirrorRepositoryVerificationDoesNotRequireRadicleActorProfile(t *testing.T) {
	t.Setenv("IDENA_API_KEY", "test-key")
	fixture := newMirrorRPCFixture(t, false)
	server := httptest.NewServer(fixture)
	defer server.Close()
	missingHome := filepath.Join(t.TempDir(), "missing-radicle-home")

	if err := runMirror(context.Background(), []string{
		"--rpc", server.URL,
		"--action-cid", fixture.actionCID,
		"--tx-hash", mirrorTestTxHash,
		"--tx-height", mirrorTestHeightText,
		"--block-hash", mirrorTestBlockHash,
		"--rad-home", missingHome,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(missingHome); !os.IsNotExist(err) {
		t.Fatalf("repository verification created or required a Radicle actor profile: %v", err)
	}
}

func TestMirrorRejectsTamperedContentBeforePin(t *testing.T) {
	t.Setenv("IDENA_API_KEY", "test-key")
	fixture := newMirrorRPCFixture(t, true)
	server := httptest.NewServer(fixture)
	defer server.Close()

	err := runMirror(context.Background(), []string{
		"--rpc", server.URL,
		"--action-cid", fixture.actionCID,
		"--tx-hash", mirrorTestTxHash,
		"--tx-height", mirrorTestHeightText,
		"--block-hash", mirrorTestBlockHash,
		"--rad-home", mirrorRadHome(t),
		"--content", filepath.Join(t.TempDir(), "content"),
		"--pin",
	})
	if err == nil || !strings.Contains(err.Error(), "calculated CID") {
		t.Fatalf("tampered content was not rejected: %v", err)
	}
	if fixture.addCount() != 0 {
		t.Fatalf("tampered publication caused %d IPFS mutation(s)", fixture.addCount())
	}
}

func TestMirrorAttestationBindsCompletedPinReceiptToIdenaIdentity(t *testing.T) {
	t.Setenv("IDENA_API_KEY", "test-key")
	fixture := newMirrorRPCFixture(t, false)
	server := httptest.NewServer(fixture)
	defer server.Close()
	receiptPath := filepath.Join(t.TempDir(), "signed-mirror-receipt.json")

	if err := runMirror(context.Background(), []string{
		"--rpc", server.URL,
		"--action-cid", fixture.actionCID,
		"--tx-hash", mirrorTestTxHash,
		"--tx-height", mirrorTestHeightText,
		"--block-hash", mirrorTestBlockHash,
		"--rad-home", filepath.Join(t.TempDir(), "no-profile-needed"),
		"--content", filepath.Join(t.TempDir(), "content"),
		"--out", receiptPath,
		"--pin",
		"--attest",
	}); err != nil {
		t.Fatal(err)
	}
	if fixture.addCount() != 2 || fixture.signatureCount() != 1 {
		t.Fatalf("mirror adds=%d signatures=%d, want 2 and 1", fixture.addCount(), fixture.signatureCount())
	}
	receipt, err := readMirrorReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	address, err := verifyMirrorAttestation(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if address != fixture.mirrorAddress || receipt.Attestation == nil || !receipt.Pinned {
		t.Fatalf("unexpected signed mirror receipt: %+v", receipt)
	}
	if err := runVerifyMirror([]string{"--receipt", receiptPath, "--expected-address", fixture.mirrorAddress}); err != nil {
		t.Fatalf("offline receipt command rejected valid attestation: %v", err)
	}
	if err := runVerifyMirror([]string{"--receipt", receiptPath, "--expected-address", receipt.Author}); err == nil || !strings.Contains(err.Error(), "differs from expected identity") {
		t.Fatalf("offline receipt command accepted wrong expected identity: %v", err)
	}

	tampered := receipt
	tampered.Content = append([]mirrorObjectReceipt(nil), receipt.Content...)
	tampered.Content[0].Bytes++
	if _, err := verifyMirrorAttestation(tampered); err == nil || !strings.Contains(err.Error(), "message hash") {
		t.Fatalf("tampered signed receipt was accepted: %v", err)
	}

	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var withUnknown map[string]any
	if err := json.Unmarshal(encoded, &withUnknown); err != nil {
		t.Fatal(err)
	}
	withUnknown["unverifiedClaim"] = true
	unknownBytes, err := json.Marshal(withUnknown)
	if err != nil {
		t.Fatal(err)
	}
	unknownPath := filepath.Join(t.TempDir(), "unknown-field.json")
	if err := os.WriteFile(unknownPath, unknownBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readMirrorReceipt(unknownPath); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("receipt with unknown claim was accepted: %v", err)
	}
}

func TestMirrorAttestationRequiresExplicitPin(t *testing.T) {
	actionCID, err := content.CIDForBytes([]byte("synthetic mirror action"))
	if err != nil {
		t.Fatal(err)
	}
	err = runMirror(context.Background(), []string{
		"--action-cid", actionCID,
		"--tx-hash", mirrorTestTxHash,
		"--tx-height", mirrorTestHeightText,
		"--block-hash", mirrorTestBlockHash,
		"--attest",
	})
	if err == nil || !strings.Contains(err.Error(), "--attest requires --pin") {
		t.Fatalf("attestation without pin was accepted: %v", err)
	}
}

type mirrorRPCFixture struct {
	t                 *testing.T
	action            []byte
	bundle            []byte
	actionCID         string
	bundleCID         string
	author            string
	epoch             uint16
	tamperBundle      bool
	signingKey        *ecdsa.PrivateKey
	mirrorAddress     string
	mu                sync.Mutex
	permanentAddCount int
	signCount         int
}

func newMirrorRPCFixture(t *testing.T, tamperBundle bool) *mirrorRPCFixture {
	t.Helper()
	action, bundle, envelope := syntheticMirrorPublication(t)
	actionCID, err := content.CIDForBytes(action)
	if err != nil {
		t.Fatal(err)
	}
	bundleCID, err := content.CIDForBytes(bundle)
	if err != nil {
		t.Fatal(err)
	}
	signingKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &mirrorRPCFixture{
		t:             t,
		action:        action,
		bundle:        bundle,
		actionCID:     actionCID,
		bundleCID:     bundleCID,
		author:        envelope.Author,
		epoch:         envelope.Epoch,
		tamperBundle:  tamperBundle,
		signingKey:    signingKey,
		mirrorAddress: identity.Address(identity.PublicKeyFromPrivate(signingKey)),
	}
}

func syntheticMirrorPublication(t *testing.T) ([]byte, []byte, *protocol.Envelope) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	root := t.TempDir()
	keyPath := filepath.Join(root, "radicle")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyText := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublicKey)))
	privateKeyBlock, err := ssh.MarshalPrivateKey(privateKey, "synthetic mirror fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(privateKeyBlock), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+".pub", []byte(publicKeyText+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	did, canonicalKey, err := radicleforge.DIDForKey(publicKeyText)
	if err != nil {
		t.Fatal(err)
	}

	repository := filepath.Join(root, "repository")
	if err := os.MkdirAll(filepath.Join(repository, "embeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	identityDocument, err := json.Marshal(map[string]any{
		"version":     3,
		"initializer": did,
		"payload": map[string]any{
			"xyz.radicle.project": map[string]any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "embeds", "radicle.json"), identityDocument, 0o644); err != nil {
		t.Fatal(err)
	}
	mirrorGit(t, "init", "-b", "main", repository)
	mirrorGit(t, "-C", repository, "config", "user.name", "Synthetic Mirror Fixture")
	mirrorGit(t, "-C", repository, "config", "user.email", "mirror@example.invalid")
	mirrorGit(t, "-C", repository, "add", "embeds/radicle.json")
	mirrorGit(t, "-C", repository, "commit", "-m", "synthetic identity")
	identityCommit := mirrorGit(t, "-C", repository, "rev-parse", "HEAD")
	identityOID := mirrorGit(t, "-C", repository, "rev-parse", "HEAD:embeds/radicle.json")
	identityBytes, err := hex.DecodeString(identityOID)
	if err != nil {
		t.Fatal(err)
	}
	encodedRID, err := multibase.Encode(multibase.Base58BTC, identityBytes)
	if err != nil {
		t.Fatal(err)
	}
	rid := "rad:" + encodedRID
	mirrorGit(t, "-C", repository, "update-ref", "refs/rad/id", identityCommit)

	manifest := []byte(
		identityCommit + " refs/heads/main\n" +
			identityCommit + " refs/rad/id\n" +
			identityCommit + " refs/rad/root\n",
	)
	if err := os.WriteFile(filepath.Join(repository, "refs"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "signature"), ed25519.Sign(privateKey, manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	mirrorGit(t, "-C", repository, "add", "refs", "signature")
	mirrorGit(t, "-C", repository, "commit", "-m", "synthetic signed refs")
	signedRefsCommit := mirrorGit(t, "-C", repository, "rev-parse", "HEAD")
	actor := strings.TrimPrefix(did, "did:key:")
	namespace := "refs/namespaces/" + actor + "/"
	for refname, oid := range map[string]string{
		namespace + "refs/heads/main":  identityCommit,
		namespace + "refs/rad/id":      identityCommit,
		namespace + "refs/rad/root":    identityCommit,
		namespace + "refs/rad/sigrefs": signedRefsCommit,
	} {
		mirrorGit(t, "-C", repository, "update-ref", refname, oid)
	}
	bundlePath := filepath.Join(root, "repository.bundle")
	mirrorGit(t, "-C", repository, "bundle", "create", bundlePath, "--all")
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	bundleCID, err := content.CIDForBytes(bundle)
	if err != nil {
		t.Fatal(err)
	}

	publisherKey, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.NewEnvelope(
		protocol.KindRepository,
		rid,
		42,
		protocol.AddressFromPrivateKey(publisherKey),
		did,
		canonicalKey,
		"00000000000000000000000000000001",
		protocol.RepositoryPayload{Head: identityCommit, Bundle: bundleCID, ActorDID: did},
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := radicleforge.SignBinding(context.Background(), keyPath, envelope.RadicleBindingMessage())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = binding
	if err := envelope.Sign(publisherKey); err != nil {
		t.Fatal(err)
	}
	action, err := envelope.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return action, bundle, envelope
}

func mirrorGit(t *testing.T, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}

func (fixture *mirrorRPCFixture) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	fixture.t.Helper()
	defer request.Body.Close()
	var rpc struct {
		JSONRPC string            `json:"jsonrpc"`
		ID      uint64            `json:"id"`
		Method  string            `json:"method"`
		Params  []json.RawMessage `json:"params"`
		Key     string            `json:"key"`
	}
	if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
		fixture.t.Errorf("decode RPC request: %v", err)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	if rpc.Key != "test-key" {
		fixture.t.Errorf("unexpected API key")
	}
	var result any
	switch rpc.Method {
	case "bcn_blockAt":
		result = map[string]any{
			"height":       mirrorTestHeight,
			"hash":         mirrorTestBlockHash,
			"transactions": []string{mirrorTestTxHash},
		}
	case "bcn_transaction":
		payload, err := idena.EncodeForgeActionPayload(fixture.action)
		if err != nil {
			fixture.t.Fatal(err)
		}
		result = map[string]any{
			"hash":      mirrorTestTxHash,
			"type":      idena.ForgeActionTxType,
			"from":      fixture.author,
			"to":        fixture.author,
			"epoch":     fixture.epoch,
			"payload":   "0x" + hex.EncodeToString(payload),
			"blockHash": mirrorTestBlockHash,
		}
	case "ipfs_get":
		cid := rawStringParam(fixture.t, rpc.Params, 0)
		var data []byte
		switch cid {
		case fixture.actionCID:
			data = fixture.action
		case fixture.bundleCID:
			data = fixture.bundle
			if fixture.tamperBundle {
				data = append(append([]byte(nil), data...), 'x')
			}
		default:
			fixture.t.Errorf("unexpected ipfs_get CID %s", cid)
		}
		result = "0x" + hex.EncodeToString(data)
	case "ipfs_cid":
		data := rawHexParam(fixture.t, rpc.Params, 0)
		cid, err := content.CIDForBytes(data)
		if err != nil {
			fixture.t.Fatal(err)
		}
		result = cid
	case "ipfs_add":
		data := rawHexParam(fixture.t, rpc.Params, 0)
		cid, err := content.CIDForBytes(data)
		if err != nil {
			fixture.t.Fatal(err)
		}
		fixture.mu.Lock()
		fixture.permanentAddCount++
		fixture.mu.Unlock()
		result = cid
	case "dna_getCoinbaseAddr":
		result = fixture.mirrorAddress
	case "dna_sign":
		message := rawStringParam(fixture.t, rpc.Params, 0)
		if mode := rawStringParam(fixture.t, rpc.Params, 1); mode != "prefix" {
			fixture.t.Errorf("unexpected dna_sign mode %s", mode)
		}
		signature, err := identity.Sign(message, fixture.signingKey)
		if err != nil {
			fixture.t.Fatal(err)
		}
		fixture.mu.Lock()
		if fixture.permanentAddCount != 2 {
			fixture.t.Errorf("receipt signed before both verified objects were pinned: %d", fixture.permanentAddCount)
		}
		fixture.signCount++
		fixture.mu.Unlock()
		result = "0x" + hex.EncodeToString(signature)
	default:
		fixture.t.Errorf("unexpected RPC method %s", rpc.Method)
		result = nil
	}
	writer.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(writer).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      rpc.ID,
		"result":  result,
	}); err != nil {
		fixture.t.Errorf("encode RPC response: %v", err)
	}
}

func (fixture *mirrorRPCFixture) addCount() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.permanentAddCount
}

func (fixture *mirrorRPCFixture) signatureCount() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.signCount
}

func mirrorRadHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "config.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "keys", "radicle.pub"), []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6Ul/D+P0I/Hl1JVOWGS8Z589us9FqKQXWv8OMOpKCh verifier\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func rawStringParam(t *testing.T, params []json.RawMessage, index int) string {
	t.Helper()
	if len(params) <= index {
		t.Fatalf("missing RPC parameter %d", index)
	}
	var value string
	if err := json.Unmarshal(params[index], &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func rawHexParam(t *testing.T, params []json.RawMessage, index int) []byte {
	t.Helper()
	value := strings.TrimPrefix(rawStringParam(t, params, index), "0x")
	data, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
