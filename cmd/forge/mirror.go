package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"idena-git-forge/internal/canonicaljson"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/idena"
	"idena-git-forge/internal/identity"
	"idena-git-forge/internal/protocol"
	radicleforge "idena-git-forge/internal/radicle"
)

const (
	mirrorReceiptSchema     = "idena-radicle/mirror-receipt/v2"
	mirrorAttestationDomain = "idena-radicle-mirror-attestation/v1"
)

type mirrorReceipt struct {
	Schema           string                 `json:"schema"`
	VerifiedAtUTC    string                 `json:"verifiedAtUtc"`
	Pinned           bool                   `json:"pinned"`
	Repository       string                 `json:"repository"`
	Author           string                 `json:"author"`
	PublicationEpoch uint16                 `json:"publicationEpoch"`
	Transaction      mirrorTransaction      `json:"transaction"`
	Action           mirrorObjectReceipt    `json:"action"`
	Content          []mirrorObjectReceipt  `json:"content"`
	Settlement       string                 `json:"settlement"`
	EvidenceBoundary mirrorEvidenceBoundary `json:"evidenceBoundary"`
	Attestation      *mirrorAttestation     `json:"attestation,omitempty"`
}

type mirrorEvidenceBoundary struct {
	OperatorIndependence   string `json:"operatorIndependence"`
	ContinuousAvailability string `json:"continuousAvailability"`
	IdentityBinding        string `json:"identityBinding"`
}

type mirrorAttestation struct {
	Domain        string `json:"domain"`
	Address       string `json:"address"`
	MessageSHA256 string `json:"messageSha256"`
	Signature     string `json:"signature"`
}

type mirrorTransaction struct {
	Hash      string `json:"hash"`
	Height    uint64 `json:"height"`
	BlockHash string `json:"blockHash"`
	Index     uint32 `json:"index"`
}

type mirrorObjectReceipt struct {
	CID    string `json:"cid"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
	Pinned bool   `json:"pinned"`
}

type mirrorObject struct {
	receipt mirrorObjectReceipt
	data    []byte
}

// runMirror reproduces one already-published action through the operator's own
// Idena node. It performs every chain, signature, CID, binding and quarantined
// Radicle check before --pin is allowed to mutate the node's IPFS pin set.
func runMirror(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("mirror", flag.ContinueOnError)
	rpcEndpoint := flags.String("rpc", "http://127.0.0.1:9009", "Idena node JSON-RPC endpoint")
	apiKeyEnvironment := flags.String("api-key-env", "IDENA_API_KEY", "environment variable containing the Idena RPC API key")
	actionCID := flags.String("action-cid", "", "published signed-action CID")
	txHash := flags.String("tx-hash", "", "canonical publication transaction hash")
	txHeight := flags.Uint64("tx-height", 0, "canonical publication block height")
	blockHash := flags.String("block-hash", "", "canonical publication block hash")
	contentDir := flags.String("content", "", "local forge content store; required with --pin")
	outputPath := flags.String("out", "", "optional atomic mirror receipt output")
	pin := flags.Bool("pin", false, "permanently pin the independently verified objects in this Idena node")
	attest := flags.Bool("attest", false, "after --pin, sign the receipt with this node's Idena coinbase without broadcasting")
	radBin := flags.String("rad-bin", envOr("RAD_BIN", "rad"), "reviewed Radicle CLI binary")
	radHome := flags.String("rad-home", defaultRadHome(), "isolated Radicle home")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	apiKey, err := resolveSecretEnvironment(*apiKeyEnvironment)
	if err != nil {
		return err
	}
	if *actionCID == "" || *txHash == "" || *txHeight == 0 || *blockHash == "" {
		return errors.New("--action-cid, --tx-hash, --tx-height and --block-hash are required")
	}
	if err := content.ValidateCID(*actionCID); err != nil {
		return fmt.Errorf("--action-cid: %w", err)
	}
	if err := validateTransactionHash(*txHash); err != nil {
		return fmt.Errorf("--tx-hash: %w", err)
	}
	if err := validateTransactionHash(*blockHash); err != nil {
		return fmt.Errorf("--block-hash: %w", err)
	}
	if *pin && *contentDir == "" {
		return errors.New("--content is required with --pin")
	}
	if *attest && !*pin {
		return errors.New("--attest requires --pin so the identity signs a completed mirror claim")
	}

	client := idena.NewClient(*rpcEndpoint, apiKey)
	block, err := client.BlockAt(ctx, *txHeight)
	if err != nil {
		return fmt.Errorf("retrieve publication block: %w", err)
	}
	if block.Height != *txHeight || !strings.EqualFold(block.Hash, *blockHash) {
		return errors.New("publication block differs from the expected canonical block")
	}
	txIndex, err := uniqueTransactionIndex(block.Transactions, *txHash)
	if err != nil {
		return err
	}
	transaction, err := client.Transaction(ctx, *txHash)
	if err != nil {
		return fmt.Errorf("retrieve publication transaction: %w", err)
	}
	if !strings.EqualFold(transaction.Hash, *txHash) || !strings.EqualFold(transaction.BlockHash, block.Hash) {
		return errors.New("publication transaction is not bound to the expected canonical block")
	}
	if transaction.Type != idena.ForgeActionTxType {
		return errors.New("publication transaction is not an Idena send")
	}

	chainPayload, err := decodeRPCPayload(transaction.Payload)
	if err != nil {
		return fmt.Errorf("decode publication transaction payload: %w", err)
	}
	chainAction, recognized, err := idena.DecodeForgeActionPayload(chainPayload)
	if err != nil {
		return fmt.Errorf("decode publication forge action: %w", err)
	}
	if !recognized {
		return errors.New("publication transaction does not contain an IDENA_GIT_ACTION_V1 action")
	}

	actionBytes, err := client.IPFSGet(ctx, *actionCID)
	if err != nil {
		return fmt.Errorf("retrieve signed action through this Idena node: %w", err)
	}
	if !bytes.Equal(actionBytes, chainAction) {
		return errors.New("Idena IPFS action bytes differ from the canonical transaction payload")
	}
	actionObject, err := verifyMirrorObject(ctx, client, *actionCID, actionBytes)
	if err != nil {
		return fmt.Errorf("verify signed action object: %w", err)
	}
	envelope, err := protocol.ParseEnvelope(actionBytes)
	if err != nil {
		return fmt.Errorf("verify signed action envelope: %w", err)
	}
	if err := radicleforge.VerifyBinding(ctx, *envelope); err != nil {
		return fmt.Errorf("verify Radicle/Idena binding: %w", err)
	}
	if !strings.EqualFold(transaction.From, envelope.Author) ||
		!strings.EqualFold(transaction.To, transaction.From) ||
		transaction.Epoch != envelope.Epoch {
		return errors.New("publication transaction sender, self-recipient or epoch differs from the signed action")
	}
	if envelope.Epoch > ^uint16(0)-2 {
		return errors.New("publication epoch cannot be extended by the content lease")
	}
	payload, err := envelope.DecodePayload()
	if err != nil {
		return err
	}
	subject, err := protocol.RadicleSubjectFor(*envelope, payload)
	if err != nil {
		return err
	}

	contentCIDs := deduplicateStrings(idena.ContentCIDs(payload))
	objects := make([]mirrorObject, 0, len(contentCIDs))
	verificationDirectory, err := os.MkdirTemp("", "idena-forge-mirror-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(verificationDirectory)
	verificationStore, err := content.Open(verificationDirectory)
	if err != nil {
		return err
	}
	for _, cid := range contentCIDs {
		data, err := client.IPFSGet(ctx, cid)
		if err != nil {
			return fmt.Errorf("retrieve referenced content %s through this Idena node: %w", cid, err)
		}
		object, err := verifyMirrorObject(ctx, client, cid, data)
		if err != nil {
			return fmt.Errorf("verify referenced content %s: %w", cid, err)
		}
		stored, err := verificationStore.Put(data, envelope.Epoch+2)
		if err != nil {
			return err
		}
		if stored != cid {
			return fmt.Errorf("verification store CID %s differs from referenced CID %s", stored, cid)
		}
		objects = append(objects, object)
	}
	verifier := radicleforge.ContentVerifier{
		Client: radicleforge.VerificationClient{
			Binary: *radBin,
			Home:   *radHome,
		},
		Store: verificationStore,
	}
	if err := verifier.Verify(ctx, subject); err != nil {
		return fmt.Errorf("verify quarantined Radicle content: %w", err)
	}

	allObjects := append([]mirrorObject{actionObject}, objects...)
	if *pin {
		persistentStore, err := content.Open(*contentDir)
		if err != nil {
			return err
		}
		for index := range allObjects {
			stored, err := persistentStore.Put(allObjects[index].data, envelope.Epoch+2)
			if err != nil {
				return err
			}
			if stored != allObjects[index].receipt.CID {
				return fmt.Errorf("local content store CID %s differs from verified CID %s", stored, allObjects[index].receipt.CID)
			}
		}
		for index := range allObjects {
			added, err := client.IPFSAdd(ctx, allObjects[index].data, true)
			if err != nil {
				return fmt.Errorf("pin verified content %s: %w", allObjects[index].receipt.CID, err)
			}
			if added != allObjects[index].receipt.CID {
				return fmt.Errorf("Idena node pinned %s for verified content %s", added, allObjects[index].receipt.CID)
			}
			if err := persistentStore.PinRepository(allObjects[index].receipt.CID, envelope.Repository); err != nil {
				return err
			}
			allObjects[index].receipt.Pinned = true
		}
	}

	receipt := mirrorReceipt{
		Schema:           mirrorReceiptSchema,
		VerifiedAtUTC:    time.Now().UTC().Format(time.RFC3339),
		Pinned:           *pin,
		Repository:       envelope.Repository,
		Author:           strings.ToLower(envelope.Author),
		PublicationEpoch: envelope.Epoch,
		Transaction: mirrorTransaction{
			Hash:      strings.ToLower(transaction.Hash),
			Height:    block.Height,
			BlockHash: strings.ToLower(block.Hash),
			Index:     txIndex,
		},
		Action:     allObjects[0].receipt,
		Content:    make([]mirrorObjectReceipt, 0, len(objects)),
		Settlement: "pending-validation-finished-checkpoint",
		EvidenceBoundary: mirrorEvidenceBoundary{
			OperatorIndependence:   "external-attestation-required",
			ContinuousAvailability: "not-provable-on-chain; repeat retrieval from another node",
			IdentityBinding:        "none; checkpoint eligibility pending",
		},
	}
	for _, object := range allObjects[1:] {
		receipt.Content = append(receipt.Content, object.receipt)
	}
	if *attest {
		receipt.EvidenceBoundary.IdentityBinding = "Idena signature present; checkpoint eligibility pending"
		address, err := client.CoinbaseAddress(ctx)
		if err != nil {
			return fmt.Errorf("read mirror attestation identity: %w", err)
		}
		address, err = identity.NormalizeAddress(address)
		if err != nil {
			return fmt.Errorf("mirror attestation identity: %w", err)
		}
		message, err := mirrorAttestationMessage(receipt)
		if err != nil {
			return err
		}
		signature, err := client.Sign(ctx, string(message))
		if err != nil {
			return fmt.Errorf("sign mirror receipt through Idena: %w", err)
		}
		digest := sha256.Sum256(message)
		receipt.Attestation = &mirrorAttestation{
			Domain:        mirrorAttestationDomain,
			Address:       address,
			MessageSHA256: hex.EncodeToString(digest[:]),
			Signature:     "0x" + hex.EncodeToString(signature),
		}
		if _, err := verifyMirrorAttestation(receipt); err != nil {
			return fmt.Errorf("self-verify mirror attestation: %w", err)
		}
	}
	if *outputPath != "" {
		if err := writeJSONAtomic(*outputPath, receipt); err != nil {
			return err
		}
	} else {
		printJSON(receipt)
	}
	return nil
}

func runVerifyMirror(arguments []string) error {
	flags := flag.NewFlagSet("verify-mirror", flag.ContinueOnError)
	receiptPath := flags.String("receipt", "", "signed mirror receipt JSON")
	expectedAddress := flags.String("expected-address", "", "optional expected Idena attestation address")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *receiptPath == "" {
		return errors.New("--receipt is required")
	}
	receipt, err := readMirrorReceipt(*receiptPath)
	if err != nil {
		return err
	}
	address, err := verifyMirrorAttestation(receipt)
	if err != nil {
		return err
	}
	if *expectedAddress != "" {
		expected, err := identity.NormalizeAddress(*expectedAddress)
		if err != nil {
			return fmt.Errorf("--expected-address: %w", err)
		}
		if address != expected {
			return fmt.Errorf("mirror receipt signer %s differs from expected identity %s", address, expected)
		}
	}
	printJSON(map[string]any{
		"verified":                 true,
		"address":                  address,
		"receiptIdentityBound":     true,
		"operatorIndependence":     "not established by the signature",
		"continuousAvailability":   "requires repeat retrieval from another node",
		"checkpointEligibility":    "requires a checkpoint identity proof",
		"chainAndContentReproduce": "required independently from the signed claim",
	})
	return nil
}

func readMirrorReceipt(path string) (mirrorReceipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return mirrorReceipt{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var receipt mirrorReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return mirrorReceipt{}, fmt.Errorf("decode mirror receipt: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return mirrorReceipt{}, errors.New("mirror receipt contains multiple JSON values")
		}
		return mirrorReceipt{}, fmt.Errorf("decode trailing mirror receipt data: %w", err)
	}
	return receipt, nil
}

func mirrorAttestationMessage(receipt mirrorReceipt) ([]byte, error) {
	receipt.Attestation = nil
	encoded, err := json.Marshal(struct {
		Domain  string        `json:"domain"`
		Receipt mirrorReceipt `json:"receipt"`
	}{
		Domain:  mirrorAttestationDomain,
		Receipt: receipt,
	})
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func verifyMirrorAttestation(receipt mirrorReceipt) (string, error) {
	if err := validateMirrorReceipt(receipt); err != nil {
		return "", err
	}
	if receipt.Attestation == nil {
		return "", errors.New("mirror receipt has no Idena attestation")
	}
	if receipt.Attestation.Domain != mirrorAttestationDomain {
		return "", errors.New("mirror receipt uses an unsupported attestation domain")
	}
	address, err := identity.NormalizeAddress(receipt.Attestation.Address)
	if err != nil {
		return "", fmt.Errorf("mirror attestation address: %w", err)
	}
	message, err := mirrorAttestationMessage(receipt)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(message)
	if receipt.Attestation.MessageSHA256 != hex.EncodeToString(digest[:]) {
		return "", errors.New("mirror attestation message hash differs from the receipt")
	}
	signatureText := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(receipt.Attestation.Signature)), "0x")
	signature, err := hex.DecodeString(signatureText)
	if err != nil {
		return "", errors.New("mirror attestation signature is not hexadecimal")
	}
	recovered, err := identity.RecoverAddress(identity.SignedMessageHash(string(message)), signature)
	if err != nil {
		return "", fmt.Errorf("recover mirror attestation identity: %w", err)
	}
	if recovered != address {
		return "", errors.New("mirror attestation signature does not recover to the declared identity")
	}
	return address, nil
}

func validateMirrorReceipt(receipt mirrorReceipt) error {
	if receipt.Schema != mirrorReceiptSchema {
		return fmt.Errorf("unsupported mirror receipt schema %q", receipt.Schema)
	}
	if _, err := time.Parse(time.RFC3339, receipt.VerifiedAtUTC); err != nil {
		return errors.New("mirror receipt has an invalid verification timestamp")
	}
	if !strings.HasPrefix(receipt.Repository, "rad:z") || len(receipt.Repository) <= len("rad:z") {
		return errors.New("mirror receipt has an invalid repository ID")
	}
	if _, err := identity.NormalizeAddress(receipt.Author); err != nil {
		return fmt.Errorf("mirror receipt author: %w", err)
	}
	if receipt.PublicationEpoch == 0 || receipt.Transaction.Height == 0 {
		return errors.New("mirror receipt has an invalid publication epoch or height")
	}
	if err := validateTransactionHash(receipt.Transaction.Hash); err != nil {
		return fmt.Errorf("mirror receipt transaction hash: %w", err)
	}
	if err := validateTransactionHash(receipt.Transaction.BlockHash); err != nil {
		return fmt.Errorf("mirror receipt block hash: %w", err)
	}
	if receipt.Settlement != "pending-validation-finished-checkpoint" {
		return errors.New("mirror receipt makes an unsupported settlement claim")
	}
	if receipt.EvidenceBoundary.OperatorIndependence != "external-attestation-required" ||
		receipt.EvidenceBoundary.ContinuousAvailability != "not-provable-on-chain; repeat retrieval from another node" {
		return errors.New("mirror receipt weakens its evidence boundary")
	}
	wantIdentityBoundary := "none; checkpoint eligibility pending"
	if receipt.Attestation != nil {
		wantIdentityBoundary = "Idena signature present; checkpoint eligibility pending"
	}
	if receipt.EvidenceBoundary.IdentityBinding != wantIdentityBoundary {
		return errors.New("mirror receipt identity boundary differs from its attestation state")
	}
	if err := validateMirrorReceiptObject(receipt.Action, receipt.Pinned); err != nil {
		return fmt.Errorf("mirror receipt action: %w", err)
	}
	if len(receipt.Content) == 0 {
		return errors.New("mirror receipt has no referenced content")
	}
	seen := map[string]struct{}{receipt.Action.CID: {}}
	for index, object := range receipt.Content {
		if err := validateMirrorReceiptObject(object, receipt.Pinned); err != nil {
			return fmt.Errorf("mirror receipt content %d: %w", index, err)
		}
		if _, exists := seen[object.CID]; exists {
			return fmt.Errorf("mirror receipt repeats content CID %s", object.CID)
		}
		seen[object.CID] = struct{}{}
	}
	return nil
}

func validateMirrorReceiptObject(object mirrorObjectReceipt, pinned bool) error {
	if err := content.ValidateCID(object.CID); err != nil {
		return err
	}
	if object.Bytes <= 0 {
		return errors.New("object byte length must be positive")
	}
	digest, err := hex.DecodeString(object.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("object SHA-256 must be 32-byte lowercase hex")
	}
	if object.SHA256 != strings.ToLower(object.SHA256) {
		return errors.New("object SHA-256 must be lowercase")
	}
	if object.Pinned != pinned {
		return errors.New("object pin state differs from the receipt")
	}
	return nil
}

func uniqueTransactionIndex(transactions []string, expected string) (uint32, error) {
	index := -1
	for candidate, hash := range transactions {
		if strings.EqualFold(hash, expected) {
			if index >= 0 {
				return 0, errors.New("publication block lists the transaction more than once")
			}
			index = candidate
		}
	}
	if index < 0 {
		return 0, errors.New("publication block does not list the expected transaction")
	}
	return uint32(index), nil
}

func decodeRPCPayload(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if value == "" || len(value)%2 != 0 {
		return nil, errors.New("payload is empty or has an odd hex length")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, errors.New("payload is not hexadecimal")
	}
	return decoded, nil
}

func verifyMirrorObject(ctx context.Context, client *idena.Client, expectedCID string, data []byte) (mirrorObject, error) {
	if len(data) == 0 {
		return mirrorObject{}, errors.New("content is empty")
	}
	calculated, err := content.CIDForBytes(data)
	if err != nil {
		return mirrorObject{}, err
	}
	if calculated != expectedCID {
		return mirrorObject{}, fmt.Errorf("calculated CID %s differs from expected CID %s", calculated, expectedCID)
	}
	nodeCID, err := client.IPFSCID(ctx, data)
	if err != nil {
		return mirrorObject{}, fmt.Errorf("ask Idena node to calculate CID: %w", err)
	}
	if nodeCID != expectedCID {
		return mirrorObject{}, fmt.Errorf("Idena node calculated CID %s instead of %s", nodeCID, expectedCID)
	}
	digest := sha256.Sum256(data)
	return mirrorObject{
		receipt: mirrorObjectReceipt{
			CID:    expectedCID,
			Bytes:  len(data),
			SHA256: hex.EncodeToString(digest[:]),
		},
		data: append([]byte(nil), data...),
	}, nil
}

func deduplicateStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
