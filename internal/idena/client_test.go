package idena

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ipfs/go-cid"
	"google.golang.org/protobuf/encoding/protowire"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

func TestStoreToIPFSCID(t *testing.T) {
	actionCID, _ := content.CIDForBytes([]byte("action"))
	parsed, _ := cidCast(actionCID)
	payload := protowire.AppendTag(nil, 1, protowire.BytesType)
	payload = protowire.AppendBytes(payload, parsed)
	payload = protowire.AppendTag(payload, 2, protowire.VarintType)
	payload = protowire.AppendVarint(payload, 6)
	got, err := StoreToIPFSCID(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got != actionCID {
		t.Fatalf("CID mismatch: want %s, got %s", actionCID, got)
	}
}

func TestIdenaSocialContractCalls(t *testing.T) {
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
		case "contract_estimateCall":
			var args ContractCallArgs
			if err := json.Unmarshal(rpc.Params[0], &args); err != nil {
				t.Error(err)
				return
			}
			if args.Method != "makePost" || args.Amount != "0.00001" ||
				len(args.Args) != 1 || args.Args[0].Format != "string" {
				t.Errorf("unexpected estimate args: %+v", args)
			}
			result = ContractEstimate{Success: true, TxFee: "0.001", GasCost: "0.0001"}
		case "contract_call":
			var args ContractCallArgs
			if err := json.Unmarshal(rpc.Params[0], &args); err != nil {
				t.Error(err)
				return
			}
			if args.MaxFee != "0.0022" {
				t.Errorf("max fee = %q", args.MaxFee)
			}
			result = "0xtx"
		default:
			t.Errorf("unexpected method %s", rpc.Method)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result":  result,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	args := ContractCallArgs{
		From: "0x1", Contract: "0x2", Method: "makePost", Amount: "0.00001",
		Args: []ContractArg{{Index: 0, Format: "string", Value: `{"message":"hello"}`}},
	}
	estimate, err := client.EstimateContractCall(context.Background(), args)
	if err != nil || !estimate.Success {
		t.Fatalf("estimate: %+v, %v", estimate, err)
	}
	args.MaxFee = "0.0022"
	hash, err := client.ContractCall(context.Background(), args)
	if err != nil || hash != "0xtx" {
		t.Fatalf("call: %q, %v", hash, err)
	}
}

func TestForgeActionEstimateAndSendUseReviewedMaxFee(t *testing.T) {
	methods := make([]string, 0, 2)
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
		methods = append(methods, rpc.Method)
		var args map[string]any
		if len(rpc.Params) != 1 {
			t.Errorf("%s params = %d", rpc.Method, len(rpc.Params))
		} else if err := json.Unmarshal(rpc.Params[0], &args); err != nil {
			t.Error(err)
		}
		if args["maxFee"] != "5" || args["amount"] != "0" || args["tips"] != "0" {
			t.Errorf("%s transaction args = %+v", rpc.Method, args)
		}
		var result any
		switch rpc.Method {
		case "bcn_estimateTx":
			result = ForgeActionEstimate{TxHash: "0xestimated", TxFee: "1.25"}
		case "dna_sendTransaction":
			result = "0xsent"
		default:
			t.Errorf("unexpected method %s", rpc.Method)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0", "id": rpc.ID, "result": result,
		})
	}))
	defer server.Close()

	client := NewClient(server.URL, "")
	action := []byte(`{"schema":"idena-radicle/anchor/v1"}`)
	estimate, err := client.EstimateForgeAction(context.Background(), "0x1", action, 10, 235, "5")
	if err != nil || estimate.TxHash != "0xestimated" || estimate.TxFee != "1.25" {
		t.Fatalf("estimate = %+v, %v", estimate, err)
	}
	hash, err := client.SendForgeAction(context.Background(), "0x1", action, 10, 235, "5")
	if err != nil || hash != "0xsent" {
		t.Fatalf("send = %q, %v", hash, err)
	}
	if strings.Join(methods, ",") != "bcn_estimateTx,dna_sendTransaction" {
		t.Fatalf("methods = %v", methods)
	}
	if _, err := client.EstimateForgeAction(context.Background(), "0x1", action, 10, 235, "0"); err == nil {
		t.Fatal("zero maximum fee was accepted")
	}
}

func TestScannerUsesInlineActionsAndIgnoresUnrelatedIPFS(t *testing.T) {
	const settlementEpoch = protocol.MainnetActivationEpoch
	key := testPrivateKey(t)
	author := protocol.AddressFromPrivateKey(key)
	bundle, _ := content.CIDForBytes([]byte("Radicle storage bundle"))
	missingBundle, _ := content.CIDForBytes([]byte("missing forge bundle"))
	unrelatedCID, _ := content.CIDForBytes([]byte("unrelated unavailable IPFS object"))
	envelope, err := protocol.NewEnvelope(
		protocol.KindIssue,
		"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
		settlementEpoch,
		author,
		"did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o",
		"00000000000000000000000000000001",
		protocol.IssuePayload{
			Issue:    strings.Repeat("1", 40),
			Action:   strings.Repeat("1", 40),
			Title:    "A native chain issue",
			Bundle:   bundle,
			ActorDID: "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = "test-binding"
	if err := envelope.Sign(key); err != nil {
		t.Fatal(err)
	}
	actionBytes, _ := envelope.Bytes()
	secondEnvelope, err := protocol.NewEnvelope(
		protocol.KindIssue,
		"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
		settlementEpoch,
		author,
		"did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o",
		"00000000000000000000000000000002",
		protocol.IssuePayload{
			Issue:    strings.Repeat("2", 40),
			Action:   strings.Repeat("2", 40),
			Title:    "A second native chain issue",
			Bundle:   missingBundle,
			ActorDID: "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	secondEnvelope.Binding = "test-binding"
	if err := secondEnvelope.Sign(key); err != nil {
		t.Fatal(err)
	}
	secondActionBytes, _ := secondEnvelope.Bytes()
	proof, epochProof := checkpointProofs(key, 103, settlementEpoch, 500_000, 8)
	checkpointHash := proof.BlockHash
	root := proof.StateRoot

	inlinePayload, err := EncodeForgeActionPayload(actionBytes)
	if err != nil {
		t.Fatal(err)
	}
	secondInlinePayload, err := EncodeForgeActionPayload(secondActionBytes)
	if err != nil {
		t.Fatal(err)
	}
	firstTxHash := "0x" + strings.Repeat("5", 64)
	secondTxHash := "0x" + strings.Repeat("6", 64)
	unrelatedTxHash := "0x" + strings.Repeat("7", 64)
	unrelatedCIDBytes, err := cidCast(unrelatedCID)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedStorePayload := protowire.AppendTag(nil, 1, protowire.BytesType)
	unrelatedStorePayload = protowire.AppendBytes(unrelatedStorePayload, unrelatedCIDBytes)
	unrelatedStorePayload = protowire.AppendTag(unrelatedStorePayload, 2, protowire.VarintType)
	unrelatedStorePayload = protowire.AppendVarint(unrelatedStorePayload, 123)
	ipfsRequests := make(map[string]int)
	ipfsAddRequests := 0
	epochCheckpointRequests := 0
	serveTamperedEpochProof := false
	serveTamperedIdentityProof := false
	serveMissingIdentityProof := false

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var rpc struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
			Key    string            `json:"key"`
		}
		if err := json.NewDecoder(request.Body).Decode(&rpc); err != nil {
			t.Error(err)
			return
		}
		if rpc.Key != "test-key" {
			t.Errorf("API key = %q", rpc.Key)
		}
		var result any
		switch rpc.Method {
		case "dna_epoch":
			result = EpochInfo{Epoch: settlementEpoch + 1, StartBlock: 103}
		case "dna_epochCheckpoint":
			epochCheckpointRequests++
			served := epochProof
			if serveTamperedEpochProof {
				served.Value = "0x00"
			}
			result = EpochCheckpoint{Height: 103, BlockHash: checkpointHash, StateRoot: root, Epoch: settlementEpoch + 1, EpochProof: served}
		case "bcn_lastBlock":
			result = Block{Hash: checkpointHash, ParentHash: "0x" + strings.Repeat("3", 64), Height: 103, Root: root, Flags: []string{"ValidationFinished"}}
		case "bcn_blockAt":
			var height uint64
			_ = json.Unmarshal(rpc.Params[0], &height)
			switch height {
			case 101:
				result = Block{Hash: "0x" + strings.Repeat("1", 64), Height: 101, Root: "0x" + strings.Repeat("2", 64), Flags: []string{"ValidationFinished"}}
			case 102:
				result = Block{Hash: "0x" + strings.Repeat("3", 64), ParentHash: "0x" + strings.Repeat("1", 64), Height: 102, Root: "0x" + strings.Repeat("4", 64), Transactions: []string{firstTxHash, unrelatedTxHash, secondTxHash}}
			case 103:
				result = Block{Hash: checkpointHash, ParentHash: "0x" + strings.Repeat("3", 64), Height: 103, Root: root, Flags: []string{"ValidationFinished"}}
			default:
				t.Errorf("unexpected block height %d", height)
			}
		case "bcn_transaction":
			var requested string
			_ = json.Unmarshal(rpc.Params[0], &requested)
			if requested == unrelatedTxHash {
				result = Transaction{
					Hash:      requested,
					Type:      "storeToIpfs",
					From:      author,
					Epoch:     settlementEpoch,
					Payload:   "0x" + hex.EncodeToString(unrelatedStorePayload),
					BlockHash: "0x" + strings.Repeat("3", 64),
				}
				break
			}
			payload := inlinePayload
			if requested == secondTxHash {
				payload = secondInlinePayload
			} else if requested != firstTxHash {
				t.Errorf("unexpected transaction %s", requested)
			}
			result = Transaction{
				Hash:      requested,
				Type:      "send",
				From:      author,
				To:        author,
				Epoch:     settlementEpoch,
				Payload:   "0x" + hex.EncodeToString(payload),
				BlockHash: "0x" + strings.Repeat("3", 64),
			}
		case "ipfs_get":
			var requested string
			_ = json.Unmarshal(rpc.Params[0], &requested)
			ipfsRequests[requested]++
			switch requested {
			case bundle:
				result = "0x" + hex.EncodeToString([]byte("Radicle storage bundle"))
			case missingBundle:
				result = "0x"
			default:
				t.Errorf("unexpected IPFS request %s", requested)
			}
		case "ipfs_add":
			ipfsAddRequests++
			var encoded string
			_ = json.Unmarshal(rpc.Params[0], &encoded)
			data, err := hex.DecodeString(strings.TrimPrefix(encoded, "0x"))
			if err != nil {
				t.Error(err)
			}
			result, err = content.CIDForBytes(data)
			if err != nil {
				t.Error(err)
			}
		case "dna_epochIdentityProof":
			if serveMissingIdentityProof {
				_ = json.NewEncoder(writer).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      rpc.ID,
					"error":   map[string]any{"code": -32000, "message": "identity does not exist"},
				})
				return
			}
			served := proof
			if serveTamperedIdentityProof {
				served.Stake = "1"
			}
			result = served
		default:
			t.Errorf("unexpected RPC method %s", rpc.Method)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result":  result,
		})
	}))
	defer server.Close()

	store, err := content.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	scanner := &Scanner{
		Client:          NewClient(server.URL, "test-key"),
		Store:           store,
		BindingVerifier: func(protocol.Envelope) error { return nil },
		MaxScan:         20,
	}
	scan, err := scanner.ScanLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if scan.Complete || len(scan.Input.Actions) != 2 {
		t.Fatalf("unexpected scan: %+v", scan)
	}
	if len(scan.Input.Proofs) != 1 || !store.Has(bundle) || store.Has(missingBundle) {
		t.Fatalf("missing proof or Radicle bundle: %+v", scan.Input)
	}
	if len(scan.MissingCIDs) != 1 || scan.MissingCIDs[0] != missingBundle {
		t.Fatalf("missing forge content was not isolated: %+v", scan.MissingCIDs)
	}
	if ipfsRequests[unrelatedCID] != 0 {
		t.Fatalf("scanner fetched unrelated StoreToIpfs content %s", unrelatedCID)
	}
	if ipfsAddRequests != 0 {
		t.Fatalf("scanner permanently pinned %d object(s) before checkpoint validation", ipfsAddRequests)
	}
	verification, err := scanner.Client.VerifyCheckpointInput(context.Background(), scan.Input, 20)
	if err != nil {
		t.Fatal(err)
	}
	if verification.Actions != 2 || verification.CheckpointMode != "archived-state-proof" {
		t.Fatalf("unexpected chain verification: %+v", verification)
	}
	if epochCheckpointRequests != 1 {
		t.Fatalf("archived epoch proof unexpectedly required %d checkpoint RPC calls", epochCheckpointRequests)
	}
	replicaVerification, err := scanner.Client.VerifyCheckpointReplica(context.Background(), scan.Input, 20)
	if err != nil {
		t.Fatal(err)
	}
	if replicaVerification != verification {
		t.Fatalf("replica verification = %+v, want %+v", replicaVerification, verification)
	}
	serveTamperedEpochProof = true
	if _, err := scanner.Client.VerifyCheckpointReplica(context.Background(), scan.Input, 20); err == nil || !strings.Contains(err.Error(), "verify peer checkpoint epoch proof") {
		t.Fatalf("tampered peer epoch proof was accepted: %v", err)
	}
	serveTamperedEpochProof = false
	serveTamperedIdentityProof = true
	if _, err := scanner.Client.VerifyCheckpointReplica(context.Background(), scan.Input, 20); err == nil || !strings.Contains(err.Error(), "verify peer identity proof") {
		t.Fatalf("tampered peer proof was accepted: %v", err)
	}
	serveTamperedIdentityProof = false
	serveMissingIdentityProof = true
	if _, err := scanner.ScanLatest(context.Background()); err == nil || !strings.Contains(err.Error(), "identity does not exist") {
		t.Fatalf("unauthenticated identity absence suppressed a canonical voter: %v", err)
	}
	serveMissingIdentityProof = false
	authenticator := func(ctx context.Context, input protocol.CheckpointInput) error {
		_, err := scanner.Client.VerifyCheckpointInput(ctx, input, 20)
		return err
	}
	authenticated, err := protocol.AuthenticateCheckpointInput(context.Background(), scan.Input, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	_, err = protocol.Reduce(authenticated, nil, func(protocol.Envelope) error {
		return nil
	}, func(subject protocol.RadicleSubject) error {
		if subject.BundleCID == missingBundle {
			return protocol.ErrContentUnavailable
		}
		return nil
	})
	if !errors.Is(err, protocol.ErrContentUnavailable) {
		t.Fatalf("authenticated checkpoint did not fail closed on missing content: %v", err)
	}
	tampered := scan.Input
	tampered.Actions = append([]protocol.OnChainAction(nil), scan.Input.Actions...)
	tampered.Actions[0].ActionBytes = append([]byte(nil), scan.Input.Actions[0].ActionBytes...)
	tampered.Actions[0].ActionBytes[0] ^= 1
	if _, err := protocol.AuthenticateCheckpointInput(context.Background(), tampered, authenticator); err == nil {
		t.Fatal("tampered inline action obtained a reducer authentication capability")
	}
	tampered = scan.Input
	tampered.Checkpoint.StateRoot = "0x" + strings.Repeat("f", 64)
	if _, err := protocol.AuthenticateCheckpointInput(context.Background(), tampered, authenticator); err == nil {
		t.Fatal("fabricated checkpoint root obtained a reducer authentication capability")
	}
	tampered = scan.Input
	tampered.Actions = append([]protocol.OnChainAction(nil), scan.Input.Actions...)
	tampered.Actions[0], tampered.Actions[1] = tampered.Actions[1], tampered.Actions[0]
	if _, err := protocol.AuthenticateCheckpointInput(context.Background(), tampered, authenticator); err == nil {
		t.Fatal("reordered inline actions obtained a reducer authentication capability")
	}
	tampered = scan.Input
	tampered.Actions = nil
	if _, err := protocol.AuthenticateCheckpointInput(context.Background(), tampered, authenticator); err == nil {
		t.Fatal("omitted inline action obtained a reducer authentication capability")
	}
	pins, err := store.Pins()
	if err != nil {
		t.Fatal(err)
	}
	foundLease := false
	for _, pin := range pins {
		if pin.CID == bundle {
			foundLease = !pin.Forever && pin.UntilEpoch == settlementEpoch+2 && len(pin.Repositories) == 0
		}
	}
	if !foundLease {
		t.Fatalf("Radicle bundle was not retained with the bounded publication lease: %+v", pins)
	}
}

func TestLatestCheckpointWaitsForValidationFinishedFlag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var rpc struct {
			ID     uint64 `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(request.Body).Decode(&rpc)
		result := Block{Hash: "0x" + strings.Repeat("a", 64), Height: 9, Root: "0x" + strings.Repeat("b", 64)}
		_ = json.NewEncoder(writer).Encode(map[string]any{"jsonrpc": "2.0", "id": rpc.ID, "result": result})
	}))
	defer server.Close()
	scanner := &Scanner{Client: NewClient(server.URL, ""), MaxScan: 5}
	if _, err := scanner.latestCheckpoint(context.Background()); err == nil {
		t.Fatal("expected absence of a ValidationFinished checkpoint")
	}
}

func TestIndexerIdentityProofSource(t *testing.T) {
	key := testPrivateKey(t)
	proof := singleLeafProof(key, 103, 10, 500_000, 8)
	encoded := encodeValueWithProof(t, proof)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		want := "/Epoch/10/Identity/" + proof.Address + "/DataWithProof"
		if request.URL.Path != want {
			t.Errorf("proof path = %q, want %q", request.URL.Path, want)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"result": "0x" + hex.EncodeToString(encoded),
		})
	}))
	defer server.Close()

	source := NewIndexerProofSource(server.URL)
	got, err := source.IdentityProof(
		context.Background(),
		10,
		proof.Height,
		proof.BlockHash,
		proof.StateRoot,
		proof.Address,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "idena-indexer" || got.Epoch != 10 || got.Stake != proof.Stake {
		t.Fatalf("unexpected indexer proof: %+v", got)
	}
	if err := protocol.VerifyIdentityProof(got, proof.StateRoot); err != nil {
		t.Fatal(err)
	}

	if _, err := source.IdentityProof(
		context.Background(),
		10,
		proof.Height,
		proof.BlockHash,
		"0x"+strings.Repeat("f", 64),
		proof.Address,
	); err == nil {
		t.Fatal("proof for a different checkpoint root was accepted")
	}
}

func TestAutoIdentityProofSourceFallsBackAfterRPCError(t *testing.T) {
	want := protocol.IdentityProof{Source: "fallback"}
	source := AutoIdentityProofSource{
		RPC: proofSourceStub(func(context.Context, uint16, uint64, string, string, string) (protocol.IdentityProof, error) {
			return protocol.IdentityProof{}, errors.New("RPC proof unavailable")
		}),
		Indexer: proofSourceStub(func(context.Context, uint16, uint64, string, string, string) (protocol.IdentityProof, error) {
			return want, nil
		}),
	}
	proof, err := source.IdentityProof(context.Background(), 1, 2, "0xblock", "0xroot", "0xaddress")
	if err != nil {
		t.Fatal(err)
	}
	if proof.Source != want.Source {
		t.Fatalf("proof source = %q", proof.Source)
	}
}

func testPrivateKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type proofSourceStub func(context.Context, uint16, uint64, string, string, string) (protocol.IdentityProof, error)

func (source proofSourceStub) IdentityProof(
	ctx context.Context,
	epoch uint16,
	height uint64,
	blockHash string,
	stateRoot string,
	address string,
) (protocol.IdentityProof, error) {
	return source(ctx, epoch, height, blockHash, stateRoot, address)
}

func encodeValueWithProof(t *testing.T, proof protocol.IdentityProof) []byte {
	t.Helper()
	value := mustDecodeHexLocal(t, proof.Value)
	leafKey := mustDecodeHexLocal(t, proof.Leaf.Key)
	valueHash := mustDecodeHexLocal(t, proof.Leaf.ValueHash)
	leaf := protowire.AppendTag(nil, 1, protowire.BytesType)
	leaf = protowire.AppendBytes(leaf, leafKey)
	leaf = protowire.AppendTag(leaf, 2, protowire.BytesType)
	leaf = protowire.AppendBytes(leaf, valueHash)
	leaf = protowire.AppendTag(leaf, 3, protowire.VarintType)
	leaf = protowire.AppendVarint(leaf, proof.Leaf.Version)

	encoded := protowire.AppendTag(nil, 1, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, value)
	encoded = protowire.AppendTag(encoded, 2, protowire.BytesType)
	encoded = protowire.AppendBytes(encoded, leaf)
	for _, step := range proof.Path {
		item := protowire.AppendTag(nil, 1, protowire.VarintType)
		item = protowire.AppendVarint(item, uint64(step.Height))
		item = protowire.AppendTag(item, 2, protowire.VarintType)
		item = protowire.AppendVarint(item, step.Size)
		item = protowire.AppendTag(item, 3, protowire.VarintType)
		item = protowire.AppendVarint(item, step.Version)
		if step.Left != "" {
			item = protowire.AppendTag(item, 4, protowire.BytesType)
			item = protowire.AppendBytes(item, mustDecodeHexLocal(t, step.Left))
		}
		if step.Right != "" {
			item = protowire.AppendTag(item, 5, protowire.BytesType)
			item = protowire.AppendBytes(item, mustDecodeHexLocal(t, step.Right))
		}
		encoded = protowire.AppendTag(encoded, 3, protowire.BytesType)
		encoded = protowire.AppendBytes(encoded, item)
	}
	return encoded
}

func mustDecodeHexLocal(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func singleLeafProof(key *ecdsa.PrivateKey, height uint64, epoch uint16, units int64, identityState uint16) protocol.IdentityProof {
	address := protocol.AddressFromPrivateKey(key)
	addressBytes, _ := hex.DecodeString(strings.TrimPrefix(address, "0x"))
	stateKey := append([]byte{0x02}, addressBytes...)
	stake := protocol.RawStakeFromUnits(units)
	value := protowire.AppendTag(nil, 1, protowire.BytesType)
	value = protowire.AppendBytes(value, stake.Bytes())
	value = protowire.AppendTag(value, 4, protowire.VarintType)
	value = protowire.AppendVarint(value, uint64(identityState))
	valueHash := sha256.Sum256(value)
	root := testIAVLLeafHash(stateKey, valueHash[:], 1)
	blockHash := sha256.Sum256([]byte(fmt.Sprintf("checkpoint-%d-%d", height, epoch)))
	return protocol.IdentityProof{
		Epoch:      epoch,
		StateEpoch: epoch + 1,
		Height:     height,
		BlockHash:  "0x" + hex.EncodeToString(blockHash[:]),
		StateRoot:  "0x" + hex.EncodeToString(root),
		Address:    address,
		Value:      "0x" + hex.EncodeToString(value),
		Stake:      protocol.RawStakeFromUnits(units).String(),
		State:      identityState,
		StateName:  protocol.IdentityStateName(identityState),
		Leaf: protocol.ProofLeaf{
			Key:       "0x" + hex.EncodeToString(stateKey),
			ValueHash: "0x" + hex.EncodeToString(valueHash[:]),
			Version:   1,
		},
		Path: []protocol.ProofStep{},
	}
}

func checkpointProofs(key *ecdsa.PrivateKey, height uint64, epoch uint16, units int64, identityState uint16) (protocol.IdentityProof, protocol.StateValueProof) {
	identity := singleLeafProof(key, height, epoch, units, identityState)
	identityKey := mustDecodeHexString(identity.Leaf.Key)
	identityValue := mustDecodeHexString(identity.Value)
	identityValueHash := sha256.Sum256(identityValue)
	identityLeafHash := testIAVLLeafHash(identityKey, identityValueHash[:], 1)

	globalKey := []byte{0x03}
	globalValue := protowire.AppendTag(nil, 1, protowire.VarintType)
	globalValue = protowire.AppendVarint(globalValue, uint64(epoch+1))
	globalValueHash := sha256.Sum256(globalValue)
	globalLeafHash := testIAVLLeafHash(globalKey, globalValueHash[:], 1)
	root := testIAVLNodeHash(1, 2, 1, identityLeafHash, globalLeafHash)
	rootHex := "0x" + hex.EncodeToString(root)

	identity.StateRoot = rootHex
	identity.Path = []protocol.ProofStep{{
		Height:  1,
		Size:    2,
		Version: 1,
		Right:   "0x" + hex.EncodeToString(globalLeafHash),
	}}
	epochProof := protocol.StateValueProof{
		Value: "0x" + hex.EncodeToString(globalValue),
		Leaf: protocol.ProofLeaf{
			Key:       "0x" + hex.EncodeToString(globalKey),
			ValueHash: "0x" + hex.EncodeToString(globalValueHash[:]),
			Version:   1,
		},
		Path: []protocol.ProofStep{{
			Height:  1,
			Size:    2,
			Version: 1,
			Left:    "0x" + hex.EncodeToString(identityLeafHash),
		}},
	}
	return identity, epochProof
}

func mustDecodeHexString(value string) []byte {
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		panic(err)
	}
	return decoded
}

func testIAVLLeafHash(key, valueHash []byte, version int64) []byte {
	payload := binary.AppendVarint(nil, 0)
	payload = binary.AppendVarint(payload, 1)
	payload = binary.AppendVarint(payload, version)
	payload = appendBytes(payload, key)
	payload = appendBytes(payload, valueHash)
	hash := sha256.Sum256(payload)
	return hash[:]
}

func testIAVLNodeHash(height, size, version int64, left, right []byte) []byte {
	payload := binary.AppendVarint(nil, height)
	payload = binary.AppendVarint(payload, size)
	payload = binary.AppendVarint(payload, version)
	payload = appendBytes(payload, left)
	payload = appendBytes(payload, right)
	hash := sha256.Sum256(payload)
	return hash[:]
}

func appendBytes(output, value []byte) []byte {
	output = protowire.AppendVarint(output, uint64(len(value)))
	return append(output, value...)
}

func cidCast(value string) ([]byte, error) {
	parsed, err := cid.Decode(value)
	if err != nil {
		return nil, err
	}
	return parsed.Bytes(), nil
}
