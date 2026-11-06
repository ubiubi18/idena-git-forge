package idena

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"idena-git-forge/internal/protocol"
)

type Client struct {
	endpoint string
	apiKey   string
	http     *http.Client
	nextID   atomic.Uint64
}

type Block struct {
	Hash         string   `json:"hash"`
	ParentHash   string   `json:"parentHash"`
	Height       uint64   `json:"height"`
	Timestamp    int64    `json:"timestamp"`
	Root         string   `json:"root"`
	IdentityRoot string   `json:"identityRoot"`
	Transactions []string `json:"transactions"`
	Flags        []string `json:"flags"`
}

type Transaction struct {
	Hash      string `json:"hash"`
	Type      string `json:"type"`
	From      string `json:"from"`
	To        string `json:"to"`
	Epoch     uint16 `json:"epoch"`
	Payload   string `json:"payload"`
	BlockHash string `json:"blockHash"`
}

type EpochInfo struct {
	StartBlock uint64 `json:"startBlock"`
	Epoch      uint16 `json:"epoch"`
}

type EpochCheckpoint struct {
	Height     uint64                   `json:"height"`
	BlockHash  string                   `json:"blockHash"`
	StateRoot  string                   `json:"stateRoot"`
	Epoch      uint16                   `json:"epoch"`
	EpochProof protocol.StateValueProof `json:"epochProof"`
}

type ContractArg struct {
	Index  int    `json:"index"`
	Format string `json:"format"`
	Value  string `json:"value"`
}

type ContractCallArgs struct {
	From     string        `json:"from"`
	Contract string        `json:"contract"`
	Method   string        `json:"method"`
	Amount   string        `json:"amount"`
	Args     []ContractArg `json:"args"`
	MaxFee   string        `json:"maxFee,omitempty"`
}

type ContractEstimate struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	TxFee   string `json:"txFee"`
	GasCost string `json:"gasCost"`
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	Key     string `json:"key,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewClient(endpoint, apiKey string) *Client {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		apiKey:   apiKey,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (client *Client) Epoch(ctx context.Context) (EpochInfo, error) {
	var result EpochInfo
	err := client.call(ctx, "dna_epoch", nil, &result)
	return result, err
}

func (client *Client) CoinbaseAddress(ctx context.Context) (string, error) {
	var address string
	err := client.call(ctx, "dna_getCoinbaseAddr", nil, &address)
	return address, err
}

func (client *Client) LastBlock(ctx context.Context) (*Block, error) {
	var result *Block
	if err := client.call(ctx, "bcn_lastBlock", nil, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("node returned no last block")
	}
	return result, nil
}

func (client *Client) BlockAt(ctx context.Context, height uint64) (*Block, error) {
	var result *Block
	if err := client.call(ctx, "bcn_blockAt", []any{height}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("block %d not found", height)
	}
	return result, nil
}

func (client *Client) Transaction(ctx context.Context, hash string) (*Transaction, error) {
	var result *Transaction
	if err := client.call(ctx, "bcn_transaction", []any{hash}, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("transaction %s not found", hash)
	}
	return result, nil
}

func (client *Client) IPFSGet(ctx context.Context, contentCID string) ([]byte, error) {
	var encoded string
	if err := client.call(ctx, "ipfs_get", []any{contentCID}, &encoded); err != nil {
		return nil, err
	}
	return decodeHex(encoded)
}

func (client *Client) IPFSAdd(ctx context.Context, data []byte, pin bool) (string, error) {
	var contentCID string
	if err := client.call(ctx, "ipfs_add", []any{"0x" + hex.EncodeToString(data), pin}, &contentCID); err != nil {
		return "", err
	}
	return contentCID, nil
}

func (client *Client) IPFSCID(ctx context.Context, data []byte) (string, error) {
	var contentCID string
	if err := client.call(ctx, "ipfs_cid", []any{"0x" + hex.EncodeToString(data)}, &contentCID); err != nil {
		return "", err
	}
	return contentCID, nil
}

func (client *Client) Sign(ctx context.Context, value string) ([]byte, error) {
	var encoded string
	if err := client.call(ctx, "dna_sign", []any{value, "prefix"}, &encoded); err != nil {
		return nil, err
	}
	return decodeHex(encoded)
}

func (client *Client) EpochIdentityProof(ctx context.Context, height uint64, blockHash, address string) (protocol.IdentityProof, error) {
	var proof protocol.IdentityProof
	args := map[string]any{
		"height":    height,
		"blockHash": blockHash,
		"address":   address,
	}
	err := client.call(ctx, "dna_epochIdentityProof", []any{args}, &proof)
	return proof, err
}

func (client *Client) EpochCheckpoint(ctx context.Context, height uint64, blockHash string) (EpochCheckpoint, error) {
	var checkpoint EpochCheckpoint
	args := map[string]any{
		"height":    height,
		"blockHash": blockHash,
	}
	err := client.call(ctx, "dna_epochCheckpoint", []any{args}, &checkpoint)
	return checkpoint, err
}

func (client *Client) IdentityProof(
	ctx context.Context,
	epoch uint16,
	height uint64,
	blockHash string,
	stateRoot string,
	address string,
) (protocol.IdentityProof, error) {
	proof, err := client.EpochIdentityProof(ctx, height, blockHash, address)
	if err != nil {
		return protocol.IdentityProof{}, err
	}
	if !strings.EqualFold(proof.StateRoot, stateRoot) {
		return protocol.IdentityProof{}, errors.New("RPC identity proof state root differs from checkpoint")
	}
	if proof.StateEpoch != 0 && proof.StateEpoch != epoch+1 {
		return protocol.IdentityProof{}, errors.New("RPC identity proof state epoch differs from checkpoint epoch")
	}
	proof.Epoch = epoch
	proof.Source = "idena-rpc"
	return proof, nil
}

type ForgeActionEstimate struct {
	TxHash string `json:"txHash"`
	TxFee  string `json:"txFee"`
}

func (client *Client) EstimateForgeAction(
	ctx context.Context,
	from string,
	action []byte,
	nonce uint32,
	epoch uint16,
	maxFee string,
) (ForgeActionEstimate, error) {
	args, err := forgeActionTxArgs(from, action, nonce, epoch, maxFee)
	if err != nil {
		return ForgeActionEstimate{}, err
	}
	var estimate ForgeActionEstimate
	err = client.call(ctx, "bcn_estimateTx", []any{args}, &estimate)
	return estimate, err
}

func (client *Client) SendForgeAction(
	ctx context.Context,
	from string,
	action []byte,
	nonce uint32,
	epoch uint16,
	maxFee string,
) (string, error) {
	args, err := forgeActionTxArgs(from, action, nonce, epoch, maxFee)
	if err != nil {
		return "", err
	}
	var txHash string
	err = client.call(ctx, "dna_sendTransaction", []any{args}, &txHash)
	return txHash, err
}

func forgeActionTxArgs(from string, action []byte, nonce uint32, epoch uint16, maxFee string) (map[string]any, error) {
	maxFee = strings.TrimSpace(maxFee)
	fee, ok := new(big.Rat).SetString(maxFee)
	if !ok || fee.Sign() <= 0 {
		return nil, errors.New("maximum transaction fee must be a positive amount")
	}
	payload, err := EncodeForgeActionPayload(action)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"type":     0,
		"from":     from,
		"to":       from,
		"amount":   "0",
		"maxFee":   maxFee,
		"tips":     "0",
		"nonce":    nonce,
		"epoch":    epoch,
		"payload":  "0x" + hex.EncodeToString(payload),
		"useProto": true,
	}, nil
}

func (client *Client) StoreToIPFS(ctx context.Context, contentCID string, nonce uint32, epoch uint16) (string, error) {
	var txHash string
	args := map[string]any{
		"cid":   contentCID,
		"nonce": nonce,
		"epoch": epoch,
	}
	err := client.call(ctx, "dna_storeToIpfs", []any{args}, &txHash)
	return txHash, err
}

func (client *Client) EstimateContractCall(ctx context.Context, args ContractCallArgs) (ContractEstimate, error) {
	var result ContractEstimate
	err := client.call(ctx, "contract_estimateCall", []any{args}, &result)
	return result, err
}

func (client *Client) ContractCall(ctx context.Context, args ContractCallArgs) (string, error) {
	var result string
	err := client.call(ctx, "contract_call", []any{args}, &result)
	return result, err
}

func (client *Client) call(ctx context.Context, method string, params []any, destination any) error {
	if client.endpoint == "" {
		return errors.New("Idena RPC endpoint is required")
	}
	request := rpcRequest{
		JSONRPC: "2.0",
		ID:      client.nextID.Add(1),
		Method:  method,
		Params:  params,
		Key:     client.apiKey,
	}
	if request.Params == nil {
		request.Params = []any{}
	}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s: HTTP %d: %s", method, response.StatusCode, strings.TrimSpace(string(payload)))
	}
	var decoded rpcResponse
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return fmt.Errorf("%s: decode response: %w", method, err)
	}
	if decoded.Error != nil {
		return fmt.Errorf("%s: RPC %d: %s", method, decoded.Error.Code, decoded.Error.Message)
	}
	if len(decoded.Result) == 0 || string(decoded.Result) == "null" {
		return fmt.Errorf("%s: empty result", method)
	}
	if err := json.Unmarshal(decoded.Result, destination); err != nil {
		return fmt.Errorf("%s: decode result: %w", method, err)
	}
	return nil
}

func decodeHex(value string) ([]byte, error) {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	if value == "" {
		return []byte{}, nil
	}
	if len(value)%2 != 0 {
		return nil, errors.New("hex response has odd length")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

func ParseInt64(value json.Number) (int64, error) {
	return strconv.ParseInt(value.String(), 10, 64)
}
