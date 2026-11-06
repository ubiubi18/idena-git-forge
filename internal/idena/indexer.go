package idena

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"idena-git-forge/internal/protocol"
)

type IdentityProofSource interface {
	IdentityProof(ctx context.Context, epoch uint16, height uint64, blockHash, stateRoot, address string) (protocol.IdentityProof, error)
}

type IndexerProofSource struct {
	endpoint string
	http     *http.Client
}

func NewIndexerProofSource(endpoint string) *IndexerProofSource {
	return &IndexerProofSource{
		endpoint: strings.TrimRight(endpoint, "/"),
		http:     &http.Client{Timeout: 20 * time.Second},
	}
}

func (source *IndexerProofSource) IdentityProof(
	ctx context.Context,
	epoch uint16,
	height uint64,
	blockHash string,
	stateRoot string,
	address string,
) (protocol.IdentityProof, error) {
	if source.endpoint == "" {
		return protocol.IdentityProof{}, errors.New("Idena indexer endpoint is required")
	}
	requestURL := fmt.Sprintf(
		"%s/Epoch/%d/Identity/%s/DataWithProof",
		source.endpoint,
		epoch,
		url.PathEscape(address),
	)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return protocol.IdentityProof{}, err
	}
	response, err := source.http.Do(request)
	if err != nil {
		return protocol.IdentityProof{}, fmt.Errorf("Idena indexer proof: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return protocol.IdentityProof{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return protocol.IdentityProof{}, fmt.Errorf("Idena indexer proof: HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Result string `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return protocol.IdentityProof{}, fmt.Errorf("decode Idena indexer proof: %w", err)
	}
	if payload.Error.Message != "" {
		return protocol.IdentityProof{}, errors.New(payload.Error.Message)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(payload.Result), "0x"))
	if err != nil || len(raw) == 0 {
		return protocol.IdentityProof{}, errors.New("Idena indexer returned no valid identity proof")
	}
	proof, err := protocol.DecodeValueWithProof(raw, height, blockHash, stateRoot, address)
	if err != nil {
		return protocol.IdentityProof{}, err
	}
	proof.Epoch = epoch
	proof.Source = "idena-indexer"
	if err := protocol.VerifyIdentityProof(proof, stateRoot); err != nil {
		return protocol.IdentityProof{}, fmt.Errorf("Idena indexer proof does not match checkpoint root: %w", err)
	}
	return proof, nil
}

type AutoIdentityProofSource struct {
	RPC     IdentityProofSource
	Indexer IdentityProofSource
}

func (source AutoIdentityProofSource) IdentityProof(
	ctx context.Context,
	epoch uint16,
	height uint64,
	blockHash string,
	stateRoot string,
	address string,
) (protocol.IdentityProof, error) {
	var rpcErr error
	if source.RPC != nil {
		proof, err := source.RPC.IdentityProof(ctx, epoch, height, blockHash, stateRoot, address)
		if err == nil {
			return proof, nil
		}
		rpcErr = err
	}
	if source.Indexer == nil {
		return protocol.IdentityProof{}, fmt.Errorf("RPC proof unavailable: %w", rpcErr)
	}
	proof, err := source.Indexer.IdentityProof(ctx, epoch, height, blockHash, stateRoot, address)
	if err != nil {
		return protocol.IdentityProof{}, fmt.Errorf("RPC proof unavailable: %v; indexer fallback failed: %w", rpcErr, err)
	}
	return proof, nil
}
