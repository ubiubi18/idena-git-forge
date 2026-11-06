package protocol

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"idena-git-forge/internal/canonicaljson"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/identity"
)

var (
	radicleRIDPattern = regexp.MustCompile(`^rad:z[1-9A-HJ-NP-Za-km-z]+$`)
	radicleDIDPattern = regexp.MustCompile(`^did:key:z[1-9A-HJ-NP-Za-km-z]+$`)
	noncePattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	gitObjectPattern  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
)

func NewEnvelope(kind, repository string, epoch uint16, author, radicleDID, radicleKey, nonce string, payload any) (*Envelope, error) {
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	canonicalPayload, err := canonicaljson.Canonicalize(payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("canonical payload: %w", err)
	}
	normalizedAuthor, err := identity.NormalizeAddress(author)
	if err != nil {
		return nil, err
	}
	envelope := &Envelope{
		Schema:     SchemaActionV1,
		Kind:       kind,
		Repository: repository,
		Epoch:      epoch,
		Author:     normalizedAuthor,
		RadicleDID: radicleDID,
		RadicleKey: strings.TrimSpace(radicleKey),
		Nonce:      strings.ToLower(nonce),
		Payload:    canonicalPayload,
	}
	if err := envelope.ValidateUnsigned(); err != nil {
		return nil, err
	}
	return envelope, nil
}

type unsignedEnvelope struct {
	Schema     string          `json:"schema"`
	Kind       string          `json:"kind"`
	Repository string          `json:"repository"`
	Epoch      uint16          `json:"epoch"`
	Author     string          `json:"author"`
	RadicleDID string          `json:"radicleIdentity"`
	RadicleKey string          `json:"radiclePublicKey"`
	Binding    string          `json:"bindingSignature"`
	Nonce      string          `json:"nonce"`
	Payload    json.RawMessage `json:"payload"`
}

func (envelope Envelope) UnsignedBytes() ([]byte, error) {
	if err := envelope.ValidateUnsigned(); err != nil {
		return nil, err
	}
	unsigned := unsignedEnvelope{
		Schema:     envelope.Schema,
		Kind:       envelope.Kind,
		Repository: envelope.Repository,
		Epoch:      envelope.Epoch,
		Author:     strings.ToLower(envelope.Author),
		RadicleDID: envelope.RadicleDID,
		RadicleKey: envelope.RadicleKey,
		Binding:    envelope.Binding,
		Nonce:      strings.ToLower(envelope.Nonce),
		Payload:    envelope.Payload,
	}
	encoded, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func (envelope Envelope) Bytes() ([]byte, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return canonicaljson.Canonicalize(encoded)
}

func ParseEnvelope(input []byte) (*Envelope, error) {
	var envelope Envelope
	if err := canonicaljson.Unmarshal(input, &envelope); err != nil {
		return nil, err
	}
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	canonical, err := envelope.Bytes()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, input) {
		return nil, errors.New("action envelope is not canonical")
	}
	return &envelope, nil
}

func (envelope Envelope) ValidateUnsigned() error {
	if envelope.Schema != SchemaActionV1 {
		return fmt.Errorf("unsupported action schema %q", envelope.Schema)
	}
	switch envelope.Kind {
	case KindRepository, KindCommit, KindIssue, KindPullRequest, KindComment, KindVote, KindMergeRequest:
	default:
		return fmt.Errorf("unsupported action kind %q", envelope.Kind)
	}
	if !radicleRIDPattern.MatchString(envelope.Repository) {
		return errors.New("repository must be a Radicle repository ID")
	}
	if _, err := identity.NormalizeAddress(envelope.Author); err != nil {
		return fmt.Errorf("author: %w", err)
	}
	if !noncePattern.MatchString(envelope.Nonce) {
		return errors.New("nonce must be 16-byte lowercase hex")
	}
	if !radicleDIDPattern.MatchString(envelope.RadicleDID) {
		return errors.New("radicleIdentity must be a did:key identifier")
	}
	if envelope.RadicleKey == "" {
		return errors.New("radiclePublicKey is required")
	}
	if len(envelope.Payload) == 0 {
		return errors.New("payload is required")
	}
	canonicalPayload, err := canonicaljson.Canonicalize(envelope.Payload)
	if err != nil {
		return fmt.Errorf("payload: %w", err)
	}
	if !bytes.Equal(canonicalPayload, envelope.Payload) {
		return errors.New("payload is not canonical")
	}
	if _, err := envelope.DecodePayload(); err != nil {
		return err
	}
	return nil
}

func (envelope Envelope) Validate() error {
	if err := envelope.ValidateUnsigned(); err != nil {
		return err
	}
	if envelope.Signature == "" {
		return errors.New("signature is required")
	}
	if envelope.Binding == "" {
		return errors.New("bindingSignature is required")
	}
	return envelope.VerifySignature()
}

func (envelope Envelope) RadicleBindingMessage() string {
	return strings.Join([]string{
		"idena-radicle-bind/v1",
		"rid=" + envelope.Repository,
		"idena=" + strings.ToLower(envelope.Author),
		"did=" + envelope.RadicleDID,
		"key=" + envelope.RadicleKey,
		"epoch=" + fmt.Sprint(envelope.Epoch),
	}, "\n")
}

func (envelope Envelope) DecodePayload() (any, error) {
	switch envelope.Kind {
	case KindRepository:
		var payload RepositoryPayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if !gitObjectPattern.MatchString(payload.Head) {
			return nil, errors.New("invalid repository head object id")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("repository bundle: %w", err)
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("repository actor does not match Radicle identity")
		}
		return payload, nil
	case KindCommit:
		var payload CommitPayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if payload.Ref == "" {
			return nil, errors.New("Radicle commit ref is required")
		}
		if !gitObjectPattern.MatchString(payload.Head) {
			return nil, errors.New("invalid commit object id")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("commit bundle: %w", err)
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("commit actor does not match Radicle identity")
		}
		return payload, nil
	case KindIssue:
		var payload IssuePayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if payload.Issue == "" || payload.Action == "" || payload.Title == "" {
			return nil, errors.New("issue id, action and title are required")
		}
		if !gitObjectPattern.MatchString(payload.Issue) || !gitObjectPattern.MatchString(payload.Action) {
			return nil, errors.New("invalid Radicle issue or action object id")
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("issue actor does not match Radicle identity")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("issue bundle: %w", err)
		}
		return payload, nil
	case KindPullRequest:
		var payload PullRequestPayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if payload.Patch == "" || payload.Revision == "" || payload.Title == "" {
			return nil, errors.New("patch, revision and title are required")
		}
		if !gitObjectPattern.MatchString(payload.Patch) || !gitObjectPattern.MatchString(payload.Revision) {
			return nil, errors.New("invalid Radicle patch or revision object id")
		}
		if !gitObjectPattern.MatchString(payload.Base) || !gitObjectPattern.MatchString(payload.Head) {
			return nil, errors.New("invalid PR base or head object id")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("PR bundle: %w", err)
		}
		if err := content.ValidateCID(payload.Diff); err != nil {
			return nil, fmt.Errorf("PR diff: %w", err)
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("patch actor does not match Radicle identity")
		}
		return payload, nil
	case KindComment:
		var payload CommentPayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if (payload.TargetType != "issue" && payload.TargetType != "patch") ||
			payload.TargetID == "" || payload.Comment == "" {
			return nil, errors.New("invalid comment target")
		}
		if !gitObjectPattern.MatchString(payload.TargetID) || !gitObjectPattern.MatchString(payload.Comment) {
			return nil, errors.New("invalid Radicle comment object id")
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("comment actor does not match Radicle identity")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("comment bundle: %w", err)
		}
		return payload, nil
	case KindVote:
		var payload VotePayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if payload.Patch == "" || payload.Revision == "" || payload.Review == "" || payload.ActionOID == "" {
			return nil, errors.New("review patch, revision, review and action are required")
		}
		if payload.Decision != DecisionApprove && payload.Decision != DecisionReject {
			return nil, errors.New("vote decision must be approve or reject")
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("review actor does not match Radicle identity")
		}
		if !gitObjectPattern.MatchString(payload.Patch) || !gitObjectPattern.MatchString(payload.Revision) ||
			!gitObjectPattern.MatchString(payload.Review) || !gitObjectPattern.MatchString(payload.ActionOID) {
			return nil, errors.New("invalid Radicle review object id")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("review bundle: %w", err)
		}
		return payload, nil
	case KindMergeRequest:
		var payload MergeRequestPayload
		if err := canonicaljson.Unmarshal(envelope.Payload, &payload); err != nil {
			return nil, err
		}
		if payload.Patch == "" || payload.Revision == "" || payload.Label == "" || payload.LabelAction == "" {
			return nil, errors.New("merge label patch, revision and action are required")
		}
		if payload.Label != "idena/merge-request" {
			return nil, errors.New("merge label must be idena/merge-request")
		}
		if payload.ActorDID != envelope.RadicleDID {
			return nil, errors.New("merge label actor does not match Radicle identity")
		}
		if !gitObjectPattern.MatchString(payload.Patch) || !gitObjectPattern.MatchString(payload.Revision) || !gitObjectPattern.MatchString(payload.LabelAction) {
			return nil, errors.New("invalid Radicle merge-label action id")
		}
		if err := content.ValidateCID(payload.Bundle); err != nil {
			return nil, fmt.Errorf("merge-label bundle: %w", err)
		}
		return payload, nil
	default:
		return nil, errors.New("unknown payload kind")
	}
}

func (envelope *Envelope) Sign(privateKey *ecdsa.PrivateKey) error {
	unsigned, err := envelope.UnsignedBytes()
	if err != nil {
		return err
	}
	signature, err := identity.Sign(string(unsigned), privateKey)
	if err != nil {
		return err
	}
	envelope.Signature = "0x" + hex.EncodeToString(signature)
	return envelope.Validate()
}

func (envelope *Envelope) AttachSignature(signature []byte) error {
	if len(signature) != 65 {
		return errors.New("Idena signature must be 65 bytes")
	}
	envelope.Signature = "0x" + hex.EncodeToString(signature)
	return envelope.Validate()
}

func (envelope Envelope) SigningHash() [32]byte {
	unsigned, err := envelope.UnsignedBytes()
	if err != nil {
		return [32]byte{}
	}
	return identity.SignedMessageHash(string(unsigned))
}

func (envelope Envelope) VerifySignature() error {
	unsigned, err := envelope.UnsignedBytes()
	if err != nil {
		return err
	}
	signatureHex := strings.TrimPrefix(strings.ToLower(envelope.Signature), "0x")
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	address, err := identity.RecoverAddress(identity.SignedMessageHash(string(unsigned)), signature)
	if err != nil {
		return err
	}
	if address != strings.ToLower(envelope.Author) {
		return errors.New("signature does not recover to the declared author")
	}
	return nil
}

func (envelope Envelope) ID() string {
	bytes, err := envelope.Bytes()
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(bytes)
	return "act_" + hex.EncodeToString(hash[:])
}

func AddressFromPrivateKey(privateKey *ecdsa.PrivateKey) string {
	return identity.Address(secp256k1.PrivKeyFromBytes(privateKey.D.FillBytes(make([]byte, 32))).PubKey())
}

func Revision(payload PullRequestPayload) (string, error) {
	if !gitObjectPattern.MatchString(payload.Revision) {
		return "", errors.New("invalid Radicle revision object id")
	}
	return payload.Revision, nil
}

func mustMarshal(value any) []byte {
	bytes, _ := json.Marshal(value)
	return bytes
}

func DecodePayload[T any](envelope Envelope) (T, error) {
	var zero T
	if err := canonicaljson.Unmarshal(envelope.Payload, &zero); err != nil {
		return zero, err
	}
	return zero, nil
}
