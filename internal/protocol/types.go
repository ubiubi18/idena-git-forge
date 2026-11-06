package protocol

import (
	"encoding/json"
	"errors"
)

const (
	SchemaActionV1 = "idena-radicle/anchor/v1"

	KindRepository   = "radicle_repository"
	KindCommit       = "radicle_commit"
	KindIssue        = "radicle_issue"
	KindPullRequest  = "radicle_patch"
	KindComment      = "radicle_comment"
	KindVote         = "radicle_review"
	KindMergeRequest = "radicle_merge_label"
)

const (
	DecisionApprove = "approve"
	DecisionReject  = "reject"
)

const (
	// Identity counts are a participation floor, not a Sybil-resistance or
	// operator-independence mechanism. Economic authority comes from the raw
	// checkpoint-stake threshold and the sublinear weighted-stake majority.
	MaxActionsPerEpoch     = 20
	MinDecisionVoters      = 3
	MinApprovalVoters      = 2
	DecisionStakeThreshold = "500000000000000000000000"
	IDenaBase              = "1000000000000000000"
	CheckpointFlagName     = "ValidationFinished"
)

type Envelope struct {
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
	Signature  string          `json:"signature,omitempty"`
}

type RepositoryPayload struct {
	Head     string `json:"head"`
	Bundle   string `json:"bundle"`
	ActorDID string `json:"actorDid"`
}

type CommitPayload struct {
	Ref      string `json:"ref"`
	Head     string `json:"head"`
	Bundle   string `json:"bundle"`
	ActorDID string `json:"actorDid"`
}

type IssuePayload struct {
	Issue    string `json:"issue"`
	Action   string `json:"action"`
	Title    string `json:"title"`
	Bundle   string `json:"bundle"`
	ActorDID string `json:"actorDid"`
}

type PullRequestPayload struct {
	Patch            string `json:"patch"`
	Revision         string `json:"revision"`
	Title            string `json:"title"`
	Base             string `json:"base"`
	Head             string `json:"head"`
	Bundle           string `json:"bundle"`
	Diff             string `json:"diff"`
	ActorDID         string `json:"actorDid"`
	DeleteRepository bool   `json:"deleteRepository,omitempty"`
}

type CommentPayload struct {
	TargetType string `json:"targetType"`
	TargetID   string `json:"targetId"`
	Comment    string `json:"comment"`
	Bundle     string `json:"bundle"`
	ActorDID   string `json:"actorDid"`
}

type VotePayload struct {
	Patch     string `json:"patch"`
	Revision  string `json:"revision"`
	Decision  string `json:"decision"`
	Review    string `json:"review"`
	ActionOID string `json:"actionOid"`
	Bundle    string `json:"bundle"`
	ActorDID  string `json:"actorDid"`
}

type MergeRequestPayload struct {
	Patch       string `json:"patch"`
	Revision    string `json:"revision"`
	Label       string `json:"label"`
	LabelAction string `json:"labelAction"`
	Bundle      string `json:"bundle"`
	ActorDID    string `json:"actorDid"`
}

type OnChainAction struct {
	Height      uint64    `json:"height"`
	BlockHash   string    `json:"blockHash"`
	TxHash      string    `json:"txHash"`
	TxIndex     uint32    `json:"txIndex"`
	TxType      string    `json:"txType"`
	TxSender    string    `json:"txSender"`
	TxRecipient string    `json:"txRecipient"`
	TxEpoch     uint16    `json:"txEpoch"`
	ActionCID   string    `json:"actionCid"`
	ActionBytes []byte    `json:"actionBytes"`
	Action      *Envelope `json:"-"`
}

type RadicleSubject struct {
	RID        string `json:"rid"`
	ActorDID   string `json:"actorDid"`
	Kind       string `json:"kind"`
	BundleCID  string `json:"bundleCid"`
	CobType    string `json:"cobType,omitempty"`
	CobID      string `json:"cobId,omitempty"`
	ActionOID  string `json:"actionOid,omitempty"`
	PatchID    string `json:"patchId,omitempty"`
	RevisionID string `json:"revisionId,omitempty"`
	ReviewID   string `json:"reviewId,omitempty"`
	Base       string `json:"base,omitempty"`
	Head       string `json:"head,omitempty"`
	Ref        string `json:"ref,omitempty"`
	Label      string `json:"label,omitempty"`
	Verdict    string `json:"verdict,omitempty"`
}

type BindingVerifier func(Envelope) error
type RadicleVerifier func(RadicleSubject) error

var ErrContentUnavailable = errors.New("required content is unavailable")

type CheckpointBlock struct {
	Epoch      uint16          `json:"epoch"`
	Height     uint64          `json:"height"`
	Hash       string          `json:"hash"`
	StateRoot  string          `json:"stateRoot"`
	Time       int64           `json:"time"`
	EpochProof StateValueProof `json:"epochProof"`
}

type ProofLeaf struct {
	Key       string `json:"key"`
	ValueHash string `json:"valueHash"`
	Version   uint64 `json:"version"`
}

type ProofStep struct {
	Height  int16  `json:"height"`
	Size    uint64 `json:"size"`
	Version uint64 `json:"version"`
	Left    string `json:"left,omitempty"`
	Right   string `json:"right,omitempty"`
}

// StateValueProof is a portable IAVL membership proof for one raw state-tree
// value. Checkpoint records use it for the global epoch object so the
// post-transition epoch remains independently verifiable after nodes prune the
// historical state version.
type StateValueProof struct {
	Value string      `json:"value"`
	Leaf  ProofLeaf   `json:"leaf"`
	Path  []ProofStep `json:"path"`
}

type IdentityProof struct {
	Epoch      uint16      `json:"epoch"`
	StateEpoch uint16      `json:"stateEpoch,omitempty"`
	Source     string      `json:"source,omitempty"`
	Height     uint64      `json:"height"`
	BlockHash  string      `json:"blockHash"`
	StateRoot  string      `json:"stateRoot"`
	Address    string      `json:"address"`
	Value      string      `json:"value"`
	Stake      string      `json:"stake"`
	State      uint16      `json:"state"`
	StateName  string      `json:"stateName"`
	Leaf       ProofLeaf   `json:"leaf"`
	Path       []ProofStep `json:"path"`
}

type CheckpointInput struct {
	ReducerPolicy string                   `json:"reducerPolicy"`
	Checkpoint    CheckpointBlock          `json:"checkpoint"`
	Actions       []OnChainAction          `json:"actions"`
	Proofs        map[string]IdentityProof `json:"proofs"`
	// PreviousHeads and PreviousDeletions are reducer-internal replay state.
	// They are deliberately excluded from serialized checkpoint input and are
	// accepted only by the explicitly non-consensus fixture reducer.
	PreviousHeads     map[string]string             `json:"-"`
	PreviousDeletions map[string]RepositoryDeletion `json:"-"`
}

// MainnetActivationEpoch is the first epoch in which the forge action format
// was published on Idena mainnet. Production replay must start here so a
// caller cannot omit an earlier authenticated checkpoint and silently derive
// repository state from an incomplete suffix.
const MainnetActivationEpoch uint16 = 235

type RepositoryDeletion struct {
	Epoch           uint16 `json:"epoch"`
	PruneAfterEpoch uint16 `json:"pruneAfterEpoch"`
}

type Rejection struct {
	ActionID string `json:"actionId,omitempty"`
	TxHash   string `json:"txHash,omitempty"`
	Reason   string `json:"reason"`
}

type Ballot struct {
	Voter    string `json:"voter"`
	State    string `json:"state"`
	Decision string `json:"decision"`
	Stake    string `json:"stake"`
	Weight   string `json:"weight"`
	ActionID string `json:"actionId"`
	TxHash   string `json:"txHash"`
}

type PRResult struct {
	Repository     string   `json:"repository"`
	PR             string   `json:"pr"`
	Revision       string   `json:"revision"`
	Title          string   `json:"title"`
	Author         string   `json:"radicleAuthor"`
	IdenaAuthor    string   `json:"idenaAuthor"`
	Base           string   `json:"base"`
	Head           string   `json:"head"`
	DiffCID        string   `json:"diffCid"`
	BundleCID      string   `json:"bundleCid"`
	ActionCID      string   `json:"actionCid"`
	MergeRequested bool     `json:"mergeRequested"`
	Approved       bool     `json:"approved"`
	Eligible       bool     `json:"eligible"`
	Reason         string   `json:"reason"`
	Ballots        []Ballot `json:"ballots"`
	UniqueVoters   int      `json:"uniqueVoters"`
	ApprovalVoters int      `json:"approvalVoters"`
	// IdentityMajority is retained as an informational and backwards-compatible
	// result field. It is not a decision gate from source version 0.6.3 onward.
	IdentityMajority  bool   `json:"identityMajority"`
	CombinedStake     string `json:"combinedStake"`
	ApprovalStake     string `json:"approvalStake"`
	RejectionStake    string `json:"rejectionStake"`
	ApprovalWeight    string `json:"approvalWeight"`
	RejectionWeight   string `json:"rejectionWeight"`
	CombinedWeight    string `json:"combinedWeight"`
	NetWeight         string `json:"netWeight"`
	StakeMajority     bool   `json:"stakeMajority"`
	MergeRequestTx    string `json:"mergeRequestTx,omitempty"`
	MergeRequestOrder uint64 `json:"mergeRequestOrder"`
	// Availability is replica-local UI state and is not part of the canonical
	// checkpoint result. The web UI derives it from its local content store.
	Availability     ContentAvailability `json:"-"`
	DeleteRepository bool                `json:"deleteRepository,omitempty"`
}

type ContentAvailability struct {
	Action        bool            `json:"action"`
	Bundle        bool            `json:"bundle"`
	Diff          bool            `json:"diff"`
	Continuous    bool            `json:"continuous"`
	RequiredUntil uint16          `json:"requiredUntil"`
	Objects       map[string]bool `json:"objects"`
}

type RepositoryResult struct {
	Repository      string     `json:"repository"`
	PreviousHead    string     `json:"previousHead"`
	CanonicalHead   string     `json:"canonicalHead"`
	Winner          string     `json:"winner,omitempty"`
	WinnerRevision  string     `json:"winnerRevision,omitempty"`
	Deleted         bool       `json:"deleted,omitempty"`
	PruneAfterEpoch uint16     `json:"pruneAfterEpoch,omitempty"`
	PRs             []PRResult `json:"prs"`
}

type CheckpointResult struct {
	ReducerPolicy string             `json:"reducerPolicy"`
	Checkpoint    CheckpointBlock    `json:"checkpoint"`
	Repositories  []RepositoryResult `json:"repositories"`
	Rejected      []Rejection        `json:"rejected"`
	InputDigest   string             `json:"inputDigest"`
}
