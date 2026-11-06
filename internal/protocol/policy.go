package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const reducerPolicySchema = "idena-radicle/reducer-policy/v3"

// currentReducerPolicyDefinition is the canonical, byte-for-byte definition
// of the settlement rules implemented by source version 0.6.3. Changing any
// consensus rule requires changing this definition, which changes the policy
// identifier carried by every checkpoint input and result.
const currentReducerPolicyDefinition = `{"activationEpoch":235,"candidateOrdering":["higherNetWeight","higherApprovalWeight","higherCombinedRawStake","earlierCanonicalMergeRequest","lexicographicallySmallerExactRevision","lexicographicallySmallerPatchId"],"combinedParticipatingRawStakeMinimum":"500000000000000000000000","eligibleIdentityStates":[3,7,8],"fastForwardRequired":true,"identityApprovalMajorityRequired":false,"maxActionsPerIdentityPerEpoch":20,"mergeRequiresExactRevision":true,"minimumApprovalVoters":2,"minimumDistinctVoters":3,"repositoryDeletionGraceEpochs":2,"schema":"idena-radicle/reducer-policy/v3","strictApprovalWeightMajority":true,"weight":"floor(rawStake^(9/10))"}`

// CurrentReducerPolicy returns the exact policy identifier accepted by this
// reducer. It includes a digest so checkpoint evidence cannot be replayed
// under a reducer with different governance semantics.
func CurrentReducerPolicy() string {
	digest := sha256.Sum256([]byte(currentReducerPolicyDefinition))
	return reducerPolicySchema + ":sha256:" + hex.EncodeToString(digest[:])
}

// ValidateReducerPolicy fails closed for omitted, legacy, or unknown policy
// identifiers. Historical checkpoint artifacts remain valid evidence for
// their original binaries, but are not accepted as 0.6.3 settlement inputs.
func ValidateReducerPolicy(policy string) error {
	expected := CurrentReducerPolicy()
	if policy == "" {
		return fmt.Errorf("checkpoint reducer policy is required; expected %s", expected)
	}
	if policy != expected {
		return fmt.Errorf("checkpoint reducer policy %q is unsupported; expected %s", policy, expected)
	}
	return nil
}

func ValidateCheckpointInputPolicy(input CheckpointInput) error {
	return ValidateReducerPolicy(input.ReducerPolicy)
}

func ValidateCheckpointResultPolicy(result CheckpointResult) error {
	return ValidateReducerPolicy(result.ReducerPolicy)
}
