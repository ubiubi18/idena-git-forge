package protocol

import (
	"context"
	"strings"
	"testing"
)

func TestCurrentReducerPolicyIsStable(t *testing.T) {
	const expected = "idena-radicle/reducer-policy/v3:sha256:4dd6a297acaa7e82ce83bf5b335dfd03196e51a29894127db893fedbc203a4db"
	if got := CurrentReducerPolicy(); got != expected {
		t.Fatalf("current reducer policy = %q, want %q", got, expected)
	}
}

func TestCheckpointPolicyFailsBeforeCanonicalAuthentication(t *testing.T) {
	for _, policy := range []string{"", "idena-radicle/reducer-policy/v2:sha256:" + strings.Repeat("0", 64)} {
		called := false
		_, err := AuthenticateCheckpointInput(context.Background(), CheckpointInput{ReducerPolicy: policy}, func(context.Context, CheckpointInput) error {
			called = true
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "reducer policy") {
			t.Fatalf("policy %q was not rejected: %v", policy, err)
		}
		if called {
			t.Fatalf("policy %q reached canonical-chain authentication", policy)
		}
	}
}

func TestCheckpointResultRejectsUnknownReducerPolicy(t *testing.T) {
	result := CheckpointResult{ReducerPolicy: CurrentReducerPolicy()}
	if err := ValidateCheckpointResultPolicy(result); err != nil {
		t.Fatalf("current policy was rejected: %v", err)
	}
	result.ReducerPolicy = "unknown"
	if err := ValidateCheckpointResultPolicy(result); err == nil {
		t.Fatal("unknown result policy was accepted")
	}
}
