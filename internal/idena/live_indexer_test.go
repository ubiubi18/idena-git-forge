package idena

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"

	"idena-git-forge/internal/protocol"
)

func TestLiveIndexerProof(t *testing.T) {
	address := os.Getenv("IDENA_LIVE_ADDRESS")
	epochText := os.Getenv("IDENA_LIVE_EPOCH")
	stateRoot := os.Getenv("IDENA_LIVE_STATE_ROOT")
	if address == "" || epochText == "" || stateRoot == "" {
		t.Skip("live indexer proof environment is not configured")
	}
	epoch, err := strconv.ParseUint(epochText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	source := NewIndexerProofSource("https://api.idena.io/api")
	proof, err := source.IdentityProof(
		context.Background(),
		uint16(epoch),
		0,
		"0x"+strings.Repeat("0", 64),
		stateRoot,
		address,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.VerifyIdentityProof(proof, stateRoot); err != nil {
		t.Fatal(err)
	}
	t.Logf("verified %s epoch proof: stake=%s state=%s", address, proof.Stake, proof.StateName)
}
