package demo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

func TestDemoProducesReplayableCheckpoint(t *testing.T) {
	root := filepath.Join(t.TempDir(), "demo")
	result, err := Run(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{result.InputPath, result.CheckpointPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(result.InputPath)
	if err != nil {
		t.Fatal(err)
	}
	var input protocol.CheckpointInput
	if err := jsonUnmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	store, err := content.Open(result.ContentDir)
	if err != nil {
		t.Fatal(err)
	}
	if !store.Has(input.Actions[0].ActionCID) {
		t.Fatal("demo action content is not pinned")
	}
	checkpointData, err := os.ReadFile(result.CheckpointPath)
	if err != nil {
		t.Fatal(err)
	}
	var checkpoint protocol.CheckpointResult
	if err := jsonUnmarshal(checkpointData, &checkpoint); err != nil {
		t.Fatal(err)
	}
	if len(checkpoint.Repositories) != 1 || len(checkpoint.Repositories[0].PRs) != 1 {
		t.Fatalf("demo checkpoint = %+v", checkpoint)
	}
	pr := checkpoint.Repositories[0].PRs[0]
	if pr.UniqueVoters != 3 || pr.ApprovalVoters != 2 || !pr.Approved {
		t.Fatalf("demo quorum = %+v", pr)
	}
}

func jsonUnmarshal(data []byte, destination any) error {
	return json.Unmarshal(data, destination)
}
