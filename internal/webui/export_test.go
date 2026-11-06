package webui

import (
	"strings"
	"testing"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

func TestStandaloneExportIsSelfContained(t *testing.T) {
	store, err := content.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	diffCID, err := store.Put([]byte("@@ -1 +1 @@\n-old\n+new\n"), 3)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := protocol.CheckpointResult{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    protocol.CheckpointBlock{Epoch: 3, Height: 30, Hash: "0xblock", StateRoot: "0xroot"},
		InputDigest:   "sha256:input",
		Repositories: []protocol.RepositoryResult{{
			Repository:     "rad:test",
			CanonicalHead:  strings.Repeat("a", 40),
			Winner:         "patch-1",
			WinnerRevision: "rev-1",
			PRs: []protocol.PRResult{{
				PR: "patch-1", Revision: "rev-1", Title: "Exact preview",
				Base: strings.Repeat("b", 40), Head: strings.Repeat("a", 40),
				DiffCID: diffCID, Reason: "ballot passed", Eligible: true,
				UniqueVoters: 3, ApprovalVoters: 2,
				CombinedStake:    "500000000000000000000000",
				IdentityMajority: true, StakeMajority: true,
			}},
		}},
	}
	html, manifest, err := ExportStandalone(checkpoint, store)
	if err != nil {
		t.Fatal(err)
	}
	text := string(html)
	for _, forbidden := range []string{`fetch(`, `<script`, `src="/`, `href="/api/`} {
		if strings.Contains(strings.ToLower(text), strings.ToLower(forbidden)) {
			t.Fatalf("standalone preview contains network dependency %q", forbidden)
		}
	}
	if !strings.Contains(text, "Exact preview") || !strings.Contains(text, "winning revision") || !strings.Contains(text, "new") ||
		!strings.Contains(text, "identity-count majority (informational):") {
		t.Fatal("preview does not contain the exact PR and diff")
	}
	if manifest.HTMLBytes != len(html) || len(manifest.EmbeddedDiffCIDs) != 1 ||
		manifest.EmbeddedDiffCIDs[0] != diffCID {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if manifest.HTMLBytes > MaxStandaloneBytes {
		t.Fatal("test fixture exceeded the Idena IPFS publishing limit")
	}
}

func TestSocialPostPlanUsesPlainTextDiscoveryReference(t *testing.T) {
	plan, err := SocialPost(protocol.CheckpointResult{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    protocol.CheckpointBlock{Epoch: 9, Height: 99},
	}, "bafkreitest", "r/idena")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Contract != IdenaSocialContract || plan.Method != "makePost" ||
		!strings.Contains(plan.Message, "idena-radicle://bafkreitest") {
		t.Fatalf("unexpected social post: %+v", plan)
	}
	if strings.Contains(plan.Message, "https://") {
		t.Fatal("social share must not depend on a hosted website")
	}
}

func TestStandaloneExportFailsInsteadOfOmittingAnOversizedDiff(t *testing.T) {
	store, err := content.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	diffCID, err := store.Put([]byte(strings.Repeat("x", MaxStandaloneBytes)), 2)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ExportStandalone(protocol.CheckpointResult{
		ReducerPolicy: protocol.CurrentReducerPolicy(),
		Checkpoint:    protocol.CheckpointBlock{Epoch: 2, Height: 20},
		Repositories: []protocol.RepositoryResult{{
			Repository: "rad:large",
			PRs:        []protocol.PRResult{{DiffCID: diffCID}},
		}},
	}, store)
	if err == nil || !strings.Contains(err.Error(), "publishing limit") {
		t.Fatalf("expected an explicit size-limit error, got %v", err)
	}
}
