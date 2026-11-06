package radicle_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
	radicleforge "idena-git-forge/internal/radicle"
)

func TestReviewedRadicleOfflineWorkflow(t *testing.T) {
	binary := os.Getenv("RAD_BIN")
	if binary == "" {
		t.Skip("set RAD_BIN to the reviewed Idena Heartwood CLI to run this integration test")
	}
	ctx := context.Background()
	root := t.TempDir()
	home := filepath.Join(root, "rad-home")
	repository := filepath.Join(root, "source")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(repository, 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"RAD_HOME="+home,
		"RAD_PASSPHRASE=radicle-integration",
		"RAD_KEYGEN_SEED=abababababababababababababababababababababababababababababababab",
		"PATH="+filepath.Dir(binary)+string(os.PathListSeparator)+os.Getenv("PATH"),
	)
	runCommand(t, env, root, binary, "auth", "--alias", "integration")
	runCommand(t, env, repository, "git", "init", "-b", "main")
	runCommand(t, env, repository, "git", "config", "user.name", "Radicle Integration")
	runCommand(t, env, repository, "git", "config", "user.email", "radicle@example.invalid")
	if err := os.WriteFile(filepath.Join(repository, "README.md"), []byte("# Radicle fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runCommand(t, env, repository, "git", "add", "README.md")
	runCommand(t, env, repository, "git", "commit", "-m", "Initial commit")
	initOutput := runCommand(t, env, repository, binary, "init", "--name", "integration", "--description", "offline Radicle fixture", "--default-branch", "main", "--public", "--no-seed", "--no-confirm", "--setup-signing")
	rid := mustMatch(t, `rad:z[1-9A-HJ-NP-Za-km-z]+`, initOutput)

	runCommand(t, env, repository, "git", "checkout", "-b", "feature/integration")
	if err := os.WriteFile(filepath.Join(repository, "change.txt"), []byte("change\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runCommand(t, env, repository, "git", "add", "change.txt")
	runCommand(t, env, repository, "git", "commit", "-m", "Patch change")
	pushOutput := runCommand(t, env, repository, "git", "push", "-o", "patch.message=Radicle integration patch", "rad", "HEAD:refs/patches")
	patchID := mustMatch(t, `[0-9a-f]{40}`, pushOutput)
	runCommand(t, env, repository, binary, "patch", "review", patchID, "--accept", "--no-message", "--no-announce", "--repo", rid)
	runCommand(t, env, repository, binary, "patch", "label", patchID, "--add", "idena/merge-request", "--no-announce", "--repo", rid)
	runCommand(t, env, repository, binary, "issue", "open", "--title", "Radicle issue", "--description", "Stored locally", "--no-announce", "--repo", rid)

	client := radicleforge.Client{
		Binary:               binary,
		Home:                 home,
		Passphrase:           "radicle-integration",
		ExpectedBinarySHA256: binarySHA256ForTest(t, binary),
	}
	entries, err := client.CobLog(ctx, rid, radicleforge.PatchType, patchID)
	if err != nil {
		t.Fatal(err)
	}
	var reviewID, labelID string
	for _, entry := range entries {
		for _, raw := range entry.Actions {
			var action radicleforge.CobAction
			if err := jsonUnmarshal(raw, &action); err != nil {
				t.Fatal(err)
			}
			switch action.Type {
			case "review":
				reviewID = entry.ID
			case "label":
				for _, label := range action.Labels {
					if label == radicleforge.MergeRequestLabel {
						labelID = entry.ID
					}
				}
			}
		}
	}
	if reviewID == "" || labelID == "" {
		t.Fatalf("missing Radicle operations: review=%q label=%q", reviewID, labelID)
	}
	key, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := os.ReadFile(filepath.Join(home, "keys", "radicle.pub"))
	if err != nil {
		t.Fatal(err)
	}
	did, _, err := radicleforge.DIDForKey(string(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := client.ExportBundle(ctx, rid)
	if err != nil {
		t.Fatal(err)
	}
	store, err := content.Open(filepath.Join(root, "content"))
	if err != nil {
		t.Fatal(err)
	}
	bundleCID, err := store.Put(bundle, 10)
	if err != nil {
		t.Fatal(err)
	}
	diffCID, err := content.CIDForBytes([]byte(runCommand(t, env, repository, binary, "patch", "diff", patchID, "--no-announce", "--repo", rid)))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := protocol.NewEnvelope(
		protocol.KindVote,
		rid,
		9,
		protocol.AddressFromPrivateKey(key),
		did,
		string(publicKey),
		"00000000000000000000000000000001",
		protocol.VotePayload{
			Patch: patchID, Revision: patchID, Decision: protocol.DecisionApprove,
			Review: reviewID, ActionOID: reviewID, Bundle: bundleCID, ActorDID: did,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := radicleforge.SignBinding(ctx, filepath.Join(home, "keys", "radicle"), envelope.RadicleBindingMessage())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = binding
	if err := envelope.Sign(key); err != nil {
		t.Fatal(err)
	}
	if err := radicleforge.VerifyBinding(ctx, *envelope); err != nil {
		t.Fatal(err)
	}
	if err := client.VerifySubject(ctx, protocol.RadicleSubject{
		RID: rid, ActorDID: did, Kind: protocol.KindVote, BundleCID: bundleCID,
		CobType: radicleforge.PatchType, CobID: patchID, RevisionID: patchID,
		ReviewID: reviewID, ActionOID: reviewID, Verdict: protocol.DecisionApprove,
	}); err != nil {
		t.Fatal(err)
	}
	_ = diffCID
}

func runCommand(t *testing.T, env []string, directory, name string, arguments ...string) string {
	t.Helper()
	output, err := awaitCommandWithError(context.Background(), env, directory, name, arguments...)
	if err != nil {
		t.Fatal(err)
	}
	return output
}

func awaitCommandWithError(ctx context.Context, env []string, directory, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	command.Env = env
	output, err := command.CombinedOutput()
	if err != nil {
		return "", errors.New(name + " " + strings.Join(arguments, " ") + ": " + err.Error() + ": " + strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func mustMatch(t *testing.T, pattern, value string) string {
	t.Helper()
	match := regexp.MustCompile(pattern).FindString(value)
	if match == "" {
		t.Fatalf("pattern %s not found in %q", pattern, value)
	}
	return match
}

func jsonUnmarshal(data []byte, destination any) error {
	return json.Unmarshal(data, destination)
}
