package radicle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/multiformats/go-multibase"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

const testRepositoryInitializer = "did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP"

const testOfflineRID = "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"

func TestReviewEditMustTraceToExactRevision(t *testing.T) {
	const actor = "z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP"
	reviewID := strings.Repeat("a", 40)
	editID := strings.Repeat("b", 40)
	revisionA := strings.Repeat("c", 40)
	revisionB := strings.Repeat("d", 40)
	entries := []CobEntry{
		cobEntry(t, reviewID, actor, CobAction{
			Type: "review", Revision: revisionA, Verdict: "accept",
		}),
		cobEntry(t, editID, actor, CobAction{
			Type: "review.edit.v2", Review: reviewID, Verdict: "reject",
		}),
	}

	subject := protocol.RadicleSubject{
		ActorDID:   "did:key:" + actor,
		Kind:       protocol.KindVote,
		RevisionID: revisionA,
		ReviewID:   reviewID,
		ActionOID:  editID,
		Verdict:    protocol.DecisionReject,
	}
	if err := verifyCobSubject(entries, subject); err != nil {
		t.Fatalf("review edit for its original revision was rejected: %v", err)
	}

	subject.RevisionID = revisionB
	if err := verifyCobSubject(entries, subject); err == nil {
		t.Fatal("review edit was accepted for a different revision")
	}
}

func TestRadicleCommandAllowlist(t *testing.T) {
	object := strings.Repeat("a", 40)
	revision := strings.Repeat("b", 40)
	valid := [][]string{
		{"cob", "log", "--repo", testOfflineRID, "--type", PatchType, "--object", object, "--format", "json"},
		{"cob", "show", "--repo", testOfflineRID, "--type", IssueType, "--object", object, "--format", "json"},
		{"patch", "diff", object, "--repo", testOfflineRID, "--no-announce"},
		{"patch", "diff", object, "--repo", testOfflineRID, "--no-announce", "--revision", revision},
		{"patch", "label", object, "--add", MergeRequestLabel, "--no-announce", "--repo", testOfflineRID},
	}
	for _, arguments := range valid {
		if err := validateOfflineRadicleCommand(arguments); err != nil {
			t.Fatalf("offline command %q was rejected: %v", arguments, err)
		}
	}

	invalid := [][]string{
		nil,
		{"clone"},
		{"fetch"},
		{"node", "start"},
		{"replicate"},
		{"cob", "update"},
		{"cob", "show", "--repo", testOfflineRID},
		{"cob", "show", "--repo", "--help", "--type", PatchType, "--object", object, "--format", "json"},
		{"cob", "show", "--repo", testOfflineRID, "--type", "xyz.radicle.unknown", "--object", object, "--format", "json"},
		{"cob", "show", "--repo", testOfflineRID, "--type", PatchType, "--object", "--help", "--format", "json"},
		{"patch", "review", object, "--accept"},
		{"patch", "diff", object, "--repo", testOfflineRID},
		{"patch", "diff", object, "--repo", testOfflineRID, "--announce"},
		{"patch", "diff", "--help", "--repo", testOfflineRID, "--no-announce"},
		{"patch", "diff", object, "--repo", testOfflineRID, "--no-announce", "--revision", "--help"},
		{"patch", "label", object, "--add", MergeRequestLabel, "--repo", testOfflineRID},
		{"patch", "label", object, "--add", "other", "--no-announce", "--repo", testOfflineRID},
	}
	for _, arguments := range invalid {
		if err := validateOfflineRadicleCommand(arguments); err == nil {
			t.Fatalf("command outside the offline allowlist was accepted: %q", arguments)
		}
	}
}

func TestRadicleRunRequiresPinnedSupportedBinaryAndNoNodeSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX shell script")
	}
	home := t.TempDir()
	binary, digest := writeFakeRadicleBinary(t, "244a8b6-dirty")
	arguments := []string{"cob", "show", "--repo", testOfflineRID, "--type", PatchType, "--object", strings.Repeat("a", 40), "--format", "json"}

	client := Client{
		Binary:               binary,
		Home:                 home,
		ExpectedBinarySHA256: digest,
	}
	output, err := client.run(context.Background(), arguments...)
	if err != nil {
		t.Fatalf("pinned supported binary was rejected: %v", err)
	}
	if strings.TrimSpace(string(output)) != `{"fixture":true}` {
		t.Fatalf("unexpected fixture output: %q", output)
	}

	withoutDigest := client
	withoutDigest.ExpectedBinarySHA256 = ""
	t.Setenv("RAD_BIN_SHA256", "")
	if _, err := withoutDigest.run(context.Background(), arguments...); err == nil ||
		!strings.Contains(err.Error(), "RAD_BIN_SHA256") {
		t.Fatalf("unpinned binary was not rejected with a useful error: %v", err)
	}

	wrongDigest := client
	wrongDigest.ExpectedBinarySHA256 = strings.Repeat("0", 64)
	if _, err := wrongDigest.run(context.Background(), arguments...); err == nil ||
		!strings.Contains(err.Error(), "digest") {
		t.Fatalf("binary digest mismatch was not rejected: %v", err)
	}

	unsupportedBinary, unsupportedDigest := writeFakeRadicleBinary(t, "2.0.0")
	unsupported := client
	unsupported.Binary = unsupportedBinary
	unsupported.ExpectedBinarySHA256 = unsupportedDigest
	if _, err := unsupported.run(context.Background(), arguments...); err == nil ||
		!strings.Contains(err.Error(), "unsupported Radicle build") {
		t.Fatalf("unreviewed Radicle 2.x build was not rejected: %v", err)
	}

	stockBinary, stockDigest := writeFakeRadicleBinary(t, "1.10.3")
	stock := client
	stock.Binary = stockBinary
	stock.ExpectedBinarySHA256 = stockDigest
	if _, err := stock.run(context.Background(), arguments...); err == nil ||
		!strings.Contains(err.Error(), "stock delegate-bearing") {
		t.Fatalf("stock delegate-bearing Radicle build was not rejected: %v", err)
	}

	nodeDirectory := filepath.Join(home, "node")
	if err := os.MkdirAll(nodeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeDirectory, "network-disabled.sock"), []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.run(context.Background(), arguments...); err == nil ||
		!strings.Contains(err.Error(), "network-disabled.sock") {
		t.Fatalf("occupied disabled socket path was not rejected: %v", err)
	}
	if err := os.Remove(filepath.Join(nodeDirectory, "network-disabled.sock")); err != nil {
		t.Fatal(err)
	}
	shortHome, err := os.MkdirTemp("/tmp", "rad-home-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(shortHome)
	client.Home = shortHome
	nodeDirectory = filepath.Join(shortHome, "node")
	if err := os.MkdirAll(nodeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(nodeDirectory, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := client.run(context.Background(), arguments...); err == nil ||
		!strings.Contains(err.Error(), "active Radicle node socket") {
		t.Fatalf("active Radicle node socket was not rejected: %v", err)
	}
}

func TestRadicleCommandEnvironmentCannotReachNode(t *testing.T) {
	home := t.TempDir()
	environment := radicleCommandEnvironment([]string{
		"PATH=/usr/bin",
		"IDENA_API_KEY=node-secret",
		"RADICLE_PRIVATE_KEY=private-key-material",
		"RAD_HOME=/ambient/home",
		"RAD_SOCKET=/ambient/control.sock",
		"RAD_PASSPHRASE=ambient-secret",
		"RAD_BIN_SHA256=ambient-policy",
	}, home, "isolated-secret")

	values := make(map[string][]string)
	for _, entry := range environment {
		key, value, found := strings.Cut(entry, "=")
		if found {
			values[key] = append(values[key], value)
		}
	}

	if got := values["RAD_HOME"]; len(got) != 1 || got[0] != home {
		t.Fatalf("RAD_HOME = %v, want exactly [%s]", got, home)
	}
	wantSocket := filepath.Join(home, "node", "network-disabled.sock")
	if got := values["RAD_SOCKET"]; len(got) != 1 || got[0] != wantSocket {
		t.Fatalf("RAD_SOCKET = %v, want exactly [%s]", got, wantSocket)
	}
	if got := values["RAD_PASSPHRASE"]; len(got) != 1 || got[0] != "isolated-secret" {
		t.Fatalf("RAD_PASSPHRASE was not isolated")
	}
	if got := values["RAD_BIN_SHA256"]; len(got) != 0 {
		t.Fatalf("RAD_BIN_SHA256 leaked into the Radicle subprocess: %v", got)
	}
	for _, name := range []string{"IDENA_API_KEY", "RADICLE_PRIVATE_KEY"} {
		if got := values[name]; len(got) != 0 {
			t.Fatalf("%s leaked into the Radicle subprocess: %v", name, got)
		}
	}

	verificationEnvironment := radicleCommandEnvironment([]string{
		"PATH=/usr/bin",
		"RAD_PASSPHRASE=ambient-secret",
	}, home, "")
	for _, entry := range verificationEnvironment {
		if strings.HasPrefix(entry, "RAD_PASSPHRASE=") {
			t.Fatalf("read-only verification inherited a Radicle passphrase: %q", entry)
		}
	}
}

func TestPublicVerificationProfileNeverCopiesPrivateKey(t *testing.T) {
	source := t.TempDir()
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(source, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		filepath.Join(source, "config.json"):         []byte("{}\n"),
		filepath.Join(source, "keys", "radicle.pub"): []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6Ul/D+P0I/Hl1JVOWGS8Z589us9FqKQXWv8OMOpKCh verifier\n"),
		filepath.Join(source, "keys", "radicle"):     []byte("private-key-must-not-be-read-or-copied\n"),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	client := VerificationClient{Home: source}
	if err := client.ValidateProfile(); err != nil {
		t.Fatalf("public-only verification profile was rejected: %v", err)
	}
	if err := copyPublicVerificationProfile(source, target); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "keys", "radicle")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private Radicle key appeared in verification quarantine: %v", err)
	}
	if _, err := os.Stat(filepath.Join(target, "keys", "radicle.pub")); err != nil {
		t.Fatalf("public Radicle key was not copied: %v", err)
	}
}

func writeFakeRadicleBinary(t *testing.T, version string) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rad")
	script := fmt.Sprintf(`#!/bin/sh
if [ "$1" = "--version" ]; then
  printf 'rad %s (fixture)\n'
  exit 0
fi
printf '{"fixture":true}\n'
`, version)
	data := []byte(script)
	if err := os.WriteFile(path, data, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return path, hex.EncodeToString(digest[:])
}

func cobEntry(t *testing.T, id, author string, actions ...CobAction) CobEntry {
	t.Helper()
	entry := CobEntry{ID: id, Author: author}
	for _, action := range actions {
		encoded, err := json.Marshal(action)
		if err != nil {
			t.Fatal(err)
		}
		entry.Actions = append(entry.Actions, encoded)
	}
	return entry
}

func TestRepositoryIdentityMustMatchStorageRID(t *testing.T) {
	home := t.TempDir()
	actualID := initializeIdentityRepository(t, filepath.Join(home, "source.git"))
	actualRID := repositoryIDForOID(t, actualID)
	actualPath := filepath.Join(home, "storage", strings.TrimPrefix(actualRID, "rad:"))
	if err := os.MkdirAll(filepath.Dir(actualPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cp", "-R", filepath.Join(home, "source.git"), actualPath).CombinedOutput(); err != nil {
		t.Fatalf("copy identity repository: %v: %s", err, output)
	}

	client := Client{Home: home}
	if err := client.ValidateRepositoryIdentity(context.Background(), actualRID); err != nil {
		t.Fatalf("valid Radicle repository identity was rejected: %v", err)
	}

	wrongBytes := make([]byte, 20)
	wrongBytes[19] = 1
	wrongEncoded, err := multibase.Encode(multibase.Base58BTC, wrongBytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongRID := "rad:" + wrongEncoded
	wrongPath := filepath.Join(home, "storage", strings.TrimPrefix(wrongRID, "rad:"))
	if output, err := exec.Command("cp", "-R", filepath.Join(home, "source.git"), wrongPath).CombinedOutput(); err != nil {
		t.Fatalf("copy mismatched repository: %v: %s", err, output)
	}
	if err := client.ValidateRepositoryIdentity(context.Background(), wrongRID); err == nil {
		t.Fatal("repository copied under a different RID was accepted")
	}
}

func TestImportBundleValidatesRIDBeforeInstalling(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.git")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actorDID := didForEd25519(t, publicKey)
	identityOID := initializeIdentityRepositoryFor(t, source, actorDID)
	actualRID := repositoryIDForOID(t, identityOID)
	identityCommit := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "refs/rad/id^{commit}"))
	installSignedActorNamespace(t, source, actorDID, privateKey, identityCommit)
	bundlePath := filepath.Join(root, "storage.bundle")
	if output, err := exec.Command("git", "-C", source, "bundle", "create", bundlePath, "--all").CombinedOutput(); err != nil {
		t.Fatalf("create bundle: %v: %s", err, output)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}

	wrongBytes := make([]byte, 20)
	wrongBytes[19] = 2
	wrongEncoded, err := multibase.Encode(multibase.Base58BTC, wrongBytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongRID := "rad:" + wrongEncoded
	client := Client{Home: filepath.Join(root, "rad-home")}
	if err := client.ImportBundle(context.Background(), wrongRID, actorDID, bundle); err == nil {
		t.Fatal("bundle with a mismatched repository identity was installed")
	}
	wrongPath := filepath.Join(client.Home, "storage", strings.TrimPrefix(wrongRID, "rad:"))
	if _, err := os.Stat(wrongPath); !os.IsNotExist(err) {
		t.Fatalf("mismatched bundle created target storage %s", wrongPath)
	}

	if err := client.ImportBundle(context.Background(), actualRID, actorDID, bundle); err != nil {
		t.Fatalf("valid bundle was rejected: %v", err)
	}
	if err := client.ValidateRepositoryIdentity(context.Background(), actualRID); err != nil {
		t.Fatalf("installed Radicle identity is invalid: %v", err)
	}
}

func TestContentVerifierUsesOnlyReferencedBundle(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.git")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actorDID := didForEd25519(t, publicKey)
	identityOID := initializeIdentityRepositoryFor(t, source, actorDID)
	rid := repositoryIDForOID(t, identityOID)
	identityCommit := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "refs/rad/id^{commit}"))
	installSignedActorNamespace(t, source, actorDID, privateKey, identityCommit)
	bundle := createAllRefsBundle(t, source, filepath.Join(root, "storage.bundle"))
	store, err := content.Open(filepath.Join(root, "content"))
	if err != nil {
		t.Fatal(err)
	}
	bundleCID, err := store.Put(bundle, 2)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "empty-live-home")
	if err := os.MkdirAll(filepath.Join(home, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{
		filepath.Join(home, "config.json"):         []byte("{}\n"),
		filepath.Join(home, "keys", "radicle.pub"): []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6Ul/D+P0I/Hl1JVOWGS8Z589us9FqKQXWv8OMOpKCh verifier\n"),
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verifier := ContentVerifier{Client: VerificationClient{Home: home}, Store: store}
	if err := verifier.Verify(context.Background(), protocol.RadicleSubject{
		RID:       rid,
		ActorDID:  actorDID,
		Kind:      protocol.KindRepository,
		BundleCID: bundleCID,
		Head:      identityCommit,
	}); err != nil {
		t.Fatalf("valid exact bundle required pre-existing live storage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "storage", strings.TrimPrefix(rid, "rad:"))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bundle verification mutated live Radicle storage: %v", err)
	}
}

func TestImportBundleCannotInstallIdenaAuthorityRefs(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.git")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actorDID := didForEd25519(t, publicKey)
	identityOID := initializeIdentityRepositoryFor(t, source, actorDID)
	rid := repositoryIDForOID(t, identityOID)
	legitimateHead := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "refs/rad/id^{commit}"))
	installSignedActorNamespace(t, source, actorDID, privateKey, legitimateHead)
	if err := os.WriteFile(filepath.Join(source, "untrusted.txt"), []byte("untrusted bundle head\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitOutput(t, source, "add", "untrusted.txt")
	runGitOutput(t, source, "commit", "-m", "untrusted authority target")
	maliciousHead := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "HEAD"))
	for _, refname := range []string{
		"refs/idena/genesis/canonical",
		"refs/idena/epoch/1/canonical",
	} {
		if output, err := exec.Command("git", "-C", source, "update-ref", refname, maliciousHead).CombinedOutput(); err != nil {
			t.Fatalf("create malicious authority ref %s: %v: %s", refname, err, output)
		}
	}
	bundlePath := filepath.Join(root, "storage.bundle")
	if output, err := exec.Command("git", "-C", source, "bundle", "create", bundlePath, "--all").CombinedOutput(); err != nil {
		t.Fatalf("create bundle: %v: %s", err, output)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	client := Client{Home: filepath.Join(root, "rad-home")}
	if err := client.ImportBundle(context.Background(), rid, actorDID, bundle); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(client.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	for _, refname := range []string{
		"refs/idena/genesis/canonical",
		"refs/idena/epoch/1/canonical",
	} {
		if output, err := exec.Command("git", "-C", target, "rev-parse", "--verify", refname).CombinedOutput(); err == nil {
			t.Fatalf("bundle installed protected authority ref %s: %s", refname, output)
		}
	}
	if err := client.WriteGenesisHead(context.Background(), rid, legitimateHead); err != nil {
		t.Fatal(err)
	}
	if err := client.WriteGovernanceHead(context.Background(), rid, 1, legitimateHead); err != nil {
		t.Fatal(err)
	}
	if err := client.ImportBundle(context.Background(), rid, actorDID, bundle); err != nil {
		t.Fatal(err)
	}
	for _, refname := range []string{
		"refs/idena/genesis/canonical",
		"refs/idena/epoch/1/canonical",
	} {
		got := strings.TrimSpace(runGitOutput(t, target, "rev-parse", refname))
		if got != legitimateHead {
			t.Fatalf("authenticated authority ref %s changed to %s; malicious bundle requested %s", refname, got, maliciousHead)
		}
	}
}

func TestImportBundleInstallsOnlyActionBoundActor(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.git")
	initializerPublic, initializerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initializerDID := didForEd25519(t, initializerPublic)
	otherDID := didForEd25519(t, otherPublic)
	identityOID := initializeIdentityRepositoryFor(t, source, initializerDID)
	rid := repositoryIDForOID(t, identityOID)
	identityCommit := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "refs/rad/id^{commit}"))
	installSignedActorNamespace(t, source, initializerDID, initializerPrivate, identityCommit)
	installSignedActorNamespace(t, source, otherDID, otherPrivate, identityCommit)
	bundle := createAllRefsBundle(t, source, filepath.Join(root, "storage.bundle"))

	attackerClient := Client{Home: filepath.Join(root, "attacker-home")}
	if err := attackerClient.ImportBundle(context.Background(), rid, otherDID, bundle); err == nil {
		t.Fatal("non-initializer actor installed new repository storage")
	}
	attackerTarget := filepath.Join(attackerClient.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	if _, err := os.Stat(attackerTarget); !os.IsNotExist(err) {
		t.Fatalf("failed non-initializer import left repository storage at %s", attackerTarget)
	}

	client := Client{Home: filepath.Join(root, "rad-home")}
	if err := client.ImportBundle(context.Background(), rid, initializerDID, bundle); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(client.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	initializerSigrefs := "refs/namespaces/" + strings.TrimPrefix(initializerDID, "did:key:") + "/refs/rad/sigrefs"
	if output, err := exec.Command("git", "-C", target, "rev-parse", "--verify", initializerSigrefs).CombinedOutput(); err != nil {
		t.Fatalf("authorized namespace was not imported: %v: %s", err, output)
	}
	otherSigrefs := "refs/namespaces/" + strings.TrimPrefix(otherDID, "did:key:") + "/refs/rad/sigrefs"
	if output, err := exec.Command("git", "-C", target, "rev-parse", "--verify", otherSigrefs).CombinedOutput(); err == nil {
		t.Fatalf("unrelated actor namespace was imported: %s", output)
	}
}

func TestImportBundleRejectsSignedRefsRollback(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.git")
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actorDID := didForEd25519(t, publicKey)
	identityOID := initializeIdentityRepositoryFor(t, source, actorDID)
	rid := repositoryIDForOID(t, identityOID)
	identityCommit := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "refs/rad/id^{commit}"))
	installSignedActorNamespace(t, source, actorDID, privateKey, identityCommit)
	oldBundle := createAllRefsBundle(t, source, filepath.Join(root, "old.bundle"))

	if err := os.WriteFile(filepath.Join(source, "new.txt"), []byte("new actor state\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitOutput(t, source, "add", "new.txt")
	runGitOutput(t, source, "commit", "-m", "new actor state")
	newHead := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "HEAD"))
	newSigrefs := installParentBoundActorNamespace(t, source, actorDID, privateKey, identityCommit, newHead)
	newBundle := createAllRefsBundle(t, source, filepath.Join(root, "new.bundle"))

	client := Client{Home: filepath.Join(root, "rad-home")}
	if err := client.ImportBundle(context.Background(), rid, actorDID, oldBundle); err != nil {
		t.Fatalf("initial actor state: %v", err)
	}
	if err := client.ImportBundle(context.Background(), rid, actorDID, newBundle); err != nil {
		t.Fatalf("advancing actor state: %v", err)
	}
	if err := client.ImportBundle(context.Background(), rid, actorDID, oldBundle); err == nil {
		t.Fatal("older signed actor state was replayed")
	}
	target := filepath.Join(client.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	sigref := "refs/namespaces/" + strings.TrimPrefix(actorDID, "did:key:") + "/refs/rad/sigrefs"
	got := strings.TrimSpace(runGitOutput(t, target, "rev-parse", sigref))
	if got != newSigrefs {
		t.Fatalf("rollback attempt changed live sigrefs to %s, want %s", got, newSigrefs)
	}
}

func TestSignedRefsVerificationRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := multibase.Encode(multibase.Base58BTC, append([]byte{0xed, 0x01}, publicKey...))
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte(strings.Repeat("a", 40) + " refs/rad/root\n")
	signature := ed25519.Sign(privateKey, canonical)
	if err := verifySignedRefs("did:key:"+encoded, canonical, signature); err != nil {
		t.Fatal(err)
	}
	canonical[0] = 'b'
	if err := verifySignedRefs("did:key:"+encoded, canonical, signature); err == nil {
		t.Fatal("tampered signed refs were accepted")
	}
}

func TestVerifiedNamespaceRefspecsRejectsSignedIdenaRef(t *testing.T) {
	root := t.TempDir()
	repository := filepath.Join(root, "source.git")
	identityOID := initializeIdentityRepository(t, repository)
	rid := repositoryIDForOID(t, identityOID)
	identityCommit := strings.TrimSpace(runGitOutput(t, repository, "rev-parse", "refs/rad/id^{commit}"))

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := multibase.Encode(multibase.Base58BTC, append([]byte{0xed, 0x01}, publicKey...))
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte(
		identityCommit + " refs/rad/root\n" +
			identityCommit + " refs/idena/epoch/1/canonical\n",
	)
	if err := os.WriteFile(filepath.Join(repository, "refs"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "signature"), ed25519.Sign(privateKey, manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitOutput(t, repository, "add", "refs", "signature")
	runGitOutput(t, repository, "commit", "-m", "malicious signed refs")
	signedRefsCommit := strings.TrimSpace(runGitOutput(t, repository, "rev-parse", "HEAD"))

	namespace := "refs/namespaces/" + actor + "/"
	for refname, oid := range map[string]string{
		namespace + "refs/rad/root":                identityCommit,
		namespace + "refs/rad/sigrefs":             signedRefsCommit,
		namespace + "refs/idena/epoch/1/canonical": identityCommit,
	} {
		runGitOutput(t, repository, "update-ref", refname, oid)
	}

	if _, _, _, err := verifiedActorRefspecs(context.Background(), repository, rid, actor); err == nil || !strings.Contains(err.Error(), "reserved Idena ref") {
		t.Fatalf("signed protected ref was not rejected: %v", err)
	}
}

func TestRepositoryActionRequiresImmutableInitializer(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.git")
	initializerPublic, initializerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPublic, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	initializerDID := didForEd25519(t, initializerPublic)
	attackerDID := didForEd25519(t, attackerPublic)
	identityOID := initializeIdentityRepositoryFor(t, source, initializerDID)
	rid := repositoryIDForOID(t, identityOID)
	identityCommit := strings.TrimSpace(runGitOutput(t, source, "rev-parse", "refs/rad/id^{commit}"))
	installSignedActorNamespace(t, source, initializerDID, initializerPrivate, identityCommit)
	installSignedActorNamespace(t, source, attackerDID, attackerPrivate, identityCommit)

	home := filepath.Join(root, "rad-home")
	target := filepath.Join(home, "storage", strings.TrimPrefix(rid, "rad:"))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cp", "-R", source, target).CombinedOutput(); err != nil {
		t.Fatalf("copy repository: %v: %s", err, output)
	}
	client := Client{Home: home}

	legitimate := protocol.RadicleSubject{
		RID:      rid,
		ActorDID: initializerDID,
		Kind:     protocol.KindRepository,
		Head:     identityCommit,
	}
	if err := client.VerifySubject(context.Background(), legitimate); err != nil {
		t.Fatalf("initializer-owned repository action was rejected: %v", err)
	}

	capture := legitimate
	capture.ActorDID = attackerDID
	if err := client.VerifySubject(context.Background(), capture); err == nil ||
		!strings.Contains(err.Error(), "immutable identity initializer") {
		t.Fatalf("foreign signed namespace captured repository initialization: %v", err)
	}
}

func TestRepositoryIdentityRequiresInitializerFormat(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, "source.git")
	identityOID := initializeIdentityRepositoryDocument(t, source, []byte(`{"version":2,"payload":{"xyz.radicle.project":{}}}`))
	rid := repositoryIDForOID(t, identityOID)
	target := filepath.Join(home, "storage", strings.TrimPrefix(rid, "rad:"))
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cp", "-R", source, target).CombinedOutput(); err != nil {
		t.Fatalf("copy repository: %v: %s", err, output)
	}
	if err := (Client{Home: home}).ValidateRepositoryIdentity(context.Background(), rid); err == nil ||
		!strings.Contains(err.Error(), "require 3") {
		t.Fatalf("pre-initializer identity format was accepted: %v", err)
	}
}

func TestRepositoryIdentityRejectsDelegateAuthorityAndDuplicateInitializer(t *testing.T) {
	for name, document := range map[string][]byte{
		"delegate fields":       []byte(`{"version":3,"initializer":"` + testRepositoryInitializer + `","payload":{"xyz.radicle.project":{}},"delegates":["` + testRepositoryInitializer + `"],"threshold":1}`),
		"duplicate initializer": []byte(`{"version":3,"initializer":"` + testRepositoryInitializer + `","initializer":"` + testRepositoryInitializer + `","payload":{"xyz.radicle.project":{}}}`),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			source := filepath.Join(root, "source.git")
			identityOID := initializeIdentityRepositoryDocument(t, source, document)
			rid := repositoryIDForOID(t, identityOID)
			target := filepath.Join(root, "storage", strings.TrimPrefix(rid, "rad:"))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command("cp", "-R", source, target).CombinedOutput(); err != nil {
				t.Fatalf("copy repository: %v: %s", err, output)
			}
			if err := (Client{Home: root}).ValidateRepositoryIdentity(context.Background(), rid); err == nil {
				t.Fatal("ambiguous or delegate-bearing identity document was accepted")
			}
		})
	}
}

func runGitOutput(t *testing.T, repository string, arguments ...string) string {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", repository}, arguments...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", arguments, err, output)
	}
	return string(output)
}

func initializeIdentityRepository(t *testing.T, path string) string {
	return initializeIdentityRepositoryFor(t, path, testRepositoryInitializer)
}

func initializeIdentityRepositoryFor(t *testing.T, path, initializer string) string {
	t.Helper()
	document, err := json.Marshal(map[string]any{
		"version":     repositoryIdentityVersion,
		"initializer": initializer,
		"payload": map[string]any{
			"xyz.radicle.project": map[string]any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return initializeIdentityRepositoryDocument(t, path, document)
}

func initializeIdentityRepositoryDocument(t *testing.T, path string, document []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "embeds"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "embeds", "radicle.json"), document, 0o644); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"init", "-b", "main", path},
		{"-C", path, "config", "user.name", "Identity Test"},
		{"-C", path, "config", "user.email", "identity@example.invalid"},
		{"-C", path, "add", "embeds/radicle.json"},
		{"-C", path, "commit", "-m", "identity"},
	}
	for _, arguments := range commands {
		if output, err := exec.Command("git", arguments...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", arguments, err, output)
		}
	}
	output, err := exec.Command("git", "-C", path, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	commitOID := strings.TrimSpace(string(output))
	output, err = exec.Command("git", "-C", path, "rev-parse", "HEAD:embeds/radicle.json").Output()
	if err != nil {
		t.Fatal(err)
	}
	identityOID := strings.TrimSpace(string(output))
	if output, err := exec.Command("git", "-C", path, "update-ref", "refs/rad/id", commitOID).CombinedOutput(); err != nil {
		t.Fatalf("set Radicle identity ref: %v: %s", err, output)
	}
	return identityOID
}

func didForEd25519(t *testing.T, publicKey ed25519.PublicKey) string {
	t.Helper()
	encoded, err := multibase.Encode(multibase.Base58BTC, append([]byte{0xed, 0x01}, publicKey...))
	if err != nil {
		t.Fatal(err)
	}
	return "did:key:" + encoded
}

func installSignedActorNamespace(
	t *testing.T,
	repository, did string,
	privateKey ed25519.PrivateKey,
	identityCommit string,
) {
	t.Helper()
	actor := strings.TrimPrefix(did, "did:key:")
	manifest := []byte(
		identityCommit + " refs/heads/main\n" +
			identityCommit + " refs/rad/id\n" +
			identityCommit + " refs/rad/root\n",
	)
	if err := os.WriteFile(filepath.Join(repository, "refs"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "signature"), ed25519.Sign(privateKey, manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitOutput(t, repository, "add", "refs", "signature")
	runGitOutput(t, repository, "commit", "-m", "signed refs for "+actor)
	signedRefsCommit := strings.TrimSpace(runGitOutput(t, repository, "rev-parse", "HEAD"))
	namespace := "refs/namespaces/" + actor + "/"
	for refname, oid := range map[string]string{
		namespace + "refs/heads/main":  identityCommit,
		namespace + "refs/rad/id":      identityCommit,
		namespace + "refs/rad/root":    identityCommit,
		namespace + "refs/rad/sigrefs": signedRefsCommit,
	} {
		runGitOutput(t, repository, "update-ref", refname, oid)
	}
}

func installParentBoundActorNamespace(
	t *testing.T,
	repository, did string,
	privateKey ed25519.PrivateKey,
	identityCommit, head string,
) string {
	t.Helper()
	actor := strings.TrimPrefix(did, "did:key:")
	parent := strings.TrimSpace(runGitOutput(t, repository, "rev-parse", "HEAD"))
	manifest := []byte(
		head + " refs/heads/main\n" +
			identityCommit + " refs/rad/id\n" +
			identityCommit + " refs/rad/root\n" +
			parent + " refs/rad/sigrefs-parent\n",
	)
	if err := os.WriteFile(filepath.Join(repository, "refs"), manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "signature"), ed25519.Sign(privateKey, manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	runGitOutput(t, repository, "add", "refs", "signature")
	runGitOutput(t, repository, "commit", "-m", "parent-bound signed refs for "+actor)
	signedRefsCommit := strings.TrimSpace(runGitOutput(t, repository, "rev-parse", "HEAD"))
	namespace := "refs/namespaces/" + actor + "/"
	for refname, oid := range map[string]string{
		namespace + "refs/heads/main":  head,
		namespace + "refs/rad/id":      identityCommit,
		namespace + "refs/rad/root":    identityCommit,
		namespace + "refs/rad/sigrefs": signedRefsCommit,
	} {
		runGitOutput(t, repository, "update-ref", refname, oid)
	}
	return signedRefsCommit
}

func createAllRefsBundle(t *testing.T, repository, path string) []byte {
	t.Helper()
	if output, err := exec.Command("git", "-C", repository, "bundle", "create", path, "--all").CombinedOutput(); err != nil {
		t.Fatalf("create bundle: %v: %s", err, output)
	}
	bundle, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func repositoryIDForOID(t *testing.T, oid string) string {
	t.Helper()
	bytes, err := hex.DecodeString(oid)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := multibase.Encode(multibase.Base58BTC, bytes)
	if err != nil {
		t.Fatal(err)
	}
	return "rad:" + encoded
}
