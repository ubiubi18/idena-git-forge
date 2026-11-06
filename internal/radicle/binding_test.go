package radicle

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

func TestRadicleIdentityBinding(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "radicle")
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", keyPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate key: %v: %s", err, output)
	}
	publicKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	did, _, err := DIDForKey(string(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	dummyCID, _ := content.CIDForBytes([]byte("patch"))
	payload := protocol.PullRequestPayload{
		Patch:    "1111111111111111111111111111111111111111",
		Revision: "2222222222222222222222222222222222222222",
		Title:    "binding",
		Base:     "3333333333333333333333333333333333333333",
		Head:     "4444444444444444444444444444444444444444",
		Bundle:   dummyCID,
		Diff:     dummyCID,
		ActorDID: did,
	}
	envelope, err := protocol.NewEnvelope(
		protocol.KindPullRequest,
		"rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5",
		42,
		"0x1111111111111111111111111111111111111111",
		did,
		string(publicKey),
		"00000000000000000000000000000001",
		payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignBinding(context.Background(), keyPath, envelope.RadicleBindingMessage())
	if err != nil {
		t.Fatal(err)
	}
	envelope.Binding = signature
	if err := VerifyBinding(context.Background(), *envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Binding = "invalid"
	if err := VerifyBinding(context.Background(), *envelope); err == nil {
		t.Fatal("tampered binding signature was accepted")
	}
}

func TestBindingCommandEnvironmentExcludesSecretsAndAskpass(t *testing.T) {
	environment := bindingCommandEnvironment([]string{
		"PATH=/usr/bin",
		"LANG=C",
		"SSH_AUTH_SOCK=/private/agent.sock",
		"IDENA_API_KEY=node-secret",
		"RAD_PASSPHRASE=key-secret",
		"SSH_ASKPASS=exfiltrate",
	})
	values := make(map[string]string)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}
	for _, name := range []string{"IDENA_API_KEY", "RAD_PASSPHRASE", "SSH_ASKPASS"} {
		if _, exists := values[name]; exists {
			t.Fatalf("%s leaked into ssh-keygen environment", name)
		}
	}
	if values["PATH"] != "/usr/bin" || values["LANG"] != "C" || values["SSH_AUTH_SOCK"] != "/private/agent.sock" {
		t.Fatalf("non-secret runtime environment was not preserved: %v", values)
	}
}

func TestBindingSigningKeyPathUsesPublicKeyWithAgent(t *testing.T) {
	directory := t.TempDir()
	privateKeyPath := filepath.Join(directory, "radicle")
	publicKeyPath := privateKeyPath + ".pub"
	if err := os.WriteFile(publicKeyPath, []byte("test public key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := bindingSigningKeyPath(privateKeyPath, []string{"SSH_AUTH_SOCK=/private/agent.sock"})
	if err != nil {
		t.Fatal(err)
	}
	if got != publicKeyPath {
		t.Fatalf("agent signing key path = %q, want %q", got, publicKeyPath)
	}
}

func TestBindingSigningKeyPathFailsClosedWithoutPublicKey(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "radicle")
	if _, err := bindingSigningKeyPath(privateKeyPath, []string{"SSH_AUTH_SOCK=/private/agent.sock"}); err == nil {
		t.Fatal("agent signing accepted a missing public-key file")
	}
}

func TestBindingSigningKeyPathUsesPrivateKeyWithoutAgent(t *testing.T) {
	privateKeyPath := filepath.Join(t.TempDir(), "radicle")
	got, err := bindingSigningKeyPath(privateKeyPath, []string{"SSH_AUTH_SOCK="})
	if err != nil {
		t.Fatal(err)
	}
	if got != privateKeyPath {
		t.Fatalf("direct signing key path = %q, want %q", got, privateKeyPath)
	}
}

func TestContentVerifierReportsMissingRadicleBundle(t *testing.T) {
	store, err := content.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	verifier := ContentVerifier{Client: VerificationClient{}, Store: store}
	err = verifier.Verify(context.Background(), protocol.RadicleSubject{
		RID: "rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", BundleCID: "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
	})
	if !errors.Is(err, protocol.ErrContentUnavailable) {
		t.Fatalf("missing content error = %v", err)
	}
}
