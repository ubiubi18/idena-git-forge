package gitutil

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleAndFastForward(t *testing.T) {
	repository := t.TempDir()
	run(t, repository, "init", "-b", "main")
	run(t, repository, "config", "user.name", "Test")
	run(t, repository, "config", "user.email", "test@example.com")
	writeFile(t, filepath.Join(repository, "file.txt"), "one\n")
	run(t, repository, "add", "file.txt")
	run(t, repository, "commit", "-m", "one")
	base := strings.TrimSpace(run(t, repository, "rev-parse", "HEAD"))
	writeFile(t, filepath.Join(repository, "file.txt"), "two\n")
	run(t, repository, "commit", "-am", "two")
	head := strings.TrimSpace(run(t, repository, "rev-parse", "HEAD"))

	bundlePath := filepath.Join(t.TempDir(), "pr.bundle")
	if err := CreateBundle(context.Background(), repository, "HEAD", bundlePath); err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBundleAndFastForward(context.Background(), bundle, base, head); err != nil {
		t.Fatal(err)
	}
	if err := ValidateBundleResources(context.Background(), bundle); err != nil {
		t.Fatalf("resource preflight rejected an ordinary bundle: %v", err)
	}
	if err := VerifyBundleAndFastForward(context.Background(), bundle, head, base); err == nil {
		t.Fatal("expected reverse ancestry to fail")
	}
}

func TestBundleResourcePreflightRejectsExpansionBeforeMaterialization(t *testing.T) {
	repository := t.TempDir()
	run(t, repository, "init", "-b", "main")
	run(t, repository, "config", "user.name", "Test")
	run(t, repository, "config", "user.email", "test@example.com")
	writeFile(t, filepath.Join(repository, "large.txt"), strings.Repeat("A", 2<<20))
	run(t, repository, "add", "large.txt")
	run(t, repository, "commit", "-m", "large compressible object")

	bundlePath := filepath.Join(t.TempDir(), "large.bundle")
	if err := CreateBundle(context.Background(), repository, "HEAD", bundlePath); err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultBundleLimits
	limits.maxObjectBytes = 1 << 20
	if err := validateBundleResources(context.Background(), bundle, limits); err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("large expanded object was accepted: %v", err)
	}
}

func TestBundleResourcePreflightRejectsObjectCountAndCanceledContext(t *testing.T) {
	repository := t.TempDir()
	run(t, repository, "init", "-b", "main")
	run(t, repository, "config", "user.name", "Test")
	run(t, repository, "config", "user.email", "test@example.com")
	writeFile(t, filepath.Join(repository, "file.txt"), "content\n")
	run(t, repository, "add", "file.txt")
	run(t, repository, "commit", "-m", "content")
	bundlePath := filepath.Join(t.TempDir(), "objects.bundle")
	if err := CreateBundle(context.Background(), repository, "HEAD", bundlePath); err != nil {
		t.Fatal(err)
	}
	bundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	limits := defaultBundleLimits
	limits.maxObjects = 1
	if err := validateBundleResources(context.Background(), bundle, limits); err == nil || !strings.Contains(err.Error(), "object count") {
		t.Fatalf("object-count limit was not enforced: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ValidateBundleResources(canceled, bundle); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preflight error = %v, want context.Canceled", err)
	}
}

func TestIsolatedGitEnvironmentExcludesSecretsAndGitOverrides(t *testing.T) {
	environment := isolatedGitEnvironment([]string{
		"PATH=/usr/bin",
		"LANG=C",
		"IDENA_API_KEY=node-secret",
		"RAD_PASSPHRASE=signer-secret",
		"GIT_CONFIG_COUNT=1",
		"GIT_SSH_COMMAND=exfiltrate",
	}, "/quarantine")
	values := make(map[string]string)
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}
	for _, name := range []string{"IDENA_API_KEY", "RAD_PASSPHRASE", "GIT_CONFIG_COUNT", "GIT_SSH_COMMAND"} {
		if _, exists := values[name]; exists {
			t.Fatalf("%s leaked into isolated Git environment", name)
		}
	}
	if values["HOME"] != "/quarantine" || values["GIT_CONFIG_GLOBAL"] != "/dev/null" || values["GIT_TERMINAL_PROMPT"] != "0" {
		t.Fatalf("isolated Git controls = %v", values)
	}
}

func run(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, arguments...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", arguments, err, output)
	}
	return string(output)
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
