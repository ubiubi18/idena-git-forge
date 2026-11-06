package gitutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func CreateBundle(ctx context.Context, repository, revision, output string) error {
	if err := runGit(ctx, repository, "bundle", "create", output, revision); err != nil {
		return fmt.Errorf("create git bundle: %w", err)
	}
	return nil
}

func CreateDiff(ctx context.Context, repository, base, head string) ([]byte, error) {
	output, err := Output(ctx, repository, "diff", "--no-color", "--full-index", base, head, "--")
	if err != nil {
		return nil, fmt.Errorf("git diff: %w", err)
	}
	return output, nil
}

func VerifyBundleAndFastForward(ctx context.Context, bundle []byte, base, head string) error {
	if !validObjectID(base) || !validObjectID(head) {
		return errors.New("base and head must be Git object IDs")
	}
	verificationContext, cancel := context.WithTimeout(ctx, BundleVerificationTimeout)
	defer cancel()
	if err := ValidateBundleResources(verificationContext, bundle); err != nil {
		return fmt.Errorf("preflight git bundle: %w", err)
	}
	tempDirectory, err := os.MkdirTemp("", "idena-forge-git-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDirectory)
	bundlePath := filepath.Join(tempDirectory, "pr.bundle")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}
	repository := filepath.Join(tempDirectory, "repo.git")
	if err := runGit(verificationContext, tempDirectory, "init", "--bare", repository); err != nil {
		return fmt.Errorf("init temporary git repository: %w", err)
	}
	if err := runGit(verificationContext, repository, "bundle", "verify", bundlePath); err != nil {
		return fmt.Errorf("verify git bundle: %w", err)
	}
	if err := runGit(verificationContext, repository, "fetch", "--no-tags", bundlePath, "*:refs/forge/pr/*"); err != nil {
		return fmt.Errorf("fetch git bundle: %w", err)
	}
	for _, object := range []string{base, head} {
		if err := runGit(verificationContext, repository, "cat-file", "-e", object+"^{commit}"); err != nil {
			return fmt.Errorf("required commit %s is absent from bundle: %w", object, err)
		}
	}
	if err := runGit(verificationContext, repository, "merge-base", "--is-ancestor", base, head); err != nil {
		return errors.New("PR head is not a fast-forward of its recorded base")
	}
	return nil
}

func runGit(ctx context.Context, directory string, arguments ...string) error {
	return Run(ctx, directory, arguments...)
}

func gitOutput(ctx context.Context, directory string, arguments ...string) (string, error) {
	output, err := Output(ctx, directory, arguments...)
	return string(output), err
}

// Run executes Git with an isolated environment and conservative resource
// settings. It intentionally does not inherit credential, signing, SSH, proxy,
// or Git configuration variables from the forge process.
func Run(ctx context.Context, directory string, arguments ...string) error {
	_, err := Output(ctx, directory, arguments...)
	return err
}

// Output is Run's output-returning counterpart.
func Output(ctx context.Context, directory string, arguments ...string) ([]byte, error) {
	gitArguments := isolatedGitArguments(directory, arguments)
	command := exec.CommandContext(ctx, "git", gitArguments...)
	command.Env = isolatedGitEnvironment(os.Environ(), directory)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return output, errors.New(message)
	}
	return output, nil
}

func isolatedGitArguments(directory string, arguments []string) []string {
	options := []string{
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.file.allow=always",
		"-c", "protocol.ext.allow=never",
		"-c", "fetch.fsckObjects=true",
		"-c", "transfer.fsckObjects=true",
		"-c", "gc.auto=0",
		"-c", "fetch.unpackLimit=1",
		"-c", "transfer.unpackLimit=1",
		"-c", "core.deltaBaseCacheLimit=16m",
		"-c", "core.packedGitWindowSize=16m",
		"-c", "core.packedGitLimit=64m",
		"-c", "pack.deltaCacheSize=16m",
		"-c", "pack.windowMemory=16m",
		"-c", "pack.threads=1",
		"-C", directory,
	}
	return append(options, arguments...)
}

func isolatedGitEnvironment(base []string, home string) []string {
	allowed := map[string]bool{
		"LANG": true, "LC_ALL": true, "LC_CTYPE": true,
		"PATH": true, "SYSTEMROOT": true,
		"TEMP": true, "TMP": true, "TMPDIR": true,
	}
	environment := make([]string, 0, len(allowed)+6)
	seen := make(map[string]bool, len(allowed))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if !found || !allowed[name] || seen[name] {
			continue
		}
		seen[name] = true
		environment = append(environment, entry)
	}
	environment = append(environment,
		"HOME="+home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GCM_INTERACTIVE=never",
	)
	return environment
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range strings.ToLower(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
