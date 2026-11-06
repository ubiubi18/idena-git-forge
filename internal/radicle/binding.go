package radicle

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/multiformats/go-multibase"
	"golang.org/x/crypto/ssh"
	"idena-git-forge/internal/protocol"
)

const bindingNamespace = "idena-radicle-binding"

func DIDForKey(publicKeyText string) (did string, canonicalKey string, err error) {
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(publicKeyText)))
	if err != nil {
		return "", "", err
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", "", errors.New("public key file contains more than one key")
	}
	cryptoKey, ok := publicKey.(ssh.CryptoPublicKey)
	if !ok {
		return "", "", errors.New("SSH key does not expose a crypto public key")
	}
	_ = cryptoKey
	wire := publicKey.Marshal()
	// Ed25519 public keys are encoded as two SSH strings: algorithm and key.
	alg, wire, ok := parseSSHString(wire)
	if !ok || string(alg) != ssh.KeyAlgoED25519 {
		return "", "", errors.New("Radicle identity key must be Ed25519")
	}
	keyBytes, rest, ok := parseSSHString(wire)
	if !ok || len(keyBytes) != 32 || len(rest) != 0 {
		return "", "", errors.New("invalid Ed25519 public key")
	}
	encoded, err := multibase.Encode(multibase.Base58BTC, append([]byte{0xed, 0x01}, keyBytes...))
	if err != nil {
		return "", "", err
	}
	return "did:key:" + encoded, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))), nil
}

func SignBinding(ctx context.Context, privateKeyPath, message string) (string, error) {
	if privateKeyPath == "" {
		return "", errors.New("Radicle private key path is required")
	}
	baseEnvironment := os.Environ()
	signingKeyPath, err := bindingSigningKeyPath(privateKeyPath, baseEnvironment)
	if err != nil {
		return "", err
	}
	directory, err := os.MkdirTemp("", "idena-radicle-bind-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	messagePath := filepath.Join(directory, "message")
	if err := os.WriteFile(messagePath, []byte(message), 0o600); err != nil {
		return "", err
	}
	command := exec.CommandContext(ctx, "ssh-keygen", "-Y", "sign", "-f", signingKeyPath, "-n", bindingNamespace, messagePath)
	command.Env = bindingCommandEnvironment(baseEnvironment)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("Radicle key did not sign binding: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	signature, err := os.ReadFile(messagePath + ".sig")
	if err != nil {
		return "", err
	}
	return string(signature), nil
}

func VerifyBinding(ctx context.Context, envelope protocol.Envelope) error {
	publicKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(envelope.RadicleKey))
	if err != nil {
		return fmt.Errorf("parse Radicle public key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("Radicle public key field contains extra data")
	}
	did, _, err := DIDForKey(envelope.RadicleKey)
	if err != nil {
		return err
	}
	if did != envelope.RadicleDID {
		return errors.New("Radicle public key does not match the declared did:key")
	}
	if strings.TrimSpace(envelope.Binding) == "" {
		return errors.New("binding signature is missing")
	}

	directory, err := os.MkdirTemp("", "idena-radicle-verify-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	messagePath := filepath.Join(directory, "message")
	signaturePath := filepath.Join(directory, "message.sig")
	signersPath := filepath.Join(directory, "allowed_signers")
	if err := os.WriteFile(messagePath, []byte(envelope.RadicleBindingMessage()), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(signaturePath, []byte(envelope.Binding), 0o600); err != nil {
		return err
	}
	line := envelope.RadicleDID + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey))) + "\n"
	if err := os.WriteFile(signersPath, []byte(line), 0o600); err != nil {
		return err
	}
	messageFile, err := os.Open(messagePath)
	if err != nil {
		return err
	}
	defer messageFile.Close()
	command := exec.CommandContext(
		ctx,
		"ssh-keygen",
		"-Y", "verify",
		"-f", signersPath,
		"-I", envelope.RadicleDID,
		"-n", bindingNamespace,
		"-s", signaturePath,
	)
	command.Stdin = messageFile
	command.Env = bindingCommandEnvironment(os.Environ())
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("Radicle binding signature is invalid: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func bindingCommandEnvironment(base []string) []string {
	allowed := map[string]bool{
		"LANG": true, "LC_ALL": true, "LC_CTYPE": true,
		"PATH": true, "SYSTEMROOT": true,
		"SSH_AUTH_SOCK": true,
		"TEMP":          true, "TMP": true, "TMPDIR": true,
	}
	environment := make([]string, 0, len(allowed))
	seen := make(map[string]bool, len(allowed))
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if !found || !allowed[name] || seen[name] {
			continue
		}
		seen[name] = true
		environment = append(environment, entry)
	}
	return environment
}

func bindingSigningKeyPath(privateKeyPath string, environment []string) (string, error) {
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if !found || name != "SSH_AUTH_SOCK" || strings.TrimSpace(value) == "" {
			continue
		}
		publicKeyPath := privateKeyPath + ".pub"
		info, err := os.Stat(publicKeyPath)
		if err != nil {
			return "", fmt.Errorf("read Radicle public key for SSH agent signing: %w", err)
		}
		if !info.Mode().IsRegular() {
			return "", errors.New("Radicle public key for SSH agent signing is not a regular file")
		}
		return publicKeyPath, nil
	}
	return privateKeyPath, nil
}

func parseSSHString(input []byte) ([]byte, []byte, bool) {
	if len(input) < 4 {
		return nil, nil, false
	}
	length := int(input[0])<<24 | int(input[1])<<16 | int(input[2])<<8 | int(input[3])
	if length < 0 || len(input) < 4+length {
		return nil, nil, false
	}
	return input[4 : 4+length], input[4+length:], true
}
