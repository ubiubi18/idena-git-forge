package radicle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/multiformats/go-multibase"
	"idena-git-forge/internal/content"
	"idena-git-forge/internal/gitutil"
	"idena-git-forge/internal/protocol"
)

const (
	PatchType = "xyz.radicle.patch"
	IssueType = "xyz.radicle.issue"

	MergeRequestLabel         = "idena/merge-request"
	repositoryIdentityVersion = 3
	maxBundleBytes            = gitutil.MaxBundleBytes
	radicleBinarySHA256Env    = "RAD_BIN_SHA256"
)

type Client struct {
	Binary               string
	Home                 string
	Passphrase           string
	ExpectedBinarySHA256 string
}

// VerificationClient is deliberately incapable of carrying signing material.
// Read-only COB verification needs the reviewed offline binary, config.json,
// and keys/radicle.pub only. Signer operations continue to use Client.
type VerificationClient struct {
	Binary               string
	Home                 string
	ExpectedBinarySHA256 string
}

func (client VerificationClient) commandClient() Client {
	return Client{
		Binary:               client.Binary,
		Home:                 client.Home,
		ExpectedBinarySHA256: client.ExpectedBinarySHA256,
	}
}

func (client VerificationClient) ValidateProfile() error {
	if client.Home == "" {
		return errors.New("Radicle verification home is required")
	}
	for _, path := range []string{
		filepath.Join(client.Home, "config.json"),
		filepath.Join(client.Home, "keys", "radicle.pub"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("public Radicle verification profile not found in %s; config.json and keys/radicle.pub are required", client.Home)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Radicle verification profile entry %s is not a regular file", path)
		}
	}
	return nil
}

type CobEntry struct {
	ID        string            `json:"id"`
	Actions   []json.RawMessage `json:"actions"`
	Author    string            `json:"author"`
	Timestamp int64             `json:"timestamp"`
	Parents   []string          `json:"parents"`
	Identity  string            `json:"identity"`
	Manifest  struct {
		TypeName string `json:"typeName"`
		Version  uint16 `json:"version"`
	} `json:"manifest"`
}

type CobAction struct {
	Type     string   `json:"type"`
	Revision string   `json:"revision,omitempty"`
	Review   string   `json:"review,omitempty"`
	Verdict  string   `json:"verdict,omitempty"`
	Labels   []string `json:"labels,omitempty"`
	Base     string   `json:"base,omitempty"`
	OID      string   `json:"oid,omitempty"`
	Title    string   `json:"title,omitempty"`
	Target   string   `json:"target,omitempty"`
}

type PatchState struct {
	Title  string `json:"title"`
	Author struct {
		ID string `json:"id"`
	} `json:"author"`
	State struct {
		Status string `json:"status"`
	} `json:"state"`
	Revisions map[string]struct {
		ID   string `json:"id"`
		Base string `json:"base"`
		OID  string `json:"oid"`
	} `json:"revisions"`
}

type repositoryIdentityDocument struct {
	Version     uint32                     `json:"version"`
	Initializer string                     `json:"initializer"`
	Payload     map[string]json.RawMessage `json:"payload"`
	Visibility  json.RawMessage            `json:"visibility,omitempty"`
}

func (client Client) VerifySubject(ctx context.Context, subject protocol.RadicleSubject) error {
	if err := client.ValidateRepositoryIdentity(ctx, subject.RID); err != nil {
		return err
	}
	return client.verifySubject(ctx, subject)
}

func (client Client) verifySubject(ctx context.Context, subject protocol.RadicleSubject) error {
	if subject.Kind == protocol.KindRepository || subject.Kind == protocol.KindCommit {
		if !validObjectID(subject.Head) {
			return errors.New("Radicle subject has an invalid head")
		}
		path, err := client.RepositoryPath(subject.RID)
		if err != nil {
			return err
		}
		if _, err := radiclePublicKey(subject.ActorDID); err != nil {
			return err
		}
		actor := strings.TrimPrefix(subject.ActorDID, "did:key:")
		entries, err := verifiedActorRefs(ctx, path, subject.RID, actor)
		if err != nil {
			return fmt.Errorf("verify actor signed refs: %w", err)
		}
		switch subject.Kind {
		case protocol.KindRepository:
			identity, err := gitOutput(ctx, path, "rev-parse", "--verify", "refs/rad/id^{commit}")
			identityCommit := strings.TrimSpace(string(identity))
			if err != nil || !strings.EqualFold(entries["refs/rad/id"], identityCommit) {
				return errors.New("repository creator did not sign the repository identity")
			}
			initializer, err := repositoryInitializer(ctx, path, subject.RID, identityCommit)
			if err != nil {
				return fmt.Errorf("verify repository initializer: %w", err)
			}
			if initializer != subject.ActorDID {
				return errors.New("repository actor does not match the immutable identity initializer")
			}
			ownsHead := false
			for name, oid := range entries {
				if strings.HasPrefix(name, "refs/heads/") && strings.EqualFold(oid, subject.Head) {
					ownsHead = true
					break
				}
			}
			if !ownsHead {
				return errors.New("repository creator did not sign the genesis head")
			}
		case protocol.KindCommit:
			if !strings.HasPrefix(subject.Ref, "refs/heads/") || entries[subject.Ref] == "" ||
				!strings.EqualFold(entries[subject.Ref], subject.Head) {
				return errors.New("commit head is not present in the actor's signed namespace")
			}
		}
		return client.git(ctx, subject.RID, "cat-file", "-e", subject.Head+"^{commit}")
	}
	entries, err := client.CobLog(ctx, subject.RID, subject.CobType, subject.CobID)
	if err != nil {
		return err
	}
	return verifyCobSubject(entries, subject)
}

func verifiedActorRefs(ctx context.Context, repository, rid, actor string) (map[string]string, error) {
	entries, _, err := verifiedActorNamespace(ctx, repository, rid, actor)
	return entries, err
}

func verifiedActorNamespace(ctx context.Context, repository, rid, actor string) (map[string]string, string, error) {
	if actor == "" || strings.Contains(actor, "/") {
		return nil, "", errors.New("invalid Radicle actor DID")
	}
	sigref := "refs/namespaces/" + actor + "/refs/rad/sigrefs"
	sigrefsBytes, err := gitOutput(ctx, repository, "rev-parse", "--verify", sigref+"^{commit}")
	if err != nil {
		return nil, "", fmt.Errorf("namespace %s has no signed-refs commit", actor)
	}
	sigrefs := strings.TrimSpace(string(sigrefsBytes))
	refsBytes, err := gitOutput(ctx, repository, "show", sigref+":refs")
	if err != nil {
		return nil, "", err
	}
	signature, err := gitOutput(ctx, repository, "show", sigref+":signature")
	if err != nil {
		return nil, "", err
	}
	if err := verifySignedRefs("did:key:"+actor, refsBytes, signature); err != nil {
		return nil, "", err
	}
	entries, err := parseSignedRefs(refsBytes)
	if err != nil {
		return nil, "", err
	}
	root, exists := entries["refs/rad/root"]
	if !exists {
		return nil, "", errors.New("signed refs omit refs/rad/root")
	}
	if err := validateIdentityObject(ctx, repository, rid, root); err != nil {
		return nil, "", err
	}
	if err := validateSignedRefsParent(ctx, repository, sigrefs, entries); err != nil {
		return nil, "", err
	}
	for name, oid := range entries {
		if name == "refs/rad/sigrefs-parent" {
			continue
		}
		source := "refs/namespaces/" + actor + "/" + name
		actual, err := gitOutput(ctx, repository, "rev-parse", "--verify", source)
		if err != nil || !strings.EqualFold(strings.TrimSpace(string(actual)), oid) {
			return nil, "", fmt.Errorf("namespace ref %s differs from its signed manifest", name)
		}
	}
	return entries, sigrefs, nil
}

func validateSignedRefsParent(ctx context.Context, repository, sigrefs string, entries map[string]string) error {
	line, err := gitOutput(ctx, repository, "rev-list", "--parents", "-n", "1", sigrefs)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(line))
	if len(fields) == 0 || !strings.EqualFold(fields[0], sigrefs) {
		return errors.New("cannot resolve signed-refs commit ancestry")
	}
	if len(fields) > 2 {
		return errors.New("signed-refs history must be linear")
	}
	declared, hasDeclared := entries["refs/rad/sigrefs-parent"]
	if !hasDeclared {
		return nil
	}
	if len(fields) != 2 || !strings.EqualFold(fields[1], declared) {
		return errors.New("signed-refs parent marker does not match the commit parent")
	}
	return nil
}

func verifyCobSubject(entries []CobEntry, subject protocol.RadicleSubject) error {
	actor := strings.TrimPrefix(subject.ActorDID, "did:key:")
	var matched *CobEntry
	for index := range entries {
		entry := &entries[index]
		if entry.ID == subject.ActionOID {
			matched = entry
			break
		}
	}
	if matched == nil {
		return fmt.Errorf("Radicle operation %s is not present", subject.ActionOID)
	}
	if matched.Author != actor {
		return errors.New("Radicle operation author does not match bound did:key")
	}
	for _, raw := range matched.Actions {
		var action CobAction
		if err := json.Unmarshal(raw, &action); err != nil {
			return err
		}
		switch subject.Kind {
		case protocol.KindIssue:
			if action.Type == "comment" {
				return nil
			}
		case protocol.KindPullRequest:
			if action.Type == "revision" &&
				action.OID == subject.Head &&
				action.Base == subject.Base {
				return nil
			}
		case protocol.KindVote:
			expectedVerdict := subject.Verdict
			if expectedVerdict == protocol.DecisionApprove {
				expectedVerdict = "accept"
			}
			if strings.EqualFold(action.Verdict, expectedVerdict) {
				if action.Type == "review" &&
					matched.ID == subject.ReviewID &&
					action.Revision == subject.RevisionID {
					return nil
				}
				if (action.Type == "review.edit" || action.Type == "review.edit.v2") &&
					action.Review == subject.ReviewID &&
					reviewAppliesToRevision(entries, subject) {
					return nil
				}
			}
		case protocol.KindMergeRequest:
			if action.Type == "label" {
				for _, label := range action.Labels {
					if label == MergeRequestLabel {
						return nil
					}
				}
			}
		case protocol.KindComment:
			if action.Type == "comment" {
				return nil
			}
		}
	}
	return errors.New("Radicle operation does not match the anchored action")
}

func reviewAppliesToRevision(entries []CobEntry, subject protocol.RadicleSubject) bool {
	actor := strings.TrimPrefix(subject.ActorDID, "did:key:")
	for _, entry := range entries {
		if entry.ID != subject.ReviewID || entry.Author != actor {
			continue
		}
		for _, raw := range entry.Actions {
			var action CobAction
			if err := json.Unmarshal(raw, &action); err != nil {
				continue
			}
			if action.Type == "review" && action.Revision == subject.RevisionID {
				return true
			}
		}
	}
	return false
}

func (client Client) CobLog(ctx context.Context, rid, typename, object string) ([]CobEntry, error) {
	output, err := client.run(ctx, "cob", "log", "--repo", rid, "--type", typename, "--object", object, "--format", "json")
	if err != nil {
		return nil, err
	}
	var entries []CobEntry
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var entry CobEntry
		if err := decoder.Decode(&entry); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (client Client) CobShow(ctx context.Context, rid, typename, object string) (json.RawMessage, error) {
	output, err := client.run(ctx, "cob", "show", "--repo", rid, "--type", typename, "--object", object, "--format", "json")
	if err != nil {
		return nil, err
	}
	return json.RawMessage(bytes.TrimSpace(output)), nil
}

func (client Client) PatchState(ctx context.Context, rid, patchID string) (PatchState, error) {
	output, err := client.CobShow(ctx, rid, PatchType, patchID)
	if err != nil {
		return PatchState{}, err
	}
	var state PatchState
	if err := json.Unmarshal(output, &state); err != nil {
		return PatchState{}, err
	}
	return state, nil
}

func (client Client) PatchDiff(ctx context.Context, rid, patchID, revisionID string) ([]byte, error) {
	arguments := []string{"patch", "diff", patchID, "--repo", rid, "--no-announce"}
	if revisionID != "" {
		arguments = append(arguments, "--revision", revisionID)
	}
	return client.run(ctx, arguments...)
}

func (client Client) MarkMergeRequest(ctx context.Context, rid, patchID string) error {
	_, err := client.run(ctx, "patch", "label", patchID, "--add", MergeRequestLabel, "--no-announce", "--repo", rid)
	return err
}

func (client Client) ExportBundle(ctx context.Context, rid string) ([]byte, error) {
	if err := client.ValidateRepositoryIdentity(ctx, rid); err != nil {
		return nil, err
	}
	path, err := client.RepositoryPath(rid)
	if err != nil {
		return nil, err
	}
	tempDirectory, err := os.MkdirTemp("", "idena-radicle-bundle-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDirectory)
	bundlePath := filepath.Join(tempDirectory, "storage.bundle")
	if err := gitutil.Run(ctx, path, "bundle", "create", bundlePath, "--all"); err != nil {
		return nil, fmt.Errorf("export Radicle storage bundle: %w", err)
	}
	return os.ReadFile(bundlePath)
}

func (client Client) ImportBundle(ctx context.Context, rid, actorDID string, bundle []byte) error {
	if !validRadicleRID(rid) || client.Home == "" {
		return errors.New("valid Radicle home and repository id are required")
	}
	if _, err := radiclePublicKey(actorDID); err != nil {
		return fmt.Errorf("valid action-bound Radicle actor is required: %w", err)
	}
	if len(bundle) == 0 || len(bundle) > maxBundleBytes {
		return errors.New("Radicle bundle is empty or exceeds the import limit")
	}
	bundleContext, cancel := context.WithTimeout(ctx, gitutil.BundleVerificationTimeout)
	defer cancel()
	if err := gitutil.ValidateBundleResources(bundleContext, bundle); err != nil {
		return fmt.Errorf("preflight Radicle bundle: %w", err)
	}
	ctx = bundleContext
	tempDirectory, err := os.MkdirTemp("", "idena-radicle-import-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDirectory)
	bundlePath := filepath.Join(tempDirectory, "storage.bundle")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}
	stagingHome := filepath.Join(tempDirectory, "home")
	stagingPath := filepath.Join(stagingHome, "storage", strings.TrimPrefix(rid, "rad:"))
	if err := os.MkdirAll(stagingPath, 0o755); err != nil {
		return err
	}
	if err := runGit(ctx, stagingPath, "init", "--bare"); err != nil {
		return err
	}
	if err := runGit(ctx, stagingPath, "bundle", "verify", bundlePath); err != nil {
		return err
	}
	if err := runGit(ctx, stagingPath, "fetch", "--no-tags", bundlePath, "+refs/*:refs/*"); err != nil {
		return err
	}
	stagingClient := client
	stagingClient.Home = stagingHome
	if err := stagingClient.ValidateRepositoryIdentity(ctx, rid); err != nil {
		return fmt.Errorf("verify staged Radicle bundle: %w", err)
	}
	actor := strings.TrimPrefix(actorDID, "did:key:")
	refspecs, incomingSigrefs, incomingEntries, err := verifiedActorRefspecs(ctx, stagingPath, rid, actor)
	if err != nil {
		return fmt.Errorf("verify staged Radicle signed refs: %w", err)
	}

	path := filepath.Join(client.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	newRepository := false
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		newRepository = true
	} else if err != nil {
		return err
	} else if err := client.ValidateRepositoryIdentity(ctx, rid); err != nil {
		return fmt.Errorf("existing Radicle storage has a different identity: %w", err)
	}
	stagedIdentity, err := gitOutput(ctx, stagingPath, "rev-parse", "--verify", "refs/rad/id^{commit}")
	if err != nil {
		return err
	}
	if newRepository {
		initializer, err := repositoryInitializer(ctx, stagingPath, rid, strings.TrimSpace(string(stagedIdentity)))
		if err != nil {
			return err
		}
		if initializer != actorDID {
			return errors.New("only the immutable repository initializer may install new storage")
		}
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
		if err := runGit(ctx, path, "init", "--bare"); err != nil {
			_ = os.RemoveAll(path)
			return err
		}
		refspecs = append(refspecs, "refs/rad/id:refs/rad/id")
	} else {
		existingIdentity, err := gitOutput(ctx, path, "rev-parse", "--verify", "refs/rad/id^{commit}")
		if err != nil {
			return err
		}
		if !bytes.Equal(bytes.TrimSpace(existingIdentity), bytes.TrimSpace(stagedIdentity)) {
			return errors.New("bundle attempts to replace the repository identity")
		}
		if err := ensureSignedRefsAdvance(ctx, stagingPath, path, actor, incomingSigrefs, incomingEntries); err != nil {
			return err
		}
	}
	sort.Strings(refspecs)
	if len(refspecs) == 0 {
		return client.ValidateRepositoryIdentity(ctx, rid)
	}
	arguments := append([]string{"fetch", "--atomic", stagingPath}, refspecs...)
	if err := runGit(ctx, path, arguments...); err != nil {
		if newRepository {
			_ = os.RemoveAll(path)
		}
		return err
	}
	if err := client.ValidateRepositoryIdentity(ctx, rid); err != nil {
		if newRepository {
			_ = os.RemoveAll(path)
		}
		return err
	}
	return nil
}

// verifiedActorRefspecs accepts only refs covered by the action-bound actor's
// Ed25519 signed-refs manifest. Other valid namespaces in the same bundle are
// intentionally ignored, and top-level refs/idena refs are never imported.
func verifiedActorRefspecs(ctx context.Context, repository, rid, actor string) ([]string, string, map[string]string, error) {
	entries, sigrefs, err := verifiedActorNamespace(ctx, repository, rid, actor)
	if err != nil {
		return nil, "", nil, err
	}
	refspecs := make([]string, 0, len(entries)+1)
	for name := range entries {
		if name == "refs/rad/sigrefs-parent" {
			continue
		}
		if strings.HasPrefix(name, "refs/idena/") {
			return nil, "", nil, fmt.Errorf("namespace %s signs a reserved Idena ref", actor)
		}
		source := "refs/namespaces/" + actor + "/" + name
		refspecs = append(refspecs, source+":"+source)
	}
	sigref := "refs/namespaces/" + actor + "/refs/rad/sigrefs"
	refspecs = append(refspecs, sigref+":"+sigref)
	return refspecs, sigrefs, entries, nil
}

func ensureSignedRefsAdvance(
	ctx context.Context,
	stagingPath, livePath, actor, incoming string,
	incomingEntries map[string]string,
) error {
	sigref := "refs/namespaces/" + actor + "/refs/rad/sigrefs"
	currentBytes, err := gitOutput(ctx, livePath, "for-each-ref", "--format=%(objectname)", "--count=1", sigref)
	if err != nil {
		return err
	}
	current := strings.TrimSpace(string(currentBytes))
	if current == "" || strings.EqualFold(current, incoming) {
		return nil
	}
	if _, exists := incomingEntries["refs/rad/sigrefs-parent"]; !exists {
		return errors.New("updated signed refs must bind their commit parent")
	}
	if err := runGit(ctx, stagingPath, "fetch", "--no-tags", livePath, sigref+":refs/idena/import-base"); err != nil {
		return fmt.Errorf("load installed signed-refs ancestry: %w", err)
	}
	if err := runGit(ctx, stagingPath, "merge-base", "--is-ancestor", current, incoming); err != nil {
		return errors.New("incoming signed refs are behind or diverged from installed actor state")
	}
	return nil
}

func verifySignedRefs(did string, canonical, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return errors.New("Radicle signed-refs signature has an invalid length")
	}
	publicKey, err := radiclePublicKey(did)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, canonical, signature) {
		return errors.New("Radicle signed-refs signature is invalid")
	}
	return nil
}

func radiclePublicKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:") {
		return nil, errors.New("Radicle identity is not an Ed25519 did:key")
	}
	encoded := strings.TrimPrefix(did, "did:key:")
	encoding, decoded, err := multibase.Decode(encoded)
	if err != nil || encoding != multibase.Base58BTC || len(decoded) != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, errors.New("Radicle identity is not an Ed25519 did:key")
	}
	canonical, err := multibase.Encode(multibase.Base58BTC, decoded)
	if err != nil || canonical != encoded {
		return nil, errors.New("Radicle identity did:key is not canonical")
	}
	return ed25519.PublicKey(decoded[2:]), nil
}

func parseSignedRefs(canonical []byte) (map[string]string, error) {
	entries := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSuffix(string(canonical), "\n"), "\n") {
		if line == "" {
			continue
		}
		oid, name, found := strings.Cut(line, " ")
		if !found || !validObjectID(oid) || !strings.HasPrefix(name, "refs/") || strings.ContainsAny(name, " \t\r\n") {
			return nil, errors.New("Radicle signed-refs manifest is malformed")
		}
		if _, duplicate := entries[name]; duplicate {
			return nil, errors.New("Radicle signed-refs manifest contains a duplicate ref")
		}
		entries[name] = strings.ToLower(oid)
	}
	return entries, nil
}

func validateIdentityObject(ctx context.Context, repository, rid, identityCommit string) error {
	_, err := repositoryInitializer(ctx, repository, rid, identityCommit)
	return err
}

func repositoryInitializer(ctx context.Context, repository, rid, identityCommit string) (string, error) {
	output, err := gitOutput(ctx, repository, "rev-parse", "--verify", identityCommit+":embeds/radicle.json")
	if err != nil {
		return "", err
	}
	identityOID := strings.TrimSpace(string(output))
	identityBytes, err := hex.DecodeString(identityOID)
	if err != nil || len(identityBytes) != 20 {
		return "", errors.New("Radicle identity is not a SHA-1 object")
	}
	encoded, err := multibase.Encode(multibase.Base58BTC, identityBytes)
	if err != nil {
		return "", err
	}
	if "rad:"+encoded != rid {
		return "", errors.New("Radicle identity does not match repository ID")
	}
	identityJSON, err := gitOutput(ctx, repository, "show", identityCommit+":embeds/radicle.json")
	if err != nil {
		return "", err
	}
	document, err := decodeRepositoryIdentityDocument(identityJSON)
	if err != nil {
		return "", fmt.Errorf("decode Radicle identity document: %w", err)
	}
	if document.Version != repositoryIdentityVersion {
		return "", fmt.Errorf("Radicle identity format version is %d, require %d", document.Version, repositoryIdentityVersion)
	}
	if _, err := radiclePublicKey(document.Initializer); err != nil {
		return "", fmt.Errorf("invalid Radicle identity initializer: %w", err)
	}
	return document.Initializer, nil
}

func decodeRepositoryIdentityDocument(data []byte) (repositoryIdentityDocument, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return repositoryIdentityDocument{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document repositoryIdentityDocument
	if err := decoder.Decode(&document); err != nil {
		return repositoryIdentityDocument{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return repositoryIdentityDocument{}, errors.New("identity document contains trailing JSON")
		}
		return repositoryIdentityDocument{}, err
	}
	if document.Payload == nil {
		return repositoryIdentityDocument{}, errors.New("identity document payload is required")
	}
	if _, exists := document.Payload["xyz.radicle.project"]; !exists {
		return repositoryIdentityDocument{}, errors.New("identity document project payload is required")
	}
	return document, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeUniqueJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("identity document contains trailing JSON")
		}
		return err
	}
	return nil
}

func consumeUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("identity document object key is not a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("identity document contains duplicate key %q", key)
			}
			keys[key] = struct{}{}
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("identity document object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("identity document array is not closed")
		}
	default:
		return errors.New("identity document has an invalid JSON delimiter")
	}
	return nil
}

func (client Client) WriteGovernanceHead(ctx context.Context, rid string, epoch uint16, head string) error {
	if !validObjectID(head) {
		return errors.New("governance head must be a Git object id")
	}
	return client.writeProtectedHead(ctx, rid, fmt.Sprintf("refs/idena/epoch/%d/canonical", epoch), head)
}

func (client Client) WriteGenesisHead(ctx context.Context, rid, head string) error {
	if !validObjectID(head) {
		return errors.New("genesis head must be a Git object id")
	}
	return client.writeProtectedHead(ctx, rid, "refs/idena/genesis/canonical", head)
}

func (client Client) writeProtectedHead(ctx context.Context, rid, refname, head string) error {
	path, err := client.RepositoryPath(rid)
	if err != nil {
		return err
	}
	if err := runGit(ctx, path, "cat-file", "-e", head+"^{commit}"); err != nil {
		return errors.New("governance head is not an available commit")
	}
	existing, err := gitOutput(ctx, path, "rev-parse", "--verify", refname)
	if err == nil {
		if strings.EqualFold(strings.TrimSpace(string(existing)), head) {
			return nil
		}
		return fmt.Errorf("protected ref %s already has a different checkpoint result", refname)
	}
	return runGit(ctx, path, "update-ref", refname, head, strings.Repeat("0", len(head)))
}

func (client Client) RepositoryPath(rid string) (string, error) {
	if !validRadicleRID(rid) {
		return "", errors.New("invalid Radicle repository id")
	}
	if client.Home == "" {
		return "", errors.New("Radicle home is required")
	}
	path := filepath.Join(client.Home, "storage", strings.TrimPrefix(rid, "rad:"))
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("Radicle storage path is not a directory")
	}
	return path, nil
}

func (client Client) ValidateProfile() error {
	if client.Home == "" {
		return errors.New("Radicle home is required")
	}
	for _, path := range []string{
		filepath.Join(client.Home, "config.json"),
		filepath.Join(client.Home, "keys", "radicle"),
	} {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("Radicle profile not found in %s; run `rad auth --alias verifier`", client.Home)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("Radicle profile entry %s is not a regular file", path)
		}
	}
	return nil
}

func (client Client) ValidateRepositoryIdentity(ctx context.Context, rid string) error {
	path, err := client.RepositoryPath(rid)
	if err != nil {
		return err
	}
	output, err := gitOutput(ctx, path, "rev-parse", "--verify", "refs/rad/id^{commit}")
	if err != nil {
		return fmt.Errorf("read Radicle repository identity: %w", err)
	}
	identityCommit := strings.TrimSpace(string(output))
	if err := validateIdentityObject(ctx, path, rid, identityCommit); err != nil {
		return fmt.Errorf("validate Radicle repository identity: %w", err)
	}
	return nil
}

func validRadicleRID(value string) bool {
	if !strings.HasPrefix(value, "rad:z") {
		return false
	}
	encoding, decoded, err := multibase.Decode(strings.TrimPrefix(value, "rad:"))
	return err == nil && encoding == multibase.Base58BTC && len(decoded) == 20
}

func (client Client) run(ctx context.Context, arguments ...string) ([]byte, error) {
	if err := validateOfflineRadicleCommand(arguments); err != nil {
		return nil, err
	}
	binary, err := client.verifiedOfflineBinary(ctx)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, binary, arguments...)
	command.Env = radicleCommandEnvironment(
		os.Environ(),
		client.Home,
		client.Passphrase,
	)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		message := strings.TrimSpace(stderr.String())
		if stdout := strings.TrimSpace(string(output)); stdout != "" {
			if message != "" {
				message += ": "
			}
			message += stdout
		}
		return nil, fmt.Errorf("rad %s: %w: %s", strings.Join(arguments, " "), err, message)
	}
	return output, nil
}

func validateOfflineRadicleCommand(arguments []string) error {
	if len(arguments) >= 2 && arguments[0] == "cob" &&
		(arguments[1] == "log" || arguments[1] == "show") &&
		len(arguments) == 10 &&
		arguments[2] == "--repo" && validRadicleRID(arguments[3]) &&
		arguments[4] == "--type" && validForgeCobType(arguments[5]) &&
		arguments[6] == "--object" && validObjectID(arguments[7]) &&
		arguments[8] == "--format" && arguments[9] == "json" {
		return nil
	}
	if len(arguments) >= 2 && arguments[0] == "patch" && arguments[1] == "diff" &&
		(len(arguments) == 6 || len(arguments) == 8) &&
		validObjectID(arguments[2]) &&
		arguments[3] == "--repo" && validRadicleRID(arguments[4]) &&
		arguments[5] == "--no-announce" &&
		(len(arguments) == 6 || arguments[6] == "--revision" && validObjectID(arguments[7])) {
		return nil
	}
	if len(arguments) == 8 && arguments[0] == "patch" && arguments[1] == "label" &&
		validObjectID(arguments[2]) &&
		arguments[3] == "--add" && arguments[4] == MergeRequestLabel &&
		arguments[5] == "--no-announce" &&
		arguments[6] == "--repo" && validRadicleRID(arguments[7]) {
		return nil
	}
	return fmt.Errorf(
		"Radicle command %q is outside the forge's local-only allowlist; node, discovery, replication, announcement and unreviewed commands are disabled",
		strings.Join(arguments, " "),
	)
}

func validForgeCobType(value string) bool {
	return value == PatchType || value == IssueType
}

func (client Client) verifiedOfflineBinary(ctx context.Context) (string, error) {
	if client.Binary == "" {
		client.Binary = "rad"
	}
	if err := validateOfflineRadicleHome(client.Home); err != nil {
		return "", err
	}
	binary, err := exec.LookPath(client.Binary)
	if err != nil {
		return "", fmt.Errorf("resolve Radicle CLI binary: %w", err)
	}
	expected := strings.TrimSpace(client.ExpectedBinarySHA256)
	if expected == "" {
		expected = strings.TrimSpace(os.Getenv(radicleBinarySHA256Env))
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != sha256.Size {
		return "", fmt.Errorf(
			"%s must contain the reviewed Radicle binary's 64-character SHA-256 digest",
			radicleBinarySHA256Env,
		)
	}
	actual, err := fileSHA256(binary)
	if err != nil {
		return "", fmt.Errorf("hash Radicle CLI binary: %w", err)
	}
	if !strings.EqualFold(expected, actual) {
		return "", fmt.Errorf("Radicle binary digest %s does not match reviewed digest %s", actual, strings.ToLower(expected))
	}

	versionCommand := exec.CommandContext(ctx, binary, "--version")
	versionCommand.Env = radicleCommandEnvironment(os.Environ(), client.Home, "")
	versionOutput, err := versionCommand.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("read Radicle CLI version: %w: %s", err, strings.TrimSpace(string(versionOutput)))
	}
	if err := validateSupportedRadicleVersion(string(versionOutput)); err != nil {
		return "", err
	}
	return binary, nil
}

func validateOfflineRadicleHome(home string) error {
	if home == "" || !filepath.IsAbs(home) {
		return errors.New("an absolute isolated Radicle home is required")
	}
	nodeDirectory := filepath.Join(home, "node")
	disabledSocket := filepath.Join(nodeDirectory, "network-disabled.sock")
	if _, err := os.Lstat(disabledSocket); err == nil {
		return fmt.Errorf("Radicle network-disabled socket path unexpectedly exists: %s", disabledSocket)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Radicle network-disabled socket path: %w", err)
	}
	entries, err := os.ReadDir(nodeDirectory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Radicle node directory: %w", err)
	}
	for _, entry := range entries {
		path := filepath.Join(nodeDirectory, entry.Name())
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("inspect Radicle node entry %s: %w", path, err)
		}
		if info.Mode()&os.ModeSocket != 0 {
			return fmt.Errorf("active Radicle node socket is not permitted: %s", path)
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validateSupportedRadicleVersion(output string) error {
	fields := strings.Fields(strings.TrimSpace(output))
	if len(fields) < 2 || fields[0] != "rad" {
		return fmt.Errorf("unrecognized Radicle version output %q", strings.TrimSpace(output))
	}
	version := fields[1]
	if version == "244a8b6" || strings.HasPrefix(version, "244a8b6-") {
		return nil
	}
	return fmt.Errorf(
		"unsupported Radicle build %q; only the reviewed 244a8b6 Idena fork is accepted, while stock delegate-bearing and Radicle 2.x builds remain disabled",
		version,
	)
}

// radicleCommandEnvironment isolates the Radicle CLI from a separately running
// node. Until Radicle's authenticated and encrypted transport is available, all
// forge content moves through signed Idena actions and Idena IPFS.
func radicleCommandEnvironment(base []string, home, passphrase string) []string {
	allowed := map[string]bool{
		"LANG": true, "LC_ALL": true, "LC_CTYPE": true,
		"PATH": true, "SYSTEMROOT": true,
		"TEMP": true, "TMP": true, "TMPDIR": true,
	}
	environment := make([]string, 0, len(allowed)+3)
	for _, entry := range base {
		name, _, found := strings.Cut(entry, "=")
		if !found || !allowed[name] {
			continue
		}
		environment = append(environment, entry)
	}
	environment = append(
		environment,
		"RAD_HOME="+home,
		"RAD_SOCKET="+filepath.Join(home, "node", "network-disabled.sock"),
	)
	if passphrase != "" {
		environment = append(environment, "RAD_PASSPHRASE="+passphrase)
	}
	return environment
}

func (client Client) git(ctx context.Context, rid string, arguments ...string) error {
	path, err := client.RepositoryPath(rid)
	if err != nil {
		return err
	}
	_, err = gitOutput(ctx, path, arguments...)
	return err
}

func gitOutput(ctx context.Context, path string, arguments ...string) ([]byte, error) {
	output, err := gitutil.Output(ctx, path, arguments...)
	if err != nil {
		return nil, fmt.Errorf("git %s: %w", strings.Join(arguments, " "), err)
	}
	return output, nil
}

func runGit(ctx context.Context, directory string, arguments ...string) error {
	if err := gitutil.Run(ctx, directory, arguments...); err != nil {
		return fmt.Errorf("git %s: %w", strings.Join(arguments, " "), err)
	}
	return nil
}

type ContentVerifier struct {
	Client VerificationClient
	Store  *content.Store
}

func (verifier *ContentVerifier) Verify(ctx context.Context, subject protocol.RadicleSubject) error {
	if verifier.Store == nil {
		return errors.New("content store is required")
	}
	if subject.BundleCID != "" {
		bundle, err := verifier.Store.Get(subject.BundleCID)
		if err != nil {
			return fmt.Errorf("%w: Radicle storage bundle %s: %v", protocol.ErrContentUnavailable, subject.BundleCID, err)
		}
		if err := verifySubjectBundle(ctx, verifier.Client, subject, bundle); err != nil {
			return fmt.Errorf("Radicle storage bundle %s: %w", subject.BundleCID, err)
		}
		return nil
	}
	return errors.New("Radicle subject has no storage bundle")
}

// verifySubjectBundle validates only the exact content-addressed bundle named
// by the action. It never consults previously restored live storage, so two
// replicas with the same bundle bytes cannot classify the action differently
// because their Radicle caches differ.
func verifySubjectBundle(ctx context.Context, client VerificationClient, subject protocol.RadicleSubject, bundle []byte) error {
	if len(bundle) == 0 || len(bundle) > maxBundleBytes {
		return errors.New("Radicle bundle is empty or exceeds the verification limit")
	}
	bundleContext, cancel := context.WithTimeout(ctx, gitutil.BundleVerificationTimeout)
	defer cancel()
	if err := gitutil.ValidateBundleResources(bundleContext, bundle); err != nil {
		return fmt.Errorf("preflight Radicle bundle: %w", err)
	}
	ctx = bundleContext
	directory, err := os.MkdirTemp("", "idena-radicle-bundle-check-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	bundlePath := filepath.Join(directory, "storage.bundle")
	if err := os.WriteFile(bundlePath, bundle, 0o600); err != nil {
		return err
	}
	stagingHome := filepath.Join(directory, "home")
	repository := filepath.Join(stagingHome, "storage", strings.TrimPrefix(subject.RID, "rad:"))
	if err := os.MkdirAll(repository, 0o755); err != nil {
		return err
	}
	if err := runGit(ctx, repository, "init", "--bare"); err != nil {
		return err
	}
	if err := runGit(ctx, repository, "bundle", "verify", bundlePath); err != nil {
		return err
	}
	if err := runGit(ctx, repository, "fetch", "--no-tags", bundlePath, "+refs/*:refs/*"); err != nil {
		return err
	}
	// Repository and commit subjects are verified entirely from the identity,
	// signed actor namespace and Git objects in the quarantined bundle. They do
	// not need a local Radicle identity or executable, which lets a new mirror
	// verify genesis without first becoming a Radicle actor. COB-backed actions
	// still require the reviewed offline client and its isolated profile.
	if subject.Kind != protocol.KindRepository && subject.Kind != protocol.KindCommit {
		if err := copyPublicVerificationProfile(client.Home, stagingHome); err != nil {
			return err
		}
	}
	stagingClient := client.commandClient()
	stagingClient.Home = stagingHome
	if err := stagingClient.ValidateRepositoryIdentity(ctx, subject.RID); err != nil {
		return err
	}
	return stagingClient.verifySubject(ctx, subject)
}

func copyPublicVerificationProfile(sourceHome, targetHome string) error {
	if sourceHome == "" {
		return errors.New("Radicle home is required for quarantined verification")
	}
	for _, relative := range []string{"config.json", filepath.Join("keys", "radicle.pub")} {
		source := filepath.Join(sourceHome, relative)
		data, err := os.ReadFile(source)
		if err != nil {
			return fmt.Errorf("read public Radicle verification profile %s: %w", relative, err)
		}
		target := filepath.Join(targetHome, relative)
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			return err
		}
	}
	return nil
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
