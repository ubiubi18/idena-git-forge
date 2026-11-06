package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"idena-git-forge/internal/content"
	"idena-git-forge/internal/protocol"
)

// MaxStandaloneBytes is the largest standalone preview the current Idena
// Desktop social publisher accepts for its local IPFS add path.
const MaxStandaloneBytes = 900_000
const IdenaSocialContract = "0x840e092e31e9656fF15E541505039ed77585338E"

type ExportManifest struct {
	Schema           string   `json:"schema"`
	ReducerPolicy    string   `json:"reducerPolicy"`
	Checkpoint       uint64   `json:"checkpoint"`
	BlockHash        string   `json:"blockHash"`
	StateRoot        string   `json:"stateRoot"`
	InputDigest      string   `json:"inputDigest"`
	HTMLSHA256       string   `json:"htmlSha256"`
	HTMLBytes        int      `json:"htmlBytes"`
	EmbeddedDiffCIDs []string `json:"embeddedDiffCids"`
	MissingDiffCIDs  []string `json:"missingDiffCids,omitempty"`
	IPFSCID          string   `json:"ipfsCid,omitempty"`
}

type SocialPostPlan struct {
	Schema   string `json:"schema"`
	From     string `json:"from,omitempty"`
	Contract string `json:"contract"`
	Method   string `json:"method"`
	Amount   string `json:"amount"`
	Argument string `json:"argument"`
	Message  string `json:"message"`
	Channel  string `json:"channel"`
	MaxFee   string `json:"maxFee,omitempty"`
	TxHash   string `json:"txHash,omitempty"`
}

type exportView struct {
	Checkpoint   protocol.CheckpointResult
	Repositories []exportRepository
}

type checkpointView struct {
	ReducerPolicy string                   `json:"reducerPolicy"`
	Checkpoint    protocol.CheckpointBlock `json:"checkpoint"`
	Repositories  []repositoryView         `json:"repositories"`
	Rejected      []protocol.Rejection     `json:"rejected"`
	InputDigest   string                   `json:"inputDigest"`
}

type repositoryView struct {
	Repository      string   `json:"repository"`
	PreviousHead    string   `json:"previousHead"`
	CanonicalHead   string   `json:"canonicalHead"`
	Winner          string   `json:"winner,omitempty"`
	WinnerRevision  string   `json:"winnerRevision,omitempty"`
	Deleted         bool     `json:"deleted,omitempty"`
	PruneAfterEpoch uint16   `json:"pruneAfterEpoch,omitempty"`
	PRs             []prView `json:"prs"`
}

type prView struct {
	protocol.PRResult
	Availability protocol.ContentAvailability `json:"availability"`
}

type exportRepository struct {
	Repository     string
	CanonicalHead  string
	Winner         string
	WinnerRevision string
	Deleted        bool
	PruneAfter     uint16
	PRs            []exportPR
}

type exportPR struct {
	PR               string
	Revision         string
	Title            string
	Author           string
	IdenaAuthor      string
	Base             string
	Head             string
	Reason           string
	Eligible         bool
	MergeRequested   bool
	UniqueVoters     int
	ApprovalVoters   int
	IdentityMajority bool
	CombinedStake    string
	ApprovalWeight   string
	RejectWeight     string
	StakeMajority    bool
	Ballots          []protocol.Ballot
	Availability     protocol.ContentAvailability
	Diff             []diffLine
	DiffError        string
}

type diffLine struct {
	Class string
	Text  string
}

// ExportStandalone renders a single HTML document with no scripts and no
// network dependencies. The checkpoint and every available exact diff are
// embedded, so the same bytes work from Idena IPFS without an HTTP service.
func ExportStandalone(checkpoint protocol.CheckpointResult, store *content.Store) ([]byte, ExportManifest, error) {
	if err := protocol.ValidateCheckpointResultPolicy(checkpoint); err != nil {
		return nil, ExportManifest{}, err
	}
	if store == nil {
		return nil, ExportManifest{}, fmt.Errorf("content store is required")
	}
	view, embedded, missing, err := buildExportView(checkpoint, store)
	if err != nil {
		return nil, ExportManifest{}, err
	}
	var output bytes.Buffer
	if err := standaloneTemplate.Execute(&output, view); err != nil {
		return nil, ExportManifest{}, err
	}
	if output.Len() > MaxStandaloneBytes {
		return nil, ExportManifest{}, fmt.Errorf(
			"standalone preview is %d bytes; current Idena IPFS publishing limit is %d bytes",
			output.Len(),
			MaxStandaloneBytes,
		)
	}
	digest := sha256.Sum256(output.Bytes())
	manifest := ExportManifest{
		Schema:           "idena-radicle/ui-export/v1",
		ReducerPolicy:    checkpoint.ReducerPolicy,
		Checkpoint:       checkpoint.Checkpoint.Height,
		BlockHash:        checkpoint.Checkpoint.Hash,
		StateRoot:        checkpoint.Checkpoint.StateRoot,
		InputDigest:      checkpoint.InputDigest,
		HTMLSHA256:       "sha256:" + hex.EncodeToString(digest[:]),
		HTMLBytes:        output.Len(),
		EmbeddedDiffCIDs: embedded,
		MissingDiffCIDs:  missing,
	}
	return output.Bytes(), manifest, nil
}

// SocialPost returns the exact idena.social makePost argument for an exported
// preview pinned at cid. A plain message is used because idena.social's current
// editor publishes image media; compatible clients recognize the marker and
// render the referenced HTML through their local Idena IPFS node.
func SocialPost(checkpoint protocol.CheckpointResult, cid, channel string) (SocialPostPlan, error) {
	if err := protocol.ValidateCheckpointResultPolicy(checkpoint); err != nil {
		return SocialPostPlan{}, err
	}
	if channel == "" {
		channel = "r/idena"
	}
	if len(channel) < 5 || !strings.HasPrefix(channel, "r/") ||
		len(channel) > 23 {
		return SocialPostPlan{}, fmt.Errorf("invalid idena.social channel %q", channel)
	}
	for _, char := range channel[2:] {
		if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '_' {
			return SocialPostPlan{}, fmt.Errorf("invalid idena.social channel %q", channel)
		}
	}
	block := checkpoint.Checkpoint.Hash
	if len(block) > 12 {
		block = block[:12]
	}
	message := fmt.Sprintf(
		"Idena x Radicle checkpoint %d at block %d (%s): idena-radicle://%s",
		checkpoint.Checkpoint.Epoch,
		checkpoint.Checkpoint.Height,
		block,
		cid,
	)
	argument, _ := json.Marshal(map[string]string{"message": message, "channelId": channel})
	return SocialPostPlan{
		Schema:   "idena-radicle/social-post/v1",
		Contract: IdenaSocialContract,
		Method:   "makePost",
		Amount:   "0.00001",
		Argument: string(argument),
		Message:  message,
		Channel:  channel,
	}, nil
}

func buildExportView(checkpoint protocol.CheckpointResult, store *content.Store) (exportView, []string, []string, error) {
	view := exportView{Checkpoint: checkpoint}
	pins, err := pinIndex(store)
	if err != nil {
		return exportView{}, nil, nil, err
	}
	seen := make(map[string]bool)
	embedded := make([]string, 0)
	missing := make([]string, 0)
	for _, repo := range checkpoint.Repositories {
		exportRepo := exportRepository{
			Repository:     repo.Repository,
			CanonicalHead:  repo.CanonicalHead,
			Winner:         repo.Winner,
			WinnerRevision: repo.WinnerRevision,
			Deleted:        repo.Deleted,
			PruneAfter:     repo.PruneAfterEpoch,
		}
		for _, pr := range repo.PRs {
			item := exportPR{
				PR:               pr.PR,
				Revision:         pr.Revision,
				Title:            pr.Title,
				Author:           pr.Author,
				IdenaAuthor:      pr.IdenaAuthor,
				Base:             pr.Base,
				Head:             pr.Head,
				Reason:           pr.Reason,
				Eligible:         pr.Eligible,
				MergeRequested:   pr.MergeRequested,
				UniqueVoters:     pr.UniqueVoters,
				ApprovalVoters:   pr.ApprovalVoters,
				IdentityMajority: pr.IdentityMajority,
				CombinedStake:    pr.CombinedStake,
				ApprovalWeight:   pr.ApprovalWeight,
				RejectWeight:     pr.RejectionWeight,
				StakeMajority:    pr.StakeMajority,
				Ballots:          pr.Ballots,
				Availability:     localAvailability(pr, checkpoint.Checkpoint.Epoch, store, pins),
			}
			if pr.DiffCID == "" {
				item.DiffError = "Diff CID unavailable."
			} else {
				data, err := store.Get(pr.DiffCID)
				if err != nil {
					item.DiffError = "Diff content is not available at this replica."
					if !seen[pr.DiffCID] {
						seen[pr.DiffCID] = true
						missing = append(missing, pr.DiffCID)
					}
				} else {
					item.Diff = parseDiff(string(data))
					if !seen[pr.DiffCID] {
						seen[pr.DiffCID] = true
						embedded = append(embedded, pr.DiffCID)
					}
				}
			}
			exportRepo.PRs = append(exportRepo.PRs, item)
		}
		view.Repositories = append(view.Repositories, exportRepo)
	}
	return view, embedded, missing, nil
}

func localCheckpointView(checkpoint protocol.CheckpointResult, store *content.Store) (checkpointView, error) {
	pins, err := pinIndex(store)
	if err != nil {
		return checkpointView{}, err
	}
	view := checkpointView{
		ReducerPolicy: checkpoint.ReducerPolicy,
		Checkpoint:    checkpoint.Checkpoint,
		Rejected:      checkpoint.Rejected,
		InputDigest:   checkpoint.InputDigest,
	}
	for _, repository := range checkpoint.Repositories {
		repositoryView := repositoryView{
			Repository:      repository.Repository,
			PreviousHead:    repository.PreviousHead,
			CanonicalHead:   repository.CanonicalHead,
			Winner:          repository.Winner,
			WinnerRevision:  repository.WinnerRevision,
			Deleted:         repository.Deleted,
			PruneAfterEpoch: repository.PruneAfterEpoch,
		}
		for _, pr := range repository.PRs {
			repositoryView.PRs = append(repositoryView.PRs, prView{
				PRResult:     pr,
				Availability: localAvailability(pr, checkpoint.Checkpoint.Epoch, store, pins),
			})
		}
		view.Repositories = append(view.Repositories, repositoryView)
	}
	return view, nil
}

func pinIndex(store *content.Store) (map[string]content.PinRecord, error) {
	pins, err := store.Pins()
	if err != nil {
		return nil, err
	}
	result := make(map[string]content.PinRecord, len(pins))
	for _, pin := range pins {
		result[pin.CID] = pin
	}
	return result, nil
}

func localAvailability(pr protocol.PRResult, epoch uint16, store *content.Store, pins map[string]content.PinRecord) protocol.ContentAvailability {
	requiredUntil := epoch
	if epoch <= ^uint16(0)-2 {
		requiredUntil = epoch + 2
	}
	objects := map[string]bool{}
	available := func(contentCID string) bool {
		if contentCID == "" {
			return false
		}
		present := store.Has(contentCID)
		objects[contentCID] = present
		return present
	}
	action := available(pr.ActionCID)
	bundle := available(pr.BundleCID)
	diff := available(pr.DiffCID)
	continuous := action && bundle && diff
	for _, contentCID := range []string{pr.ActionCID, pr.BundleCID, pr.DiffCID} {
		pin, exists := pins[contentCID]
		if contentCID == "" || !exists || !pin.Forever {
			continuous = false
		}
	}
	return protocol.ContentAvailability{
		Action:        action,
		Bundle:        bundle,
		Diff:          diff,
		Continuous:    continuous,
		RequiredUntil: requiredUntil,
		Objects:       objects,
	}
}

func parseDiff(diff string) []diffLine {
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	result := make([]diffLine, 0, len(lines))
	for _, line := range lines {
		class := "context"
		switch {
		case strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++"):
			class = "added"
		case strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---"):
			class = "removed"
		case strings.HasPrefix(line, "@@"):
			class = "hunk"
		}
		result = append(result, diffLine{Class: class, Text: line})
	}
	return result
}

func formatIDNA(raw string) string {
	if raw == "" {
		return "0"
	}
	if len(raw) <= 18 {
		raw = strings.Repeat("0", 19-len(raw)) + raw
	}
	whole := strings.TrimLeft(raw[:len(raw)-18], "0")
	if whole == "" {
		whole = "0"
	}
	fraction := strings.TrimRight(raw[len(raw)-18:], "0")
	if fraction == "" {
		return whole
	}
	return whole + "." + fraction
}

func short(value string) string {
	if len(value) <= 20 {
		return value
	}
	return value[:10] + "…" + value[len(value)-8:]
}

var standaloneTemplate = template.Must(template.New("standalone").Funcs(template.FuncMap{
	"idna":  formatIDNA,
	"short": short,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Idena x Radicle checkpoint</title>
<style>
:root{--paper:#f4f3ee;--surface:#fbfaf7;--ink:#171915;--muted:#6e7269;--line:#d8d7cf;--green:#1e6a46;--green-soft:#e6f0ea;--red:#9b3f34;--red-soft:#f4e8e5;--mono:"SFMono-Regular","Cascadia Code","Liberation Mono",monospace;--sans:"Avenir Next","Segoe UI",sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.5 var(--sans);overflow-x:hidden}code,pre{font-family:var(--mono)}header{padding:20px 28px;border-bottom:1px solid var(--line);background:var(--surface)}h1{margin:2px 0;font-size:24px}h2{font-size:16px}h3{margin:0;font-size:15px}.muted{color:var(--muted)}main{max-width:1120px;margin:auto;padding:24px}.repo{background:var(--surface);border:1px solid var(--line);margin-bottom:18px;padding:18px;min-width:0}.repo-head{display:flex;justify-content:space-between;gap:16px;align-items:baseline}.pr{border-top:1px solid var(--line);margin-top:14px;padding-top:14px;min-width:0}.pr summary{cursor:pointer}.pr>.muted{overflow-wrap:anywhere}.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:0;border:1px solid var(--line);margin:14px 0}.grid div{padding:9px 11px;min-width:0;border-right:1px solid var(--line)}.grid div:last-child{border-right:0}.grid dt{color:var(--muted);font-size:10px;text-transform:uppercase}.grid dd{margin:2px 0 0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font:11px var(--mono)}.badge{display:inline-block;padding:2px 7px;background:var(--green-soft);color:var(--green);font-size:11px}.badge.open{background:#eee;color:var(--muted)}.diff{max-height:480px;overflow:auto;background:#171a17;color:#d7ddd5;padding:12px;white-space:pre-wrap;font-size:11px}.diff span{display:block}.added{background:rgba(57,159,101,.18);color:#bfe2ca}.removed{background:rgba(190,77,60,.18);color:#f0c2bb}.hunk{color:#8fb4c6}.table-scroll{display:block;max-width:100%;overflow-x:auto}.ballots{border-collapse:collapse;width:100%;font-size:11px}.ballots th,.ballots td{text-align:left;border-bottom:1px solid var(--line);padding:7px}.approve{color:var(--green)}.reject{color:var(--red)}.proof{margin:8px 0;color:var(--muted);overflow-wrap:anywhere}.availability{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted)}.digest{font-size:10px;color:var(--muted);overflow-wrap:anywhere}.empty{padding:40px;text-align:center;color:var(--muted)}@media(max-width:760px){main{padding:12px}.repo{padding:12px}.grid{grid-template-columns:1fr 1fr}.grid div:nth-child(2){border-right:0}.repo-head{align-items:flex-start;flex-direction:column}.ballots{min-width:560px}}
</style>
</head>
<body>
<header>
<div class="muted">Content-addressed checkpoint preview</div>
<h1>Idena × Radicle</h1>
<div>Epoch {{.Checkpoint.Checkpoint.Epoch}} · block {{.Checkpoint.Checkpoint.Height}} · <code>{{short .Checkpoint.Checkpoint.Hash}}</code></div>
<div class="proof">Policy {{.Checkpoint.ReducerPolicy}}</div>
<div class="proof">Input {{.Checkpoint.InputDigest}}</div>
</header>
<main>
{{if not .Repositories}}<div class="empty">No canonical repositories in this checkpoint.</div>{{end}}
{{range .Repositories}}
<section class="repo">
<div class="repo-head"><div><h2>{{.Repository}}</h2><div class="muted">Canonical head <code>{{short .CanonicalHead}}</code>{{if .WinnerRevision}} · winning revision <code>{{short .WinnerRevision}}</code>{{end}}</div></div>
{{if .Deleted}}<span class="badge">Deleted; prune after epoch {{.PruneAfter}}</span>{{else}}<span class="badge">Active</span>{{end}}</div>
{{if not .PRs}}<p class="muted">No public pull requests in this checkpoint.</p>{{end}}
{{range .PRs}}
<details class="pr" open>
<summary><h3>{{.Title}}</h3></summary>
<div class="muted"><code>{{.PR}}</code> · revision <code>{{short .Revision}}</code></div>
<div class="grid">
<div><dt>Radicle author</dt><dd>{{.Author}}</dd></div>
<div><dt>Idena author</dt><dd>{{.IdenaAuthor}}</dd></div>
<div><dt>Base</dt><dd>{{short .Base}}</dd></div>
<div><dt>Head</dt><dd>{{short .Head}}</dd></div>
</div>
<div><span class="badge {{if not .Eligible}}open{{end}}">{{.Reason}}</span></div>
<p>Voters: {{.UniqueVoters}} · approvals: {{.ApprovalVoters}} · identity-count majority (informational):
<strong>{{.IdentityMajority}}</strong> · combined stake: {{idna .CombinedStake}} iDNA · approval weight majority:
<strong>{{.StakeMajority}}</strong></p>
{{if .Ballots}}<div class="table-scroll"><table class="ballots"><thead><tr><th>Identity</th><th>Choice</th><th>Stake</th><th>Weight</th><th>IAVL</th></tr></thead><tbody>
{{range .Ballots}}<tr><td><code title="{{.Voter}}">{{short .Voter}}</code></td><td class="{{.Decision}}">{{.Decision}}</td><td>{{idna .Stake}}</td><td><code>{{.Weight}}</code></td><td>verified</td></tr>{{end}}
</tbody></table></div>{{else}}<p class="muted">No ballots.</p>{{end}}
<p class="availability"><span>Action: {{if .Availability.Action}}available{{else}}missing{{end}}</span><span>Bundle: {{if .Availability.Bundle}}available{{else}}missing{{end}}</span><span>Diff: {{if .Availability.Diff}}available{{else}}missing{{end}}</span><span>Minimum lease: epoch {{.Availability.RequiredUntil}}</span></p>
<details><summary>Exact diff</summary>
{{if .DiffError}}<p class="muted">{{.DiffError}}</p>{{else}}<pre class="diff">{{range .Diff}}<span class="{{.Class}}">{{.Text}}</span>
{{end}}</pre>{{end}}
</details>
</details>
{{end}}
</section>
{{end}}
</main>
</body>
</html>`))
