const state = { data: null, selectedRepo: 0, selectedPR: 0 };

const elements = {
  headline: document.querySelector("#headline"),
  repoCount: document.querySelector("#repo-count"),
  repoList: document.querySelector("#repo-list"),
  empty: document.querySelector("#empty-state"),
  view: document.querySelector("#pr-view"),
  breadcrumb: document.querySelector("#breadcrumb"),
  title: document.querySelector("#pr-title"),
  revision: document.querySelector("#revision"),
  outcome: document.querySelector("#outcome"),
  author: document.querySelector("#author"),
  idenaAuthor: document.querySelector("#idena-author"),
  base: document.querySelector("#base"),
  head: document.querySelector("#head"),
  checkpoint: document.querySelector("#checkpoint"),
  diff: document.querySelector("#diff"),
  ballots: document.querySelector("#ballots"),
  ballotSummary: document.querySelector("#ballot-summary"),
  repositoryState: document.querySelector("#repository-state"),
  voters: document.querySelector("#voters"),
  approvals: document.querySelector("#approvals"),
  identityMajority: document.querySelector("#identity-majority"),
  combinedStake: document.querySelector("#combined-stake"),
  approvalWeight: document.querySelector("#approval-weight"),
  rejectionWeight: document.querySelector("#rejection-weight"),
  stakeMajority: document.querySelector("#stake-majority"),
  pruneAfter: document.querySelector("#prune-after"),
  availability: document.querySelector("#availability"),
  reason: document.querySelector("#reason"),
  inputDigest: document.querySelector("#input-digest"),
};

async function load() {
  const response = await fetch("/api/checkpoint", { cache: "no-store" });
  if (!response.ok) throw new Error(`checkpoint request failed: ${response.status}`);
  state.data = await response.json();
  elements.headline.textContent = `Epoch ${state.data.checkpoint.epoch} | block ${state.data.checkpoint.height}`;
  renderRepoList();
  const first = firstPR();
  if (first) selectPR(first.repoIndex, first.prIndex);
}

function firstPR() {
  for (let repoIndex = 0; repoIndex < state.data.repositories.length; repoIndex += 1) {
    if (state.data.repositories[repoIndex].prs?.length) {
      return { repoIndex, prIndex: 0 };
    }
  }
  return null;
}

function renderRepoList() {
  elements.repoCount.textContent = state.data.repositories.length;
  elements.repoList.replaceChildren();
  state.data.repositories.forEach((repo, repoIndex) => {
    const group = document.createElement("section");
    group.className = "repo-group";
    const heading = document.createElement("div");
    heading.className = "repo-name";
    heading.textContent = repo.repository;
    group.append(heading);
    (repo.prs || []).forEach((pr, prIndex) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "pr-link";
      button.dataset.selected = String(repoIndex === state.selectedRepo && prIndex === state.selectedPR);
      const marker = document.createElement("span");
      marker.className = `marker ${repo.winner === pr.pr ? "winner" : pr.eligible ? "eligible" : "open"}`;
      const label = document.createElement("span");
      label.className = "pr-link-copy";
      const title = document.createElement("strong");
      title.textContent = pr.title;
      const revision = document.createElement("small");
      revision.textContent = `${pr.pr} | ${shortHash(pr.revision)}`;
      label.append(title, revision);
      button.append(marker, label);
      button.addEventListener("click", () => selectPR(repoIndex, prIndex));
      group.append(button);
    });
    elements.repoList.append(group);
  });
}

function selectPR(repoIndex, prIndex) {
  const repo = state.data.repositories[repoIndex];
  const pr = repo?.prs?.[prIndex];
  if (!pr) return;
  state.selectedRepo = repoIndex;
  state.selectedPR = prIndex;
  renderRepoList();
  elements.empty.hidden = true;
  elements.view.hidden = false;
  elements.breadcrumb.textContent = repo.repository;
  elements.title.textContent = pr.title;
  elements.revision.textContent = pr.revision;
  elements.author.textContent = pr.radicleAuthor || pr.author || "-";
  elements.idenaAuthor.textContent = pr.idenaAuthor ? `Idena ${shortAddress(pr.idenaAuthor)}` : "";
  elements.base.textContent = pr.base;
  elements.head.textContent = pr.head;
  elements.checkpoint.textContent = `#${state.data.checkpoint.height} | epoch ${state.data.checkpoint.epoch}`;
  const isWinner = repo.winner === pr.pr && repo.winnerRevision === pr.revision;
  elements.outcome.textContent = isWinner
    ? repo.deleted ? "Deletion decision" : "Canonical merge"
    : pr.eligible ? "Eligible" : "Open";
  elements.outcome.dataset.state = isWinner ? "winner" : pr.eligible ? "eligible" : "open";
  const approvalVoters = pr.approvalVoters ?? (pr.ballots || []).filter((ballot) => ballot.decision === "approve").length;
  const identityMajority = pr.identityMajority ?? (approvalVoters * 2 > pr.uniqueVoters);
  elements.repositoryState.textContent = repo.deleted ? "Deleted" : "Active";
  elements.voters.textContent = String(pr.uniqueVoters);
  elements.approvals.textContent = String(approvalVoters);
  elements.identityMajority.textContent = identityMajority ? "Yes" : "No";
  elements.combinedStake.textContent = `${formatIDNA(pr.combinedStake)} iDNA`;
  elements.approvalWeight.textContent = pr.approvalWeight;
  elements.rejectionWeight.textContent = pr.rejectionWeight;
  elements.stakeMajority.textContent = pr.stakeMajority ? "Yes" : "No";
  elements.pruneAfter.textContent = repo.deleted ? `Epoch ${repo.pruneAfterEpoch}` : "-";
  elements.reason.textContent = pr.reason;
  elements.inputDigest.textContent = state.data.inputDigest;
  elements.ballotSummary.textContent = `${pr.uniqueVoters} voters | ${approvalVoters} approvals | ${formatIDNA(pr.combinedStake)} iDNA combined`;
  renderBallots(pr.ballots || []);
  renderAvailability(pr.availability);
  loadDiff(pr.diffCid);
}

function renderBallots(ballots) {
  elements.ballots.replaceChildren();
  ballots.forEach((ballot) => {
    const row = document.createElement("div");
    row.className = "table-row";
    const identity = document.createElement("span");
    identity.className = "ballot-identity";
    identity.title = ballot.voter;
    const address = document.createElement("span");
    address.textContent = shortAddress(ballot.voter);
    identity.append(address);
    const proof = document.createElement("small");
    proof.textContent = "IAVL verified";
    identity.append(proof);
    const choice = document.createElement("span");
    choice.className = `choice ${ballot.decision}`;
    choice.textContent = ballot.decision;
    const stake = document.createElement("span");
    stake.textContent = `${formatIDNA(ballot.stake)} iDNA`;
    const weight = document.createElement("span");
    weight.className = "mono";
    weight.textContent = ballot.weight;
    row.append(identity, choice, stake, weight);
    elements.ballots.append(row);
  });
}

function renderAvailability(availability) {
  elements.availability.replaceChildren();
  const objects = availability?.objects || {};
  const labels = { action: "Idena anchor", bundle: "Radicle storage bundle", diff: "Patch diff" };
  ["action", "bundle", "diff"].forEach((name) => {
    const row = document.createElement("div");
    row.className = "availability-row";
    const label = document.createElement("span");
    label.textContent = labels[name];
    const value = document.createElement("span");
    value.className = availability?.[name] ? "available" : "unavailable";
    value.textContent = availability?.[name] ? "Available" : "Missing";
    row.append(label, value);
    elements.availability.append(row);
  });
  const lease = document.createElement("p");
  lease.className = "lease";
  lease.textContent = availability?.continuous
    ? `Continuous while active; minimum lease through epoch ${availability.requiredUntil ?? "-"}`
    : `Required through epoch ${availability?.requiredUntil ?? "-"}`;
  elements.availability.append(lease);
}

async function loadDiff(contentCID) {
  elements.diff.textContent = "Loading diff...";
  if (!contentCID) {
    elements.diff.textContent = "Diff CID unavailable.";
    return;
  }
  const response = await fetch(`/api/content/${encodeURIComponent(contentCID)}`);
  if (!response.ok) {
    elements.diff.textContent = "Diff content is not available at this replica.";
    return;
  }
  renderDiff(await response.text());
}

function renderDiff(diff) {
  elements.diff.replaceChildren();
  diff.split("\n").forEach((line) => {
    const span = document.createElement("span");
    span.className = line.startsWith("+") && !line.startsWith("+++") ? "added"
      : line.startsWith("-") && !line.startsWith("---") ? "removed"
      : line.startsWith("@@") ? "hunk" : "context";
    span.textContent = `${line}\n`;
    elements.diff.append(span);
  });
}

function shortAddress(value) {
  return value.length > 16 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value;
}

function shortHash(value) {
  return value.length > 18 ? `${value.slice(0, 10)}...${value.slice(-6)}` : value;
}

function formatIDNA(raw) {
  if (!raw) return "0";
  const padded = raw.padStart(19, "0");
  const whole = padded.slice(0, -18).replace(/^0+(?=\d)/, "");
  const fraction = padded.slice(-18).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction.slice(0, 4)}` : whole;
}

load().catch((error) => {
  elements.headline.textContent = error.message;
  elements.empty.querySelector("h1").textContent = "Checkpoint unavailable";
  elements.empty.querySelector("p").textContent = "The local preview server could not load its checkpoint data.";
});
