#!/bin/sh
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

mode=${1:---history}
case "$mode" in
  --staged|--history) ;;
  *)
    printf 'usage: %s [--staged|--history]\n' "$0" >&2
    exit 2
    ;;
esac

scan_tmp=$(mktemp -d "${TMPDIR:-/tmp}/idena-forge-secret-scan.XXXXXX")
trap 'find "$scan_tmp" -xdev -depth -delete' EXIT HUP INT TERM

content_pattern='/Users/[^/[:space:]]+/|/home/[^/[:space:]]+/\.ssh/|/root/|/var/lib/idena|Documents/Codex|hetzner|fod-session|codex-accidental-idena-datadir|BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|BEGIN SSH SIGNATURE|U1NIU0lH[A-Za-z0-9+/=]{20,}|A(KIA|SIA)[0-9A-Z]{16}|gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}|(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3})'
email_pattern='[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}'
allowed_email_pattern='@(example\.invalid|example\.com|users\.noreply\.github\.com)$'
linkable_pattern='did:key:z[1-9A-HJ-NP-Za-km-z]{20,}|rad:z[1-9A-HJ-NP-Za-km-z]{20,}|ssh-ed25519 [A-Za-z0-9+/=]{40,}|0x[0-9A-Fa-f]{64,}|0x[0-9A-Fa-f]{40}|baf[a-z2-7]{20,}|z[1-9A-HJ-NP-Za-km-z]{40,}'
allowed_linkable_values='did:key:z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP
rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5
z6Mko9uYxDPk2BetRRziLz1xHN8nR5zQWdNjytKNDPcygHJP
z3gqcJUoA1n9HaHKufZs5FCSGazv5
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE6Ul/D+P0I/Hl1JVOWGS8Z589us9FqKQXWv8OMOpKCh
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIFHIt5xxbFOdI3/Mirn98QVzuVYdmSVKSzWxMCmqd8o
0x1111111111111111111111111111111111111111
0x2222222222222222222222222222222222222222
0x840e092e31e9656fF15E541505039ed77585338E
0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
0x1111111111111111111111111111111111111111111111111111111111111111
0x2222222222222222222222222222222222222222222222222222222222222222
0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku'
printf '%s\n' "$allowed_linkable_values" >"$scan_tmp/allowed-linkable-values"

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

protected_hashes='node-extension/idena-go-checkpoint-proof-security-candidate.patch aebf20840bdf5a705794c2dac25eaf01e37a50a8e5fa66754e4becba4ac13bb0
node-extension/build-evidence.json dfe8fc94eb8fe7e93f8808b7e9392ef4e81b1ae1b0ec9ffedecbc14e7a509dd2
trial/trial-policy-v3.json a45f83d54f64944132b6dff23eafd091a42a9cc2f924ab863451de9855ede006'

check_protected_hashes() {
  revision=$1
  printf '%s\n' "$protected_hashes" | while IFS=' ' read -r path expected; do
    if [ "$revision" = : ]; then
      object=:$path
    else
      object=$revision:$path
    fi
    if ! git cat-file -e "$object" 2>/dev/null; then
      printf 'protected handoff artifact missing: %s\n' "$path" >&2
      exit 1
    fi
    actual=$(git show "$object" | sha256_stream)
    if [ "$actual" != "$expected" ]; then
      printf 'protected handoff artifact changed: %s\n' "$path" >&2
      exit 1
    fi
  done
}

check_path() {
  path=$1
  case "$path" in
    .env|.env.*|*/.env|*/.env.*|*.pem|*.key|*.p12|*.pfx|*.kdbx|\
    id_ed25519*|*/id_ed25519*|id_rsa*|*/id_rsa*|\
    *.log|*.tar|*.tar.gz|*.gz|*.zip|*.7z|*.rar|*.xz|*.zst|\
    *.bundle|*.diff|*.mbox|*.har|*.sqlite|*.sqlite3|*.db|\
    *.jpg|*.jpeg|*.png|*.gif|*.webp|*.heic|\
    .DS_Store|*/.DS_Store|*receipt*.json|\
    *deployment-plan*.json|checkpoint-history.json|*/checkpoint-history.json|\
    checkpoint-latest.json|*/checkpoint-latest.json|trials/*|*/trials/*|\
    *repository-action*.json|*signed-action*.json)
      printf 'forbidden private or generated path: %s\n' "$path" >&2
      return 1
      ;;
  esac
}

check_blob() {
  path=$1
  blob=$2

  if file "$blob" | grep -Eq 'ELF|Mach-O|PE32'; then
    printf 'compiled executable is forbidden: %s\n' "$path" >&2
    return 1
  fi

  case "$path" in
    scripts/secret-scan.sh|scripts/verify-handoff.sh) return 0 ;;
  esac

  if LC_ALL=C grep -a -nE "$content_pattern" "$blob" >"$scan_tmp/content-findings"; then
    printf 'private path, network, or credential-shaped value in %s:\n' "$path" >&2
    sed -n '1,20p' "$scan_tmp/content-findings" >&2
    return 1
  fi

  if LC_ALL=C grep -a -Eio "$email_pattern" "$blob" | \
    LC_ALL=C grep -Eiv "$allowed_email_pattern" >"$scan_tmp/email-findings"; then
    printf 'non-project email-like value in %s:\n' "$path" >&2
    sed -n '1,20p' "$scan_tmp/email-findings" >&2
    return 1
  fi

  if LC_ALL=C grep -a -Eo "$linkable_pattern" "$blob" | \
    LC_ALL=C sort -u | \
    LC_ALL=C grep -Fvx -f "$scan_tmp/allowed-linkable-values" >"$scan_tmp/linkable-findings"; then
    printf 'unreviewed identity-linked public value in %s:\n' "$path" >&2
    sed -n '1,20p' "$scan_tmp/linkable-findings" >&2
    return 1
  fi
}

scan_revision() {
  revision=$1
  git ls-tree -r --name-only "$revision" >"$scan_tmp/paths"
  while IFS= read -r path; do
    check_path "$path"
    git show "$revision:$path" >"$scan_tmp/blob"
    check_blob "$path" "$scan_tmp/blob"
  done <"$scan_tmp/paths"
}

scan_staged() {
  check_protected_hashes :
  git diff --cached --name-only --diff-filter=ACMR >"$scan_tmp/paths"
  while IFS= read -r path; do
    check_path "$path"
    git show ":$path" >"$scan_tmp/blob"
    check_blob "$path" "$scan_tmp/blob"
  done <"$scan_tmp/paths"

  git var GIT_AUTHOR_IDENT >"$scan_tmp/identity"
  if LC_ALL=C grep -Eio "$email_pattern" "$scan_tmp/identity" | \
    LC_ALL=C grep -Eiv "$allowed_email_pattern" >"$scan_tmp/email-findings"; then
    printf '%s\n' 'commit author email must use a project or GitHub no-reply domain' >&2
    exit 1
  fi
}

scan_history() {
  check_protected_hashes HEAD
  git rev-list --all >"$scan_tmp/revisions"
  while IFS= read -r revision; do
    scan_revision "$revision"
  done <"$scan_tmp/revisions"

  git log --all --format='%ae%n%ce' >"$scan_tmp/identities"
  if LC_ALL=C grep -Eio "$email_pattern" "$scan_tmp/identities" | \
    LC_ALL=C grep -Eiv "$allowed_email_pattern" >"$scan_tmp/email-findings"; then
    printf '%s\n' 'reachable commit metadata contains a non-project email' >&2
    sed -n '1,20p' "$scan_tmp/email-findings" >&2
    exit 1
  fi
}

if [ "$mode" = --staged ]; then
  scan_staged
else
  scan_history
fi

if command -v gitleaks >/dev/null 2>&1; then
  if [ "$mode" = --staged ]; then
    gitleaks git --staged --redact --no-banner --log-level error .
  else
    gitleaks git --redact --no-banner --log-level error .
  fi
fi

printf 'secret and privacy scan passed (%s)\n' "$mode"
