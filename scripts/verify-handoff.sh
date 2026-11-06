#!/bin/sh
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"

verify_tmp=$(mktemp -d "${TMPDIR:-/tmp}/idena-forge-handoff-verify.XXXXXX")
trap 'find "$verify_tmp" -xdev -depth -delete' EXIT HUP INT TERM
mkdir -p "$verify_tmp/go-build" "$verify_tmp/go-tmp"

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

require_hash() {
  path=$1
  expected=$2
  actual=$(sha256_file "$path")
  if [ "$actual" != "$expected" ]; then
    printf 'SHA-256 mismatch for %s: got %s, want %s\n' "$path" "$actual" "$expected" >&2
    exit 1
  fi
}

require_hash node-extension/idena-go-checkpoint-proof-security-candidate.patch \
  aebf20840bdf5a705794c2dac25eaf01e37a50a8e5fa66754e4becba4ac13bb0
require_hash node-extension/build-evidence.json \
  dfe8fc94eb8fe7e93f8808b7e9392ef4e81b1ae1b0ec9ffedecbc14e7a509dd2
require_hash trial/trial-policy-v3.json \
  a45f83d54f64944132b6dff23eafd091a42a9cc2f924ab863451de9855ede006

jq empty node-extension/build-evidence.json trial/trial-policy-v3.json

if find . -path './.git' -prune -o -type l -print | grep -q .; then
  printf '%s\n' 'symlinks are not allowed in the handoff tree' >&2
  exit 1
fi

if find . -path './.git' -prune -o -type f -size +1M -print | grep -q .; then
  printf '%s\n' 'files larger than 1 MiB are not allowed in the handoff tree' >&2
  exit 1
fi

if find . -path './.git' -prune -o -type f \( \
  -name '.DS_Store' -o -name '*.log' -o -name '*.tar' -o -name '*.tar.gz' -o \
  -name '*.gz' -o -name '*.zip' -o -name '*.7z' -o -name '*.rar' -o \
  -name '*.xz' -o -name '*.zst' -o -name '*.bundle' -o -name '*.diff' -o \
  -name '*.mbox' -o -name '*.har' -o -name '*.sqlite' -o -name '*.sqlite3' -o \
  -name '*.db' -o -name '*.jpg' -o -name '*.jpeg' -o -name '*.png' -o \
  -name '*.gif' -o -name '*.webp' -o -name '*.heic' -o \
  -name '*.pem' -o -name '*.key' -o -name '*.p12' -o \
  -name '*.pfx' -o -name '*.kdbx' -o -name 'api.key' -o -name '.env' -o \
  -name '.env.*' -o -name '*repository-action*.json' -o -name '*signed-action*.json' \) \
  -print | grep -q .; then
  printf '%s\n' 'forbidden generated or credential-like file found' >&2
  exit 1
fi

privacy_pattern='/Users/[[:alnum:]_.-]+/|/home/[[:alnum:]_.-]+/\.ssh/|/root/|/var/lib/idena|Documents/Codex|hetzner|fod-session|BEGIN (OPENSSH |RSA |EC |DSA )?PRIVATE KEY|BEGIN PGP PRIVATE KEY BLOCK|BEGIN SSH SIGNATURE|U1NIU0lH[A-Za-z0-9+/=]{20,}|A(KIA|SIA)[0-9A-Z]{16}|gh[opusr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,}'
if git grep -nEI "$privacy_pattern" -- . \
  ':(exclude)scripts/verify-handoff.sh' \
  ':(exclude)scripts/secret-scan.sh'; then
  printf '%s\n' 'private-path or secret-like content found' >&2
  exit 1
fi

if find . -path './.git' -prune -o -type f -exec file {} + | grep -E 'ELF|Mach-O|PE32'; then
  printf '%s\n' 'compiled executable found in handoff tree' >&2
  exit 1
fi

remotes=$(git remote)
case "$remotes" in
  '') ;;
  origin)
    remote_url=$(git remote get-url origin)
    case "$remote_url" in
      https://github.com/ubiubi18/idena-git-forge|\
      https://github.com/ubiubi18/idena-git-forge.git) ;;
      *)
        printf 'unexpected origin URL: %s\n' "$remote_url" >&2
        exit 1
        ;;
    esac
    ;;
  *)
    printf 'unexpected remotes: %s\n' "$remotes" >&2
    exit 1
    ;;
esac
test "$(git rev-list --count HEAD)" = 1
git diff --exit-code
git diff --cached --exit-code
test -x scripts/secret-scan.sh
test -x scripts/install-git-hooks.sh
test -x .githooks/pre-commit
test -x .githooks/pre-push
./scripts/secret-scan.sh --history

GOCACHE="$verify_tmp/go-build" GOTMPDIR="$verify_tmp/go-tmp" go test ./...

printf '%s\n' 'handoff verification passed'
