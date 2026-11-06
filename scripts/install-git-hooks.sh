#!/bin/sh
set -eu

repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
git -C "$repo" config core.hooksPath .githooks

printf '%s\n' 'Git privacy hooks enabled from .githooks'
