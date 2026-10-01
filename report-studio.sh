#!/bin/sh
set -eu

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'Node.js was not found. Install Node.js 22.12 or newer and reopen your terminal.' \
    'First-time setup in this checkout: npm ci --include=dev --ignore-scripts' >&2
  exit 1
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec node "$root/scripts/start-studio.mjs" "$@"
