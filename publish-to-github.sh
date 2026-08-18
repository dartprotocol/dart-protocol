#!/usr/bin/env bash
#
# publish-to-github.sh — stage exactly what belongs in the public repo and
# commit it, ready to push to a new GitHub repository.
#
# Usage:
#   ./publish-to-github.sh                          # commit locally, print push steps
#   ./publish-to-github.sh https://github.com/USER/REPO.git   # commit AND push
#
# What is included: the protocol source (TypeScript/Go/Rust), codec, docs,
# website HTML/CSS, tests and benchmark. What is excluded: node_modules,
# compiled output, binaries, the 89MB desktop installers and the server's
# private identity key (dart_server.key) — see .gitignore.
#
set -euo pipefail

cd "$(dirname "$0")"

echo "==> Dart Protocol → GitHub publish"

# 1. The Rust tree ships with its own nested .git (used for local history).
#    A nested .git would make git treat rust/ as an embedded repo and refuse
#    to track its contents. Remove it so the Rust source is part of this repo.
if [ -d rust/.git ]; then
  echo "==> Removing nested rust/.git so the Rust source is tracked by the root repo..."
  rm -rf rust/.git
fi

# 2. Initialize the root repository if it does not exist yet.
if [ ! -d .git ]; then
  echo "==> Initializing git repository (branch: main)..."
  git init -b main
fi

# 3. Make sure a .gitignore exists and hides the heavy/secrets.
if [ ! -f .gitignore ]; then
  echo "ERROR: .gitignore missing. Aborting to avoid committing binaries/secrets."
  exit 1
fi

# 4. Stage everything the gitignore allows.
git add -A

# 5. Sanity checks.
echo
echo "==== Staged paths ($(git diff --cached --name-only | wc -l | tr -d ' ') files) ===="
git status --short | sed 's/^/  /' | head -80
echo "  ..."

# Warn about accidentally-large files that should not be committed.
echo
echo "==== Files larger than 5 MB staged (should be NONE) ===="
large=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  [ -f "$f" ] || continue
  if [ "$(stat -c%s "$f" 2>/dev/null || stat -f%z "$f")" -gt 5242880 ]; then
    echo "  ⚠ $f"
    large=1
  fi
done < <(git diff --cached --name-only)
[ "$large" -eq 0 ] && echo "  (none — good)"

# 6. Commit.
if git diff --cached --quiet; then
  echo
  echo "==> Nothing new to commit."
else
  git commit -m "Dart Protocol: E2EE group-key messaging protocol (TypeScript/Go/Rust)"
  echo
  echo "==> Committed."
fi

# 7. Push or print instructions.
URL="${1:-}"
if [ -n "$URL" ]; then
  git remote remove origin 2>/dev/null || true
  git remote add origin "$URL"
  git push -u origin main
  echo
  echo "==> Pushed to $URL"
else
  echo
  echo "==> Repo is committed locally. Create an empty repository on GitHub, then run:"
  echo
  echo "    git remote add origin https://github.com/<YOUR_USER>/<REPO>.git"
  echo "    git push -u origin main"
  echo
  echo "Tip: name it e.g. 'dart-protocol' and add a short description."
  echo "Note: the live website is hosted separately at dartprotocol.org; the repo"
  echo "keeps the website assets under public/ as part of the published source."
fi
