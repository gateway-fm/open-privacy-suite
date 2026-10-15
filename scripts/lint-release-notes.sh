#!/usr/bin/env bash
#
# Lint a GitHub release body against the canonical Open Privacy Suite
# release-notes structure (see .claude/skills/release/SKILL.md §3).
#
# Reads the body from the first argument (a file path, or "-" for stdin),
# or from stdin when no argument is given. Exits non-zero and names the
# missing section(s) if any required header is absent. It checks header
# PRESENCE only, not content — so a release authored without the /release
# skill still passes as long as it keeps the standard section headers.
#
# Required headers are matched as whole "##" header LINES, not arbitrary
# substrings, so prose such as "No action required on upgrade" cannot
# satisfy the "## ⚠️ Action required on upgrade" requirement. The section
# emoji is not matched, so the check is robust to emoji encoding in the body.
#
# Enforcement is independent of the skill: run in CI on release publish
# (.github/workflows/release-notes-lint.yml), and locally on a draft:
#     scripts/lint-release-notes.sh <notes-file>
#
set -euo pipefail

if [ "${1:-}" != "" ] && [ "${1:-}" != "-" ]; then
  body="$(cat -- "$1")"
else
  body="$(cat)"
fi

# Required sections, in canonical order (kept in sync with the skill's §3).
# Each label is paired with an extended regex matched against a single line.
# The six "##" sections are anchored to a header line; "Full changelog:" is
# validated separately as its own (bold, non-header) line. "## Deprecations"
# is intentionally NOT required — the skill makes it optional (omit-if-none);
# every other §3 section, including "## Incompatibilities / breaking", is
# mandatory ("None." if none).
labels=(
  "## Highlights"
  "## ⚠️ Action required on upgrade"
  "## Incompatibilities / breaking"
  "## Docker images"
  "## Compatible versions"
  "## Verify after deploy"
  "Full changelog: line"
)
patterns=(
  '^##[[:space:]]+Highlights[[:space:]]*$'
  '^##[[:space:]].*Action required on upgrade[[:space:]]*$'
  '^##[[:space:]].*Incompatibilities / breaking[[:space:]]*$'
  '^##[[:space:]]+Docker images[[:space:]]*$'
  '^##[[:space:]]+Compatible versions[[:space:]]*$'
  '^##[[:space:]].*Verify after deploy[[:space:]]*$'
  'Full changelog:'
)

missing=()
for i in "${!labels[@]}"; do
  if ! printf '%s\n' "$body" | grep -Eq "${patterns[$i]}"; then
    missing+=("${labels[$i]}")
  fi
done

if [ "${#missing[@]}" -ne 0 ]; then
  echo "release-notes lint FAILED — missing required section(s):" >&2
  for label in "${missing[@]}"; do
    echo "  - ${label}" >&2
  done
  echo >&2
  echo "See .claude/skills/release/SKILL.md §3 for the canonical release-notes format." >&2
  exit 1
fi

echo "release-notes lint OK — all required sections present."
