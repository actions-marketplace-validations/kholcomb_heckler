#!/usr/bin/env bash
# heckler-scan.sh — Zero-dependency shell fallback for detecting dangerous invisible Unicode.
# Requires GNU grep with PCRE support (grep -P). macOS users: brew install grep
# Usage: ./heckler-scan.sh [directory]    (defaults to current dir)
# Exit code 1 if findings detected (CI-friendly)

set -euo pipefail

TARGET="${1:-.}"

# Check for PCRE support
if ! echo "test" | grep -P "test" >/dev/null 2>&1; then
  echo "Error: grep -P (PCRE) not supported. Install GNU grep:"
  echo "  macOS: brew install grep (then use ggrep or add to PATH)"
  echo "  Linux: grep should support -P by default"
  exit 2
fi

PATTERN='[\x{00A0}\x{00AD}\x{061C}\x{180E}\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{2066}-\x{206F}\x{2800}\x{3164}\x{FE00}-\x{FE0F}\x{FEFF}\x{FFF9}-\x{FFFB}\x{FFA0}\x{E0001}\x{E0020}-\x{E007F}\x{E0100}-\x{E01EF}]'

INCLUDES=(
  --include='*.js' --include='*.cjs' --include='*.mjs'
  --include='*.ts' --include='*.jsx' --include='*.tsx'
  --include='*.py' --include='*.rb' --include='*.go' --include='*.rs'
  --include='*.c' --include='*.cpp' --include='*.h' --include='*.java'
  --include='*.cs' --include='*.php' --include='*.sh' --include='*.yaml'
  --include='*.yml' --include='*.json' --include='*.toml' --include='*.xml'
  --include='*.html' --include='*.css' --include='*.sql' --include='*.swift'
  --include='*.kt' --include='*.scala' --include='*.lua' --include='*.md'
)

EXCLUDES=(
  --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git
  --exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=venv
  --exclude-dir=dist --exclude-dir=build --exclude-dir=target
  --exclude-dir=site-packages --exclude-dir=coverage
)

RESULTS=$(grep -rPn "$PATTERN" "${INCLUDES[@]}" "${EXCLUDES[@]}" "$TARGET" 2>/dev/null || true)

if [ -n "$RESULTS" ]; then
  COUNT=$(echo "$RESULTS" | wc -l | tr -d ' ')
  echo ""
  echo "Dangerous invisible Unicode characters detected! ($COUNT occurrence(s))"
  echo ""
  echo "$RESULTS" | head -50
  [ "$COUNT" -gt 50 ] && echo "... and $((COUNT - 50)) more."
  echo ""
  echo "Review with: cat -v <file> or hexdump -C <file>"
  exit 1
else
  echo "No dangerous invisible Unicode characters found."
  exit 0
fi
