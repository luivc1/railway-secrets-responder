#!/usr/bin/env bash
# =====================================================================
#  install.sh  -  one-shot installer for railway-secrets-responder
#
#  ./install.sh --target claude          # skills -> ~/.claude/skills
#  ./install.sh --target hermes          # skills -> ~/.hermes/skills
#  ./install.sh --dest /path/to/skills   # any Agent Skills loader / project
#  ./install.sh --uninstall [--target X | --dest DIR]
#
#  Always installs the toolkit (scripts, advisories) to ~/.railway-secrets-responder
#  (override with RSR_HOME=...). Skills look there automatically.
#
#  Claude Code users can instead install as a plugin (adds slash commands,
#  the rsr-verifier agent and the safety hook):
#    /plugin marketplace add <this folder or GitHub repo>
#    /plugin install railway-secrets-responder@railway-secrets-responder
# =====================================================================
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
RSR_HOME="${RSR_HOME:-$HOME/.railway-secrets-responder}"
DEST=""; UNINSTALL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --target)
      case "$2" in
        claude) DEST="$HOME/.claude/skills";;
        hermes) DEST="$HOME/.hermes/skills";;
        *) echo "Unknown target '$2' (use claude, hermes, or --dest DIR)"; exit 3;;
      esac; shift 2;;
    --dest) DEST="$2"; shift 2;;
    --uninstall) UNINSTALL=1; shift;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^#//'; exit 0;;
    *) echo "Unknown option: $1"; exit 3;;
  esac
done

if [ "$UNINSTALL" -eq 1 ]; then
  if [ -n "$DEST" ]; then
    for s in "$SRC"/skills/rsr-*; do rm -rf "$DEST/$(basename "$s")"; done
    echo "Removed rsr-* skills from $DEST"
  fi
  rm -rf "$RSR_HOME"; echo "Removed $RSR_HOME"
  exit 0
fi

mkdir -p "$RSR_HOME"
cp -R "$SRC/scripts" "$SRC/advisories" "$SRC/AGENTS.md" "$RSR_HOME/"
chmod +x "$RSR_HOME"/scripts/*.py
echo "Toolkit installed: $RSR_HOME"

if [ -n "$DEST" ]; then
  mkdir -p "$DEST"
  for s in "$SRC"/skills/rsr-*; do
    rm -rf "$DEST/$(basename "$s")"
    cp -R "$s" "$DEST/"
  done
  echo "Skills installed: $DEST ($(ls -d "$SRC"/skills/rsr-* | wc -l | tr -d ' ') skills)"
fi

echo
echo "Quick start:  python3 $RSR_HOME/scripts/railway-audit.py --api -o railway-report   (token from RAILWAY_API_TOKEN or a hidden prompt)"
echo "Ask your agent:  \"Which Railway secrets do I need to rotate?\"  /  \"¿Qué llaves de Railway tengo que rotar?\""
