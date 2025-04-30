#!/bin/bash
set -e

HOOK_SRC=".hooks/pre-commit"
HOOK_DEST=".git/hooks/pre-commit"

if [ ! -f "$HOOK_SRC" ]; then
  echo "❌ Hook file $HOOK_SRC does not exist. Aborting."
  exit 1
fi

echo "🔗 Linking $HOOK_DEST to $HOOK_SRC..."
ln -s "$(pwd)/.hooks/pre-commit" .git/hooks/pre-commit
chmod +x $HOOK_SRC
echo "✅ Git pre-commit hook installed."