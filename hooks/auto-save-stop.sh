#!/usr/bin/env bash
# Mnemosyne: Auto-save on session end (Stop hook)
INPUT=$(cat)
cat <<'EOF'
{"continue": true, "additionalContext": "[Mnemosyne Auto-Save] Session ending. If you learned anything new about the user, their projects, or received corrections during this session, save them to memory/ files now before the session closes. Check: (1) Any unsaved user preferences or feedback? (2) Any project decisions not yet recorded? (3) Any corrections that should update lessons-learned.md?"}
EOF
