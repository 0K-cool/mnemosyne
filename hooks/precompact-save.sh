#!/usr/bin/env bash
# ok-mnemosyne: Save before context compression (PreCompact hook)
INPUT=$(cat)
cat <<'EOF'
{"continue": true, "additionalContext": "[Mnemosyne Pre-Compact] Context compression imminent. Save any unsaved decisions, corrections, or learnings to memory/ files NOW — they may be lost after compression."}
EOF
