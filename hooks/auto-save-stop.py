#!/usr/bin/env python3
"""Mnemosyne: Auto-save on session end (Stop hook). Cross-platform stdlib."""
import sys
import json

_ = sys.stdin.read()  # drain stdin; content unused
print(json.dumps({
    "continue": True,
    "additionalContext": "[Mnemosyne Auto-Save] Session ending. If you learned anything new about the user, their projects, or received corrections during this session, save them to memory/ files now before the session closes. Check: (1) Any unsaved user preferences or feedback? (2) Any project decisions not yet recorded? (3) Any corrections that should update lessons-learned.md?"
}))
