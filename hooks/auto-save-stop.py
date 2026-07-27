#!/usr/bin/env python3
"""Mnemosyne: Auto-save on session end (Stop hook). Cross-platform stdlib."""
import sys
import json

_ = sys.stdin.read()  # drain stdin; content unused
print(json.dumps({
    "continue": True,
    "additionalContext": "[Mnemosyne Auto-Save] Session ending. If you learned anything new about the user, their projects, received corrections, or learned something from the work itself during this session, save them to memory/ files now before the session closes. Check: (1) Any unsaved user preferences or feedback? (2) Any project decisions not yet recorded? (3) Any lesson that should update lessons-learned.md -- either a correction you received OR something the work taught (a defect you found, a review finding that exposed a blind spot, an approach that failed)? Filter on whether it would recur, not on who taught it."
}))
