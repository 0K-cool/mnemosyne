#!/usr/bin/env python3
"""Mnemosyne: Save before context compression (PreCompact hook). Cross-platform stdlib."""
import sys
import json

_ = sys.stdin.read()  # drain stdin; content unused
print(json.dumps({
    "continue": True,
    "additionalContext": "[Mnemosyne Pre-Compact] Context compression imminent. Save any unsaved decisions, corrections, or learnings to memory/ files NOW — they may be lost after compression."
}))
