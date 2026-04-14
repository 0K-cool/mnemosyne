---
name: gotcha
description: |
  Capture mistakes, gotchas, and lessons learned — either for a specific skill or as a general lesson.
  Auto-appends to the target skill's ## Gotchas section with a timestamp, or falls back to
  memory/lessons-learned.md for non-skill issues. Use this skill whenever the user says "/gotcha",
  "log gotcha", "add gotcha", "remember this mistake", "note this for next time", or wants to
  record any lesson learned, correction, or edge case discovered during work. Even if the user
  just says something like "we should remember that" or "don't forget this next time" after
  hitting an issue — this is the right skill.
---

# Gotcha — Skill Self-Improvement Logger

The highest-signal content in any skill is its Gotchas section. Every time something goes wrong
or an edge case surfaces, capturing it at the source means the skill gets smarter for next time.
This turns reactive debugging into proactive improvement — the skill learns from its own mistakes
without anyone having to remember to update documentation later.

## How It Works

### Step 1: Parse the Arguments

The user types `/gotcha <args>`. Extract two pieces:
- **First word** = candidate skill name
- **Everything after** = the gotcha description

If there's only one word or a quoted string, treat the entire input as the description (no skill target).

### Step 2: Find the Right Target

Check whether a skill directory exists at either of these paths (relative to the project root):
1. `skills/<candidate>/SKILL.md`
2. `skills/<candidate>/skill.md`

**If the skill exists** — that SKILL.md is the target. The gotcha belongs with the skill it's about,
so it's available in context every time that skill loads.

**If the skill doesn't exist** — the first word wasn't a skill name, so it's part of the description.
The target becomes `memory/lessons-learned.md` — the general catch-all for lessons that don't belong
to any specific skill. Create this file with a `# Lessons Learned` header if it doesn't exist yet.

The lessons-learned path: Use the project's `memory/lessons-learned.md` file (relative to the memory directory).

### Step 3: Append the Gotcha

**Read** the target file first (this is required before editing).

**For skill-targeted gotchas:**
Look for an existing `## Gotchas` section. If it exists, append the new entry at the end of that section.
If it doesn't exist, add `## Gotchas` as the last section in the file, then append the entry.

**For general lessons-learned:**
Append the entry at the end of the file.

**Entry format:**
```markdown
- **[YYYY-MM-DD]** <description>
```

Use today's actual date (not a placeholder).

### Step 4: Confirm

Keep it brief — the user is in the middle of something and just wants to know it's logged:

```
Gotcha logged to skills/<skill-name>/SKILL.md:
- [2026-03-26] <description>
```

Or for general:
```
Lesson logged to memory/lessons-learned.md:
- [2026-03-26] <description>
```

## Examples

```
/gotcha setup-rag Ollama must be running before health check or Step 1 always fails
→ Appends to skills/setup-rag/SKILL.md ## Gotchas

/gotcha mine-session --dry-run flag must come after path argument or it is ignored
→ Appends to skills/mine-session/SKILL.md ## Gotchas

/gotcha Always check that memory/ directory exists before writing files
→ "Always" isn't a skill name → Appends to memory/lessons-learned.md

/gotcha "RAG config path must be absolute — relative paths cause silent failures"
→ Quoted string, no skill name → Appends to memory/lessons-learned.md
```
