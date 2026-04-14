# Memory Files

This directory stores persistent memory files for Mnemosyne.

Each file has YAML frontmatter with:
- `name`: Memory identifier
- `description`: One-line summary (used for retrieval matching)
- `type`: One of `user`, `feedback`, `project`, `reference`

Files are human-readable markdown, git-trackable, and grep-able.
