"""Mnemosyne v2 — memory-driven hook enforcement.

The `enforce` block on a memory entry's frontmatter declares that the rule
should be enforced as a runtime hook. This module reads those blocks,
validates them, and generates Claude Code hooks from templates.

Public API:
  - validate_enforce_block(d) → dict
  - parse_memory_entry(md) → (meta, body)
  - pick_template(tool, pattern, template_dir) → Path
  - generate_hook(md, template_dir) → str
  - EnforceValidationError
  - GenerationError

Design doc: docs/v2-enforcement.md (in this repo) and
output/product-ip/mnemosyne/2026-04-29-v2-enforcement-architecture.md
in PAI for the full architectural rationale.
"""

from .cli import main as cli_main
from .generator import GenerationError, generate_hook, parse_memory_entry, pick_template
from .schema import EnforceValidationError, validate_enforce_block

__all__ = [
    "EnforceValidationError",
    "GenerationError",
    "cli_main",
    "generate_hook",
    "parse_memory_entry",
    "pick_template",
    "validate_enforce_block",
]
