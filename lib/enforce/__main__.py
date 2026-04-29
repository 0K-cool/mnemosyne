"""Entry point for `python -m enforce`.

For audit aggregation use `python -m enforce.audit` (parallel module
with its own __main__).
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
