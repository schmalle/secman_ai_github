"""Process-wide dry-run guard.

`--dry-run` promises that a command performs **no external writes**: no GitHub
issue is opened and nothing is pushed to secman. The branches that skip those
calls live in `issues.py`, `orchestrator.py`, and `cli.py` — but a promise kept
only by branching is one refactor away from being silently broken, and the cost
of breaking it is a real issue filed on someone's repo or a real row written to
a vulnerability tracker.

So the flag also arms a guard here. Every call site that would write to the
outside world calls `guard()` first; while the guard is armed that raises
`DryRunViolation` instead of performing the write. In a correct dry run the
guard never fires — it exists to turn a future regression into a loud failure
rather than an unwanted side effect.

The state is a module-level flag because it is a property of the whole process:
one CLI invocation is either a dry run or it isn't.
"""

from __future__ import annotations

import os

_TRUTHY = ("1", "true", "yes", "on")

_active = False


class DryRunViolation(RuntimeError):
    """An external write was attempted while dry-run was active."""


def resolve(flag: bool) -> bool:
    """True if the CLI flag was passed or SECSCAN_DRY_RUN is set to a truthy value."""
    if flag:
        return True
    return os.environ.get("SECSCAN_DRY_RUN", "").strip().lower() in _TRUTHY


def activate() -> None:
    """Arm the guard for the rest of this process."""
    global _active
    _active = True


def reset() -> None:
    """Disarm the guard (used by tests; a CLI process never needs this)."""
    global _active
    _active = False


def is_active() -> bool:
    return _active


def guard(action: str) -> None:
    """Raise if `action` would write to the outside world during a dry run."""
    if _active:
        raise DryRunViolation(f"dry-run is active: refusing to {action}")


def notice() -> str:
    """The one-line banner commands print when running dry."""
    return (
        "Dry run: no GitHub issues will be created and nothing will be pushed to secman."
    )
