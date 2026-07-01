"""
Cross-platform terminal compatibility
======================================
Windows cmd/PowerShell defaults to cp1252 which can't encode Unicode
box-drawing characters, check marks, etc. This module:

1. Forces stdout/stderr to UTF-8 on startup (reconfigure if available,
   env var PYTHONIOENCODING=utf-8 as fallback instruction).
2. Provides _supports_unicode() so output functions can fall back to
   ASCII equivalents when the terminal can't handle Unicode.

Import this at the top of cli.py — the reconfigure call is a side effect
that runs once when the package is first imported.
"""
from __future__ import annotations
import os
import sys


def _force_utf8() -> None:
    """
    Reconfigure stdout/stderr to UTF-8 with error replacement so
    Unicode characters never crash on Windows cp1252 terminals.
    Errors='replace' means unknown chars print as '?' instead of raising.
    """
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _supports_unicode() -> bool:
    """
    True if the current terminal can render Unicode.
    Conservative: returns False on Windows unless explicitly UTF-8.
    """
    if sys.platform == "win32":
        enc = getattr(sys.stdout, "encoding", "") or ""
        return enc.lower().replace("-", "") in ("utf8", "utf-8")
    return True


# Run once on import
_force_utf8()


# Symbol sets — use ASCII fallbacks when Unicode isn't safe
if _supports_unicode():
    SYM_OK      = "✓"
    SYM_FAIL    = "✗"
    SYM_WARN    = "⚠"
    SYM_BULLET  = "•"
    SYM_ARROW   = "→"
    SYM_CRITICAL= "✗"
    SYM_HIGH    = "!"
    SYM_MEDIUM  = "▲"
    SYM_INFO    = "ℹ"
    SYM_BLOCK_FULL  = "█"
    SYM_BLOCK_EMPTY = "░"
    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_SIDE = "║"
    BOX_LINE = "═"
    DASH = "──"
else:
    SYM_OK      = "[OK]"
    SYM_FAIL    = "[X]"
    SYM_WARN    = "[!]"
    SYM_BULLET  = "*"
    SYM_ARROW   = "->"
    SYM_CRITICAL= "[X]"
    SYM_HIGH    = "[!]"
    SYM_MEDIUM  = "[~]"
    SYM_INFO    = "[i]"
    SYM_BLOCK_FULL  = "#"
    SYM_BLOCK_EMPTY = "."
    BOX_TL = "+"
    BOX_TR = "+"
    BOX_BL = "+"
    BOX_BR = "+"
    BOX_SIDE = "|"
    BOX_LINE = "="
    DASH = "--"
