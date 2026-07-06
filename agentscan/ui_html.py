# -*- coding: utf-8 -*-
"""Dashboard HTML loader - reads dashboard.html and injects D3."""
from __future__ import annotations
from pathlib import Path

_HERE = Path(__file__).parent
_ASSETS = _HERE / "outputs" / "assets"
_TEMPLATE = _HERE / "dashboard.html"


def get_dashboard_html(version: str = "") -> str:
    template = _TEMPLATE.read_text(encoding="utf-8")
    d3 = (_ASSETS / "d3.min.js").read_text(encoding="utf-8") if (_ASSETS / "d3.min.js").exists() else ""
    # Replace the placeholder script tag with the real D3 source
    template = template.replace(
        "// Injected by server: __D3_SCRIPT__",
        d3
    )
    template = template.replace("v0.2.9", "v" + version)
    return template
