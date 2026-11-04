"""Render the standalone comparison UI without computing research statistics."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re


def _browser_numbers(value):
    """Copy JSON containers, retaining integers beyond JavaScript's exact range."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value) if abs(value) > 2**53 - 1 else value
    if isinstance(value, dict):
        return {key: _browser_numbers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_browser_numbers(item) for item in value]
    return value


def render_dashboard(payload: dict) -> str:
    """Return offline HTML with an inert, escaped JSON payload and hashed script.

    All analytical values are supplied by the comparison backend. This function
    neither mutates the payload nor reads or writes analysis artifacts.
    """
    encoded = json.dumps(_browser_numbers(payload), ensure_ascii=False, allow_nan=False, separators=(',', ':'))
    for char, escape in (('&', '\\u0026'), ('<', '\\u003c'), ('>', '\\u003e'),
                         ('\u2028', '\\u2028'), ('\u2029', '\\u2029')):
        encoded = encoded.replace(char, escape)
    template = Path(__file__).with_name('dashboard.html').read_text(encoding='utf-8')
    scripts = re.findall(r'<script>(.*?)</script>', template, re.S)
    if (len(scripts) != 1 or template.count('__DASHBOARD_SCRIPT_HASH__') != 1
            or template.count('__DASHBOARD_DATA__') != 1):
        raise ValueError('Dashboard template needs one application script, hash slot and data slot')
    digest = base64.b64encode(hashlib.sha256(scripts[0].encode('utf-8')).digest()).decode('ascii')
    # Insert data last: marker-like untrusted text must remain literal data.
    return template.replace('__DASHBOARD_SCRIPT_HASH__', digest).replace('__DASHBOARD_DATA__', encoded)
