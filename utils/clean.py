"""
utils/clean.py — Subdomain cleaning/validation (direct port from original).
"""
import re
from typing import List

_RE_WILDCARD  = re.compile(r'^\*\.?')
_RE_SUBDOMAIN = re.compile(r'^[a-z0-9][a-z0-9\-\.]{0,252}[a-z0-9]$')
_RE_SINGLE    = re.compile(r'^[a-z0-9]$')


def clean_subdomains(raw: List[str]) -> List[str]:
    seen, out = set(), []
    for s in raw:
        if not s:
            continue
        s = _RE_WILDCARD.sub('', s.strip().lower()).strip('.')
        if not s or s in seen:
            continue
        if _RE_SUBDOMAIN.match(s) or _RE_SINGLE.match(s):
            seen.add(s)
            out.append(s)
    return sorted(out)
