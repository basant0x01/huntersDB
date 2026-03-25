"""
utils/garbage_classifier.py — Async wrapper around garbage_ai.py classifier.

Used by all subdomain import paths (Manual, Chaos, HackerOne, YesWeHack)
to split incoming subdomains into "real" and "garbage" before any scanning.

Only the REAL subdomains are inserted into the `subdomains` table and used
for live detection / deep scan / nuclei.
Garbage subdomains are stored in `garbage_subdomains` with their score and
reason so the user can review and promote them if needed.
"""
import asyncio
import logging
import re
from collections import Counter
from datetime import datetime
from math import log2
from typing import Dict, List, Tuple

logger = logging.getLogger("utils.garbage_classifier")

# ── Feature helpers (ported from garbage_ai.py) ───────────────────────────────

def _alpha_ratio(s: str) -> float:
    return sum(c.isalpha() for c in s) / len(s) if s else 0

def _digit_ratio(s: str) -> float:
    return sum(c.isdigit() for c in s) / len(s) if s else 0

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * log2(p) for p in prob)

def _get_labels(s: str) -> List[str]:
    s = s.lstrip("*.")
    parts = s.split(".")
    return parts[:-2] if len(parts) > 2 else []

def _looks_like_ip_segment(s: str) -> bool:
    return bool(re.fullmatch(r'\d+[-]\d+[-]\d+[-]\d+', s))

def _looks_like_mac_or_hash(s: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-f]{6,}', s, re.I))

def _has_version_like_suffix(s: str) -> bool:
    return bool(re.fullmatch(r'[a-z]{2,}[0-9]{1,3}', s, re.I))

def _looks_like_random_string(s: str) -> bool:
    vowels = sum(c.lower() in 'aeiou' for c in s)
    return len(s) >= 6 and vowels == 0 and _entropy(s) > 3.8

_ISP_TOKENS = re.compile(
    r'(?:^|(?<=[_-]))(?:bcust|bbcust|cust|lladsl|elladsl|bbadsl|adsl\d*|vdsl|dsl|dslb|'
    r'dynamic|pool|ppp|pppoe|pppst|pppo|dhcp|cable|fiber|fibre|broad|atmpu|highway|'
    r'cpe|fttx|ftth|fttc|lte|umts|custom|static|dyn|modem|router|gateway|dialup|'
    r'residential|dynamicip|poolip|ipaddr|host-)(?:[^a-z]|$)', re.I
)

_ANY_LABEL_GARBAGE_RE = re.compile(
    r'(?:^|\.)(?:bbcust|bcust|pppoe|pppst|pppost|pppo|dialup|residential|dynamic|pool|'
    r'dhcp|cpe|dslb|adsl|vdsl|ftth|dyn|modem|router|gateway|dialup|poolip|dynamicip)(?:\.|$)',
    re.I
)

_REVERSED_IP_TN_LABEL = re.compile(r'^tn$', re.I)

KNOWN_REAL_WORDS = {
    'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'sftp', 'api', 'app', 'admin', 'login',
    'auth', 'sso', 'portal', 'dashboard', 'panel', 'shop', 'store', 'blog', 'news',
    'forum', 'forums', 'community', 'mobile', 'wap', 'm', 'cdn', 'assets', 'static',
    'media', 'img', 'images', 'files', 'upload', 'uploads', 'download', 'downloads',
    'dev', 'staging', 'stg', 'stage', 'uat', 'test', 'qa', 'prod', 'prd', 'int',
    'vpn', 'remote', 'access', 'secure', 'ssl', 'webmail', 'exchange', 'ns', 'ns1',
    'ns2', 'mx', 'mx1', 'mx2', 'relay', 'autodiscover', 'autoconfig', 'cpanel', 'whm',
    'help', 'support', 'status', 'monitor', 'git', 'gitlab', 'github', 'ci', 'jenkins',
    'cloud', 'internal', 'intranet', 'partner', 'partners', 'clients', 'b2b', 'b2c',
    'video', 'stream', 'live', 'maps', 'search', 'jobs', 'career', 'new', 'old',
    'legacy', 'backup', 'sandbox', 'roaming', 'gprs', 'mms', 'fut', 'pst', 'web',
    'payment', 'account', 'ticket', 'frontend', 'on', 'res'
}


def _is_isp_ptr(sub: str, labels: List[str]) -> Tuple[bool, str]:
    if _ANY_LABEL_GARBAGE_RE.search(sub):
        return True, "any-label-isp-token"
    if labels and _REVERSED_IP_TN_LABEL.match(labels[0]) and len(labels) >= 2:
        return True, "reversed-ip-tn"
    for label in labels:
        if re.fullmatch(r'\d+', label) or _looks_like_ip_segment(label) or _looks_like_mac_or_hash(label):
            return True, "numeric-ip-hash-any-label"
        if _ISP_TOKENS.search(label) or _looks_like_random_string(label):
            return True, f"any-label-garbage:{label}"
    return False, ""


class _Classifier:
    """Stateful classifier that trains on provisional real subs then scores all."""

    def __init__(self):
        self.word_freq: Counter = Counter()
        self.total: int = 0

    def train(self, subs: List[str]) -> None:
        for s in subs:
            labels = _get_labels(s)
            if any(_ANY_LABEL_GARBAGE_RE.search(s) or re.fullmatch(r'\d+', lbl) for lbl in labels):
                continue
            for label in labels:
                if label.isalpha() and len(label) > 1 and not _ISP_TOKENS.search(label):
                    self.word_freq[label.lower()] += 1
                    self.total += 1

    def _word_score(self, label: str) -> float:
        return self.word_freq[label.lower()] / self.total if self.total else 0

    def score(self, sub: str) -> Tuple[float, str]:
        labels = _get_labels(sub)
        if not labels:
            return -10.0, "no-labels"

        first = labels[0]

        is_ptr, reason = _is_isp_ptr(sub, labels)
        if is_ptr:
            return -10.0, f"garbage-any-label:{reason}"

        if re.fullmatch(r'\d+', first):
            return -10.0, "pure-numeric-first"

        result = 0.0
        reasons = []

        if first.lower() in KNOWN_REAL_WORDS:
            result += 6
            reasons.append("known-real")

        if _looks_like_ip_segment(first) or _looks_like_mac_or_hash(first):
            result -= 6
            reasons.append("ip-hash")
        if _has_version_like_suffix(first):
            result += 2
            reasons.append("versioned")
        if first.isalpha():
            result += 2
            reasons.append("pure-alpha")
        if '-' in first and _digit_ratio(first) == 0 and _alpha_ratio(first) >= 0.85:
            result += 2
            reasons.append("compound")

        ws = self._word_score(first)
        if ws > 0:
            result += ws * 6
            reasons.append(f"word-freq")

        dr = _digit_ratio(first)
        if dr > 0.4:
            result -= 4
        ar = _alpha_ratio(first)
        if ar < 0.45:
            result -= 3
        ent = _entropy(first)
        if ent > 4.2 or _looks_like_random_string(first):
            result -= 5
            reasons.append("random-high-entropy")

        if len(labels) >= 4:
            result -= 1.5
        if len(first) > 22 and ar < 0.65:
            result -= 4

        top = reasons[0] if reasons else "scored"
        return result, top


def classify_subdomains(
    subs: List[str],
    threshold: float = 0.0,
) -> Tuple[List[str], List[Tuple[str, float, str]]]:
    """
    Classify a list of subdomains into real vs garbage.

    Returns:
        real_subs   — list of real subdomain strings (to be scanned)
        garbage     — list of (subdomain, score, reason) for storage
    """
    if not subs:
        return [], []

    clf = _Classifier()

    # Two-pass: train on provisional real, then classify all
    provisional = [s for s in subs if clf.score(s)[0] >= 2.5]
    clf.word_freq.clear()
    clf.total = 0
    clf.train(provisional)

    real: List[str] = []
    garbage: List[Tuple[str, float, str]] = []

    for s in subs:
        sc, reason = clf.score(s)
        if sc >= threshold:
            real.append(s)
        else:
            garbage.append((s, round(sc, 2), reason))

    return real, garbage


async def classify_and_store(
    pool,
    project_id: str,
    subs: List[str],
    source: str = "",
    threshold: float = 0.0,
) -> Tuple[List[str], int]:
    """
    Classify subdomains and persist garbage ones to the DB.

    Returns:
        (real_subs, garbage_count)
    """
    real, garbage = await asyncio.to_thread(classify_subdomains, subs, threshold)

    if garbage:
        now = datetime.now().isoformat()
        try:
            async with pool.acquire() as conn:
                await conn.executemany(
                    """INSERT INTO garbage_subdomains
                       (project_id, subdomain, score, reason, source, created_at)
                       VALUES($1, $2, $3, $4, $5, $6)
                       ON CONFLICT (project_id, subdomain) DO NOTHING""",
                    [(project_id, sub, score, reason, source, now)
                     for sub, score, reason in garbage]
                )
        except Exception as e:
            logger.error("Failed to store garbage subdomains for %s: %s", project_id, e)

    logger.info(
        "classify_and_store [%s]: %d real, %d garbage (source=%s)",
        project_id, len(real), len(garbage), source
    )
    return real, len(garbage)
