"""Printable string extraction and indicator classification (Phase 3).

Output is labeled as INDICATOR. A string that looks like a URL or a shell command shows that
the text exists in the binary; it does not prove that the program uses it. Confirmed behavior
can only come from the sandbox (Phase 5+).
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from enum import StrEnum

MIN_LENGTH = 4
MAX_STRINGS = 20000
_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{%d,}" % MIN_LENGTH)

_URL = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>]{3,}", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|onion)\b", re.I)
_PATH = re.compile(r"(?:^|[\s'\"=])(/(?:[\w.-]+/?){1,})")
_ENV = re.compile(r"\b(?:HOME|PATH|USER|SHELL|LD_PRELOAD|LD_LIBRARY_PATH|TMPDIR)=?\b")
_SHELL = re.compile(
    r"(?<!\w)(?:/bin/(?:sh|bash|dash)|sh -c|bash -c|wget |curl |chmod |nc |netcat|base64 -d)(?!\w)"
)
_SUSPICIOUS_KEYWORDS = (
    "password", "passwd", "shadow", "credential", "keylog", "exfil", "backdoor", "reverse shell",
    "ptrace", "setuid", "crontab", "authorized_keys", "/etc/passwd",
)


class IndicatorKind(StrEnum):
    URL = "URL"
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    FILE_PATH = "FILE_PATH"
    SHELL_COMMAND = "SHELL_COMMAND"
    ENVIRONMENT_VARIABLE = "ENVIRONMENT_VARIABLE"
    SUSPICIOUS_KEYWORD = "SUSPICIOUS_KEYWORD"


@dataclass(frozen=True, slots=True)
class Indicator:
    kind: IndicatorKind
    value: str
    offset: int


@dataclass(frozen=True, slots=True)
class StringReport:
    count: int
    truncated: bool
    indicators: list[Indicator]
    by_kind: dict[str, int]


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[tuple[int, str]]:
    """Return (offset, text) for printable ASCII runs of at least MIN_LENGTH bytes."""
    found: list[tuple[int, str]] = []
    for match in _PRINTABLE.finditer(data):
        found.append((match.start(), match.group().decode("ascii")))
        if len(found) >= limit:
            break
    return found


def classify(text: str) -> list[IndicatorKind]:
    kinds: list[IndicatorKind] = []
    if _URL.search(text):
        kinds.append(IndicatorKind.URL)
    if any(_is_reportable_ip(m) for m in _IPV4.findall(text)):
        kinds.append(IndicatorKind.IP_ADDRESS)
    if _DOMAIN.search(text) and not _URL.search(text):
        kinds.append(IndicatorKind.DOMAIN)
    if _PATH.search(text):
        kinds.append(IndicatorKind.FILE_PATH)
    if _SHELL.search(text):
        kinds.append(IndicatorKind.SHELL_COMMAND)
    if _ENV.search(text):
        kinds.append(IndicatorKind.ENVIRONMENT_VARIABLE)
    lowered = text.lower()
    if any(keyword in lowered for keyword in _SUSPICIOUS_KEYWORDS):
        kinds.append(IndicatorKind.SUSPICIOUS_KEYWORD)
    return kinds


def analyze_strings(data: bytes, limit: int = MAX_STRINGS) -> StringReport:
    strings = extract_strings(data, limit)
    indicators: list[Indicator] = []
    counts: dict[str, int] = defaultdict(int)
    for offset, text in strings:
        for kind in classify(text):
            indicators.append(Indicator(kind=kind, value=text[:200], offset=offset))
            counts[kind.value] += 1
    return StringReport(
        count=len(strings),
        truncated=len(strings) >= limit,
        indicators=indicators,
        by_kind=dict(counts),
    )


def _is_reportable_ip(candidate: str) -> bool:
    """Ignore strings that are not valid IPv4 addresses, and skip loopback and multicast."""
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_unspecified or addr.is_multicast)
