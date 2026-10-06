"""Transparent risk scoring (Phase 10).

The score is a sum of five components. Each component has a fixed cap, and every point added
is recorded with its reason and evidence, so the number can be reproduced by hand.

    total = min(100, static + behavior + network + privilege + correlation)

Component caps (sum = 100):
    static       0-25   ELF mitigations, string indicator kinds, YARA matches
    behavior     0-40   process starts, file writes and deletes
    network      0-15   connections to non-loopback destinations
    privilege    0-10   UID/GID change attempts (failed or successful)
    correlation  0-10   correlation findings from Phase 9

A score is not a verdict. It does not prove that a sample is malicious, and a missing signal
(for example, no strace data) adds nothing rather than counting as safe or unsafe.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from malvax.correlation import BehaviorEvent, BehaviorType, Finding
from malvax.elf import ElfReport
from malvax.net_monitor import Connection
from malvax.strings_analysis import IndicatorKind, StringReport
from malvax.yara_scan import YaraMatch

CAPS = {"static": 25, "behavior": 40, "network": 15, "privilege": 10, "correlation": 10}
YARA_POINTS = {"info": 0, "low": 2, "medium": 5, "high": 8}
STRING_KIND_POINTS = {
    IndicatorKind.URL: 2,
    IndicatorKind.IP_ADDRESS: 2,
    IndicatorKind.DOMAIN: 1,
    IndicatorKind.FILE_PATH: 1,
    IndicatorKind.SHELL_COMMAND: 3,
    IndicatorKind.ENVIRONMENT_VARIABLE: 1,
    IndicatorKind.SUSPICIOUS_KEYWORD: 3,
}
PER_PROCESS_START = 3
PER_FILE_WRITE = 1
PER_FILE_DELETE = 1
PER_EXTERNAL_CONNECTION = 5
PER_PRIVILEGE_ATTEMPT = 2
PRIVILEGE_SUCCESS_BONUS = 5
CORRELATION_POINTS = {"WRITE_THEN_CONNECT": 5, "MASS_DELETE": 2, "CHILD_PROCESS": 1,
                      "PRIVILEGE_ATTEMPT": 2}


@dataclass(frozen=True, slots=True)
class Contribution:
    component: str
    points: int
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class RiskReport:
    total: int
    component_totals: dict[str, int]
    contributions: list[Contribution] = field(default_factory=list)


def score(
    *,
    elf: ElfReport | None = None,
    strings: StringReport | None = None,
    yara: list[YaraMatch] | None = None,
    timeline: list[BehaviorEvent] | None = None,
    connections: list[Connection] | None = None,
    findings: list[Finding] | None = None,
) -> RiskReport:
    """Pure function: the same inputs always give the same report."""
    contributions: list[Contribution] = []
    contributions += _static(elf, strings, yara or [])
    contributions += _behavior(timeline or [])
    contributions += _network(connections or [])
    contributions += _privilege(timeline or [])
    contributions += _correlation(findings or [])

    totals = {name: 0 for name in CAPS}
    for c in contributions:
        totals[c.component] += c.points
    capped = {name: min(totals[name], CAPS[name]) for name in CAPS}
    total = min(100, sum(capped.values()))
    return RiskReport(total=total, component_totals=capped, contributions=contributions)


def _static(elf: ElfReport | None, strings: StringReport | None,
            yara: list[YaraMatch]) -> list[Contribution]:
    out: list[Contribution] = []
    if elf is not None:
        # Only an explicit weakness adds points. None means "could not determine", and that
        # is not treated as a vulnerability.
        if elf.mitigations.nx is False:
            out.append(Contribution("static", 3, "Stack is executable (NX disabled)"))
        if elf.mitigations.relro == "none":
            out.append(Contribution("static", 2, "No RELRO segment"))
        if elf.mitigations.pie is False:
            out.append(Contribution("static", 1, "Non-PIE executable (fixed load address)"))
    if strings is not None:
        for kind, points in STRING_KIND_POINTS.items():
            hits = [i for i in strings.indicators if i.kind is kind]
            if hits:
                # Each indicator keeps its file offset, so the finding points at real bytes.
                evidence = tuple(f"string@0x{i.offset:x}" for i in hits)
                out.append(Contribution(
                    "static", points,
                    f"String indicators of kind {kind.value} present ({len(hits)})",
                    evidence=evidence,
                ))
    for match in yara:
        points = YARA_POINTS.get(match.severity, 0)
        if points:
            out.append(Contribution(
                "static", points,
                f"YARA rule {match.rule_id} matched (severity {match.severity})",
                evidence=(match.rule_id,),
            ))
    return out


def _behavior(timeline: list[BehaviorEvent]) -> list[Contribution]:
    out: list[Contribution] = []
    starts = [e for e in timeline if e.type is BehaviorType.PROCESS_CREATED]
    for e in starts:
        out.append(Contribution("behavior", PER_PROCESS_START,
                                "Process started", evidence=(e.event_id,)))
    writes = [e for e in timeline if e.type in {BehaviorType.FILE_CREATED,
                                                 BehaviorType.FILE_MODIFIED}]
    for e in writes:
        out.append(Contribution("behavior", PER_FILE_WRITE,
                                "File created or modified", evidence=(e.event_id,)))
    for e in timeline:
        if e.type is BehaviorType.FILE_DELETED:
            out.append(Contribution("behavior", PER_FILE_DELETE,
                                    "File deleted", evidence=(e.event_id,)))
    return out


def _network(connections: list[Connection]) -> list[Contribution]:
    out: list[Contribution] = []
    for conn in connections:
        if _is_external(conn.destination):
            out.append(Contribution(
                "network", PER_EXTERNAL_CONNECTION,
                f"Connection to non-loopback address {conn.destination}:"
                f"{conn.destination_port}",
                evidence=(f"socket-inode:{conn.inode}",),
            ))
    return out


def _privilege(timeline: list[BehaviorEvent]) -> list[Contribution]:
    out: list[Contribution] = []
    for e in timeline:
        if e.type is not BehaviorType.PRIVILEGE_CHANGE:
            continue
        out.append(Contribution("privilege", PER_PRIVILEGE_ATTEMPT,
                                "UID/GID change attempted", evidence=(e.event_id,)))
        if e.succeeded:
            out.append(Contribution("privilege", PRIVILEGE_SUCCESS_BONUS,
                                    "UID/GID change succeeded", evidence=(e.event_id,)))
    return out


def _correlation(findings: list[Finding]) -> list[Contribution]:
    out: list[Contribution] = []
    for f in findings:
        points = CORRELATION_POINTS.get(f.rule, 0)
        if points:
            out.append(Contribution("correlation", points,
                                    f"Correlation rule {f.rule}: {f.title}",
                                    evidence=f.observed))
    return out


def _is_external(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast)
