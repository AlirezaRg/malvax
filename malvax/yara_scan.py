"""YARA scanning (Phase 3).

Rules are loaded from the modular rules/ tree. Each rule must carry the metadata fields
required by the project (id, description, author, references, severity, tags); rules that
miss them are rejected at load time so every match can be explained in a report.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yara

REQUIRED_META = ("rule_id", "description", "author", "references", "severity")
SEVERITIES = frozenset({"info", "low", "medium", "high"})
RULE_SUBDIRS = ("generic", "linux", "elf", "laboratory")


class RuleMetadataError(ValueError):
    """Raised when a rule is missing required metadata."""


@dataclass(frozen=True, slots=True)
class YaraMatch:
    rule: str
    rule_id: str
    severity: str
    description: str
    references: str
    tags: tuple[str, ...]
    offsets: tuple[int, ...]


def collect_rule_files(rules_root: Path) -> list[Path]:
    files: list[Path] = []
    for sub in RULE_SUBDIRS:
        files.extend(sorted((rules_root / sub).glob("*.yar")))
    return files


def compile_rules(rules_root: Path) -> yara.Rules:
    files = collect_rule_files(rules_root)
    if not files:
        raise FileNotFoundError(f"no .yar files under {rules_root}")
    filepaths = {f"{p.parent.name}_{p.stem}": str(p) for p in files}
    compiled = yara.compile(filepaths=filepaths)
    for rule in compiled:
        _check_metadata(rule)
    return compiled


def scan_bytes(rules: yara.Rules, data: bytes) -> list[YaraMatch]:
    matches: list[YaraMatch] = []
    for m in rules.match(data=data):
        meta = m.meta
        matches.append(
            YaraMatch(
                rule=m.rule,
                rule_id=str(meta["rule_id"]),
                severity=str(meta["severity"]),
                description=str(meta["description"]),
                references=str(meta["references"]),
                tags=tuple(m.tags),
                offsets=tuple(off for _, off, _ in _string_hits(m)),
            )
        )
    return matches


def _string_hits(match: yara.Match):
    for item in match.strings:
        for instance in item.instances:
            yield item.identifier, instance.offset, instance.matched_data


def _check_metadata(rule) -> None:
    missing = [key for key in REQUIRED_META if key not in rule.meta]
    if missing:
        raise RuleMetadataError(f"rule {rule.identifier} missing metadata: {missing}")
    if rule.meta["severity"] not in SEVERITIES:
        raise RuleMetadataError(f"rule {rule.identifier} has invalid severity")
