"""AI-assisted analyst summary (Phase 15).

Security model:
- The model receives structured evidence only: rule ids, severities, counts, risk points and
  evidence ids. Raw sample text (strings, filenames, command lines) is never included, so an
  instruction hidden in a sample cannot reach the model as a prompt.
- Every output is validated. Unknown fields are rejected, every referenced evidence id must
  exist in the input, and confidence must be a number in [0, 1]. Anything else is an error,
  never silently accepted.
- The default provider is offline and deterministic. The external provider is off unless the
  operator sets MALVAX_AI_PROVIDER=anthropic and a key, because it sends evidence outside the lab.
- The model has no tools and cannot execute anything, reach the host, or fetch payloads.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

MAX_SUMMARY_CHARS = 1000
MAX_ITEMS = 20
OUTPUT_FIELDS = frozenset({
    "executive_summary",
    "behavior_summary",
    "important_evidence",
    "potential_threats",
    "confidence",
    "recommended_investigation_steps",
    "recommended_remediation",
})


class AnalystOutputError(ValueError):
    """Raised when provider output does not match the required shape or references unknown ids."""


@dataclass(frozen=True, slots=True)
class EvidenceItem:
    id: str
    kind: str
    fields: dict[str, str | int | bool | None]


class AnalystProvider(Protocol):
    name: str

    def analyze(self, evidence: list[EvidenceItem]) -> dict[str, Any]: ...


def build_evidence(report: dict[str, Any]) -> list[EvidenceItem]:
    """Extract scalar evidence from a stored report. Free text from the sample is excluded."""
    items: list[EvidenceItem] = []
    static = report.get("static", {}) if isinstance(report.get("static"), dict) else {}

    elf = static.get("elf")
    if isinstance(elf, dict) and "parse_error" in elf:
        items.append(EvidenceItem("elf-parse-error", "elf", {"status": "parse_failed"}))
    elif isinstance(elf, dict):
        mit = elf.get("mitigations", {})
        items.append(EvidenceItem("elf-mitigations", "elf", {
            "nx": mit.get("nx"), "pie": mit.get("pie"),
            "relro": mit.get("relro"), "stack_canary": mit.get("stack_canary"),
        }))

    strings = static.get("strings")
    if isinstance(strings, dict):
        by_kind = strings.get("by_kind", {})
        for kind, count in sorted(by_kind.items()):
            items.append(EvidenceItem(f"strings-{kind.lower()}", "string_indicator",
                                      {"indicator_kind": kind, "count": int(count)}))

    yara = static.get("yara")
    if isinstance(yara, list):
        for match in yara[:MAX_ITEMS]:
            if isinstance(match, dict) and "rule_id" in match:
                items.append(EvidenceItem(f"yara-{match['rule_id']}", "yara_match", {
                    "rule_id": str(match["rule_id"]), "severity": str(match.get("severity")),
                }))

    risk = report.get("risk")
    if isinstance(risk, dict):
        for index, c in enumerate(risk.get("contributions", [])[:MAX_ITEMS]):
            items.append(EvidenceItem(f"risk-{index}", "risk_contribution", {
                "component": str(c.get("component")), "points": int(c.get("points", 0)),
            }))
        items.append(EvidenceItem("risk-total", "risk_total", {"total": int(risk.get("total", 0))}))

    if report.get("execution") == "NOT_COLLECTED" or _all_not_collected(report.get("execution")):
        items.append(EvidenceItem("dynamic-not-collected", "limitation",
                                  {"status": "NOT_COLLECTED"}))
    return items


def validate_output(output: Any, evidence_ids: set[str]) -> dict[str, Any]:
    if not isinstance(output, dict):
        raise AnalystOutputError("output is not an object")
    unknown = set(output) - OUTPUT_FIELDS
    if unknown:
        raise AnalystOutputError(f"unexpected fields: {sorted(unknown)}")
    missing = OUTPUT_FIELDS - set(output)
    if missing:
        raise AnalystOutputError(f"missing fields: {sorted(missing)}")

    summary = output["executive_summary"]
    if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_SUMMARY_CHARS:
        raise AnalystOutputError("executive_summary must be a short non-empty string")
    if not isinstance(output["behavior_summary"], str):
        raise AnalystOutputError("behavior_summary must be a string")

    refs = output["important_evidence"]
    if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
        raise AnalystOutputError("important_evidence must be a list of ids")
    bad = [r for r in refs if r not in evidence_ids]
    if bad:
        raise AnalystOutputError(f"output references unknown evidence ids: {bad}")

    confidence = output["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise AnalystOutputError("confidence must be a number")
    if not 0.0 <= float(confidence) <= 1.0:
        raise AnalystOutputError("confidence must be between 0 and 1")

    for field in ("potential_threats", "recommended_investigation_steps",
                  "recommended_remediation"):
        value = output[field]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise AnalystOutputError(f"{field} must be a list of strings")
    return output


class OfflineProvider:
    """Deterministic summary built only from evidence. Used by default and in tests."""

    name = "offline"

    def analyze(self, evidence: list[EvidenceItem]) -> dict[str, Any]:
        by_id = {e.id: e for e in evidence}
        scored = [e for e in evidence if e.kind == "risk_contribution"]
        total = by_id["risk-total"].fields["total"] if "risk-total" in by_id else None
        yara = [e for e in evidence if e.kind == "yara_match"]
        not_collected = "dynamic-not-collected" in by_id

        summary = (
            f"Static analysis recorded {len(evidence)} evidence items"
            + (f" and a risk score of {total}/100." if total is not None else ".")
            + " The score is a heuristic and does not establish malicious behavior."
        )
        behavior = (
            "Dynamic behavior was not collected; no runtime activity is reported."
            if not_collected else
            "Runtime behavior is reported from the sandbox evidence listed below."
        )
        threats = [
            f"Laboratory rule {e.fields['rule_id']} matched (severity {e.fields['severity']}); "
            "this is an indicator, not a verdict."
            for e in yara
        ]
        steps = [
            "Confirm each YARA match by reviewing the rule definition and the byte offsets.",
            "Obtain dynamic (sandbox) results before drawing any behavioral conclusion.",
        ]
        remediation = [
            "Keep the sample isolated and do not execute it outside the lab VM.",
        ]
        confidence = round(min(0.9, 0.2 + 0.05 * len(scored) + 0.05 * len(yara)), 2)
        return {
            "executive_summary": summary,
            "behavior_summary": behavior,
            "important_evidence": [e.id for e in evidence[:5]],
            "potential_threats": threats,
            "confidence": confidence,
            "recommended_investigation_steps": steps,
            "recommended_remediation": remediation,
        }


def analyze_report(report: dict[str, Any], provider: AnalystProvider) -> dict[str, Any]:
    evidence = build_evidence(report)
    ids = {e.id for e in evidence}
    raw = provider.analyze(evidence)
    result = validate_output(raw, ids)
    result["provider"] = provider.name
    result["ai_generated"] = True
    result["evidence_count"] = len(evidence)
    return result


def evidence_payload(evidence: list[EvidenceItem]) -> str:
    """The exact JSON a remote provider would receive. Kept here so it can be audited."""
    return json.dumps(
        [{"id": e.id, "kind": e.kind, "fields": e.fields} for e in evidence],
        sort_keys=True,
    )


def _all_not_collected(value: Any) -> bool:
    if value == "NOT_COLLECTED":
        return True
    if isinstance(value, dict) and value:
        return all(_all_not_collected(v) for v in value.values())
    return False
