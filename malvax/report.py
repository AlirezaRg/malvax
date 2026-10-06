"""Analysis report generation (Phase 11).

Builds one structured document from the results of the earlier phases, then renders it as JSON
(machine-readable, the source of truth) or HTML (for reading).

Rules this module follows:
- Every value that came from a sample (filenames, strings, command lines, ELF metadata) is
  untrusted. It is escaped before it enters HTML, so a sample cannot run script in the report.
- A section that was not collected is marked NOT_COLLECTED. It is never shown as "nothing found".
- The limitations section is always present.
- PDF export is not implemented here. It needs a renderer dependency and comes later.
"""

from __future__ import annotations

import html
import json
from dataclasses import asdict, is_dataclass
from datetime import UTC, datetime
from typing import Any

from malvax.correlation import BehaviorEvent, Finding
from malvax.elf import ElfReport
from malvax.fs_monitor import FsEvent
from malvax.net_monitor import Connection
from malvax.process_monitor import ProcessNode, render_tree
from malvax.risk import RiskReport
from malvax.strings_analysis import StringReport
from malvax.syscall_monitor import SyscallEvent
from malvax.yara_scan import YaraMatch

SCHEMA_VERSION = "1.0"
NOT_COLLECTED = "NOT_COLLECTED"
LIMITATIONS = [
    "Static indicators (strings, YARA) show that text or patterns exist; "
    "they do not prove behavior.",
    "Snapshot-based file and network monitoring can miss short-lived activity between snapshots.",
    "Process owner attribution for sockets depends on readable /proc/<pid>/fd entries.",
    "The risk score is a transparent heuristic, not a verdict. Its weights are not yet measured.",
    "No software sandbox guarantees perfect isolation. Results depend on the lab VM being clean.",
]


def build_report(
    *,
    sample: dict[str, Any],
    elf: ElfReport | None = None,
    elf_error: str | None = None,
    strings: StringReport | None = None,
    yara: list[YaraMatch] | None = None,
    process_tree: list[ProcessNode] | None = None,
    fs_events: list[FsEvent] | None = None,
    connections: list[Connection] | None = None,
    syscalls: list[SyscallEvent] | None = None,
    timeline: list[BehaviorEvent] | None = None,
    findings: list[Finding] | None = None,
    risk: RiskReport | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Return the report as a plain dict. Missing inputs become NOT_COLLECTED."""
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at or datetime.now(UTC).isoformat(),
        "sample": sample,
        "static": {
            "elf": _elf_block(elf, elf_error),
            "strings": _plain(strings) if strings is not None else NOT_COLLECTED,
            "yara": [_plain(m) for m in yara] if yara is not None else NOT_COLLECTED,
        },
        "execution": {
            "process_tree": _or_missing(process_tree, _tree_to_dicts),
            "filesystem": _or_missing(fs_events, _plain_list),
            "network": _or_missing(connections, _plain_list),
            "syscalls": _or_missing(syscalls, _plain_list),
        },
        "behavior": {
            "timeline": _or_missing(timeline, _plain_list),
            "findings": _or_missing(findings, _plain_list),
        },
        "risk": _plain(risk) if risk is not None else NOT_COLLECTED,
        "limitations": LIMITATIONS,
    }


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def to_html(report: dict[str, Any]) -> str:
    """Render a report. Every sample-derived value is escaped; nothing is trusted as markup."""
    sample = report["sample"]
    risk = report["risk"]
    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>MalvaX report</title></head><body>",
        "<h1>MalvaX analysis report</h1>",
        f"<p>Schema {_e(report['schema_version'])} · generated {_e(report['generated_at'])}</p>",
        "<h2>Sample</h2>",
        _kv(sample),
        "<h2>Risk</h2>",
        _risk_block(risk),
        "<h2>Static analysis</h2>",
        _section(report["static"]),
        "<h2>Execution</h2>",
        _section(report["execution"]),
        "<h2>Behavior</h2>",
        _section(report["behavior"]),
        "<h2>Limitations</h2><ul>",
        *[f"<li>{_e(item)}</li>" for item in report["limitations"]],
        "</ul></body></html>",
    ]
    return "\n".join(parts)


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _kv(data: dict[str, Any]) -> str:
    rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in data.items())
    return f"<table>{rows}</table>"


def _risk_block(risk: Any) -> str:
    if risk == NOT_COLLECTED:
        return f"<p>{_e(NOT_COLLECTED)}</p>"
    rows = "".join(
        f"<li>{_e(c['component'])} +{_e(c['points'])}: {_e(c['reason'])}</li>"
        for c in risk["contributions"]
    )
    return f"<p>Score {_e(risk['total'])}/100</p><ul>{rows}</ul>"


def _section(block: dict[str, Any]) -> str:
    out: list[str] = []
    for name, value in block.items():
        out.append(f"<h3>{_e(name)}</h3>")
        if value == NOT_COLLECTED:
            out.append(f"<p>{_e(NOT_COLLECTED)}</p>")
        elif isinstance(value, list):
            if not value:
                out.append("<p>No entries recorded.</p>")
            else:
                items = "".join(f"<li>{_e(_one_line(v))}</li>" for v in value)
                out.append(f"<ul>{items}</ul>")
        elif isinstance(value, dict):
            out.append(_kv(value))
        else:
            out.append(f"<p>{_e(value)}</p>")
    return "\n".join(out)


def _one_line(value: Any) -> str:
    if isinstance(value, dict):
        return "; ".join(f"{k}={v}" for k, v in value.items())
    return str(value)


def _elf_block(elf: ElfReport | None, error: str | None) -> Any:
    if elf is not None:
        return _plain(elf)
    if error is not None:
        return {"parse_error": error}
    return NOT_COLLECTED


def _or_missing(value: Any, convert: Any) -> Any:
    return NOT_COLLECTED if value is None else convert(value)


def _plain_list(items: list[Any]) -> list[Any]:
    return [_plain(item) for item in items]


def _plain(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _plain(v) for k, v in asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    if hasattr(obj, "value") and not isinstance(obj, (str, int, float, bool)):
        return obj.value  # enums
    return obj


def _tree_to_dicts(roots: list[ProcessNode]) -> dict[str, Any]:
    def walk(node: ProcessNode) -> dict[str, Any]:
        rec = _plain(node.record)
        rec["children"] = [walk(c) for c in node.children]
        return rec

    return {"rendered": render_tree(roots), "roots": [walk(r) for r in roots]}
