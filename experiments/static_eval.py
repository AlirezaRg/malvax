"""Static-analysis evaluation harness (Phase 18).

Change log:
- v1 (first run, Windows): a YARA match counted as positive only at severity low or higher.
  The lab marker rule LAB-003 is severity info, so yara_marker was a false negative. That
  result is kept in experiments/results/static_windows_20261006T103731Z.*.
- v2 (this version): any YARA match or any string indicator counts as positive. A lab marker is
  an indicator by definition, so severity should not hide it. This rule was changed AFTER
  seeing the v1 result, so the v2 recall of 1.0 must not be read as real detection performance.

What this measures, and what it does not:
- It times each static stage (intake, ELF parse, strings, YARA, risk) on a labeled set, and
  checks how often the static indicators match the labels.
- The labels are written by the project author, and the samples are synthetic. So the accuracy
  numbers measure consistency between the detector and the design, NOT detection performance on
  real malware. They are reported with that caveat.
- Dynamic (sandbox) results are not measured here. The report marks them NOT_MEASURED.

Run:  python experiments/static_eval.py --runs 20
Output: experiments/results/static_<timestamp>.json and a Markdown table next to it.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from malvax.elf import ElfParseError, analyze_elf  # noqa: E402
from malvax.intake import intake_sample  # noqa: E402
from malvax.risk import score  # noqa: E402
from malvax.strings_analysis import IndicatorKind, analyze_strings  # noqa: E402
from malvax.yara_scan import compile_rules, scan_bytes  # noqa: E402

DATASET_DIR = Path(__file__).resolve().parent / "dataset"
RULES_DIR = ROOT / "rules"
ELF_HEADER = b"\x7fELF\x02\x01\x01" + b"\x00" * 57  # minimal 64-bit header, no program headers
INDICATOR_KINDS = {IndicatorKind.URL, IndicatorKind.SHELL_COMMAND, IndicatorKind.SUSPICIOUS_KEYWORD}


@dataclass(frozen=True, slots=True)
class LabeledSample:
    name: str
    label_positive: bool  # designed to contain laboratory indicators
    content: bytes


def build_dataset() -> list[LabeledSample]:
    """Deterministic synthetic set. This script writes every sample; nothing is downloaded."""
    return [
        LabeledSample("clean_text", False, b"plain notes with no indicators at all\n"),
        LabeledSample("clean_elf_stub", False, ELF_HEADER),
        LabeledSample("url_only", True, b"fetch http://lab.example.test/item"),
        LabeledSample("shell_only", True, ELF_HEADER + b"\x00/bin/sh -c id\x00"),
        LabeledSample("yara_marker", True, b"prefix MALVAX_LAB_TMP suffix"),
        LabeledSample("mixed_indicators", True,
                      ELF_HEADER + b"\x00http://lab.example.test/x /bin/sh MALVAX_LAB_TMP\x00"),
    ]


def write_dataset(samples: list[LabeledSample]) -> list[Path]:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    paths = []
    for s in samples:
        path = DATASET_DIR / f"{s.name}.bin"
        path.write_bytes(s.content)
        paths.append(path)
    return paths


def time_stages(path: Path, rules) -> dict[str, float]:
    """Wall time per stage in milliseconds, for one run on one file."""
    data = path.read_bytes()
    t: dict[str, float] = {}

    start = time.perf_counter()
    meta = intake_sample(path)
    t["intake_ms"] = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    try:
        elf = analyze_elf(path) if meta.file_type == "ELF" else None
    except ElfParseError:
        elf = None
    t["elf_ms"] = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    strings = analyze_strings(data)
    t["strings_ms"] = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    yara = scan_bytes(rules, data)
    t["yara_ms"] = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    score(elf=elf, strings=strings, yara=yara)
    t["risk_ms"] = (time.perf_counter() - start) * 1000

    t["total_ms"] = sum(t.values())
    return t


def predicted_positive(path: Path, rules) -> tuple[bool, dict]:
    data = path.read_bytes()
    strings = analyze_strings(data)
    yara = scan_bytes(rules, data)
    string_hit = any(i.kind in INDICATOR_KINDS for i in strings.indicators)
    yara_hit = bool(yara)  # any rule match is an indicator; severity is a score input only
    return string_hit or yara_hit, {
        "string_indicator_kinds": sorted({i.kind.value for i in strings.indicators}),
        "yara_rules": sorted(m.rule_id for m in yara),
    }


def confusion(rows: list[tuple[bool, bool]]) -> dict[str, int]:
    tp = sum(1 for truth, pred in rows if truth and pred)
    fp = sum(1 for truth, pred in rows if not truth and pred)
    tn = sum(1 for truth, pred in rows if not truth and not pred)
    fn = sum(1 for truth, pred in rows if truth and not pred)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def summarize(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    q = statistics.quantiles(ordered, n=4) if len(ordered) >= 2 else [ordered[0]] * 3
    return {"median": round(statistics.median(ordered), 4), "q1": round(q[0], 4),
            "q3": round(q[2], 4), "n": len(ordered)}


def run(runs: int) -> dict:
    samples = build_dataset()
    paths = write_dataset(samples)
    rules = compile_rules(RULES_DIR)

    per_sample = {}
    for sample, path in zip(samples, paths, strict=True):
        timings = [time_stages(path, rules) for _ in range(runs)]
        stage_keys = timings[0].keys()
        predicted, evidence = predicted_positive(path, rules)
        per_sample[sample.name] = {
            "label_positive": sample.label_positive,
            "predicted_positive": predicted,
            "evidence": evidence,
            "timing_ms": {k: summarize([t[k] for t in timings]) for k in stage_keys},
        }

    rows = [(v["label_positive"], v["predicted_positive"]) for v in per_sample.values()]
    counts = confusion(rows)
    n = len(rows)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "host": {"platform": platform.platform(), "python": platform.python_version()},
        "runs_per_sample": runs,
        "dataset_size": n,
        "caveat": "Synthetic samples with author-written labels. Measures detector/design "
                  "consistency, not detection performance on real malware.",
        "confusion": counts,
        "precision": round(counts["tp"] / (counts["tp"] + counts["fp"]), 4)
        if counts["tp"] + counts["fp"] else "NOT YET MEASURED",
        "recall": round(counts["tp"] / (counts["tp"] + counts["fn"]), 4)
        if counts["tp"] + counts["fn"] else "NOT YET MEASURED",
        "static_only": per_sample,
        "dynamic": "NOT_MEASURED (sandbox not connected)",
        "static_plus_dynamic": "NOT_MEASURED (sandbox not connected)",
    }


def to_markdown(result: dict) -> str:
    lines = [
        "| sample | label | predicted | total median ms (IQR) | n |",
        "|---|---|---|---|---|",
    ]
    for name, row in result["static_only"].items():
        total = row["timing_ms"]["total_ms"]
        lines.append(
            f"| {name} | {'positive' if row['label_positive'] else 'negative'} | "
            f"{'positive' if row['predicted_positive'] else 'negative'} | "
            f"{total['median']} ({total['q1']}–{total['q3']}) | {total['n']} |"
        )
    lines += [
        "",
        f"Confusion: {result['confusion']}",
        f"Precision: {result['precision']} · Recall: {result['recall']}",
        f"Caveat: {result['caveat']}",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    result = run(args.runs)

    out_dir = Path(__file__).resolve().parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    host = platform.system().lower()
    base = out_dir / f"static_{host}_{stamp}"
    base.with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    base.with_suffix(".md").write_text(to_markdown(result), encoding="utf-8")
    print(to_markdown(result))
    print(f"\nwritten: {base.with_suffix('.json')}")


if __name__ == "__main__":
    main()
