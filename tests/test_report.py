import json

from malvax.correlation import BehaviorEvent, BehaviorType
from malvax.report import LIMITATIONS, NOT_COLLECTED, SCHEMA_VERSION, build_report, to_html, to_json
from malvax.risk import score
from malvax.strings_analysis import StringReport
from malvax.yara_scan import YaraMatch

SAMPLE = {"filename": "sample.elf", "sha256": "ab" * 32, "size": 104, "file_type": "ELF"}
FIXED = "2026-01-01T00:00:00+00:00"


def _minimal() -> dict:
    return build_report(sample=SAMPLE, generated_at=FIXED)


def test_json_is_valid_and_has_schema_version() -> None:
    data = json.loads(to_json(_minimal()))
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["sample"]["sha256"] == "ab" * 32


def test_missing_sections_are_not_collected_not_empty() -> None:
    report = _minimal()
    assert report["static"]["elf"] == NOT_COLLECTED
    assert report["execution"]["network"] == NOT_COLLECTED
    assert report["risk"] == NOT_COLLECTED


def test_empty_collected_list_is_distinct_from_not_collected() -> None:
    report = build_report(sample=SAMPLE, fs_events=[], generated_at=FIXED)
    assert report["execution"]["filesystem"] == []
    assert report["execution"]["filesystem"] != NOT_COLLECTED


def test_limitations_always_present() -> None:
    assert _minimal()["limitations"] == LIMITATIONS
    assert "NOT_COLLECTED" not in LIMITATIONS


def test_enums_and_dataclasses_serialize() -> None:
    events = [BehaviorEvent("e1", 1.0, BehaviorType.FILE_CREATED, 1, "s", True, {"p": "/x"})]
    text = to_json(build_report(sample=SAMPLE, timeline=events, generated_at=FIXED))
    data = json.loads(text)
    assert data["behavior"]["timeline"][0]["type"] == "FILE_CREATED"


def test_risk_block_is_serialized_with_reasons() -> None:
    matches = [YaraMatch("LAB-003", "LAB-003", "info", "d", "r", (), (0,))]
    risk = score(yara=matches)
    report = build_report(sample=SAMPLE, risk=risk, generated_at=FIXED)
    assert report["risk"]["total"] == 0


def test_html_escapes_malicious_sample_strings() -> None:
    hostile = '<script>alert("x")</script>'
    strings = StringReport(count=1, truncated=False, indicators=[], by_kind={})
    report = build_report(
        sample={"filename": hostile, "sha256": "00", "size": 1, "file_type": "ELF"},
        strings=strings,
        generated_at=FIXED,
    )
    page = to_html(report)
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_html_contains_every_required_section() -> None:
    page = to_html(_minimal())
    for heading in ("Sample", "Risk", "Static analysis", "Execution", "Behavior", "Limitations"):
        assert f"<h2>{heading}</h2>" in page


def test_html_marks_uncollected_sections() -> None:
    page = to_html(_minimal())
    assert NOT_COLLECTED in page


def test_html_limitations_are_rendered() -> None:
    page = to_html(_minimal())
    assert LIMITATIONS[0] in page or LIMITATIONS[0].replace("'", "&#x27;") in page
