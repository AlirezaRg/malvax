from pathlib import Path

import pytest

from malvax.strings_analysis import IndicatorKind, analyze_strings, classify, extract_strings
from malvax.yara_scan import RuleMetadataError, compile_rules, scan_bytes

RULES = Path(__file__).resolve().parent.parent / "rules"


def test_extracts_printable_runs_with_offsets() -> None:
    data = b"\x00\x01abcd\x00xy\x00hello world\xff"
    found = extract_strings(data)
    assert found == [(2, "abcd"), (10, "hello world")]  # "xy" is shorter than 4


def test_url_and_ip_and_path_classified() -> None:
    assert IndicatorKind.URL in classify("connect to https://lab.example.test/a")
    assert IndicatorKind.IP_ADDRESS in classify("server 10.0.0.5 port")
    assert IndicatorKind.FILE_PATH in classify("open /etc/hosts now")


def test_loopback_and_multicast_ips_are_not_reported() -> None:
    assert IndicatorKind.IP_ADDRESS not in classify("127.0.0.1")
    assert IndicatorKind.IP_ADDRESS not in classify("224.0.0.1")


def test_version_like_text_is_not_ip() -> None:
    assert IndicatorKind.IP_ADDRESS not in classify("version 999.999.1.1")


def test_shell_and_env_classified() -> None:
    assert IndicatorKind.SHELL_COMMAND in classify("/bin/sh -c id")
    assert IndicatorKind.ENVIRONMENT_VARIABLE in classify("LD_PRELOAD=/tmp/x.so")


def test_url_is_not_double_counted_as_domain() -> None:
    assert IndicatorKind.DOMAIN not in classify("https://lab.example.test/path")


def test_report_counts_and_is_labeled_indicators() -> None:
    report = analyze_strings(b"fetch http://lab.example.test/x and run /bin/sh\x00")
    assert report.count >= 1
    assert report.by_kind["URL"] == 1
    assert report.by_kind["SHELL_COMMAND"] == 1
    assert all(i.value for i in report.indicators)


def test_yara_rules_compile_and_match_lab_marker() -> None:
    rules = compile_rules(RULES)
    matches = scan_bytes(rules, b"prefix MALVAX_LAB_TMP suffix")
    assert [m.rule_id for m in matches] == ["LAB-003"]
    assert matches[0].severity == "info"
    assert matches[0].offsets == (7,)


def test_yara_no_match_on_clean_data() -> None:
    assert scan_bytes(compile_rules(RULES), b"nothing interesting here") == []


def test_yara_rule_without_metadata_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    (root / "generic").mkdir(parents=True)
    (root / "generic" / "bad.yar").write_text(
        'rule Bad { meta: rule_id = "X" strings: $a = "x" condition: $a }'
    )
    with pytest.raises(RuleMetadataError, match="missing metadata"):
        compile_rules(root)
