from malvax.correlation import BehaviorEvent, BehaviorType, Finding
from malvax.elf import ElfReport, Mitigations
from malvax.net_monitor import Connection
from malvax.risk import CAPS, score
from malvax.strings_analysis import Indicator, IndicatorKind, StringReport
from malvax.yara_scan import YaraMatch


def _elf(nx: bool | None = True, relro: str | None = "full", pie: bool | None = True) -> ElfReport:
    return ElfReport(
        elf_class="ELF64", endianness="little", os_abi=0, elf_type="DYN",
        machine="x86-64", entry_point=0,
        mitigations=Mitigations(pie=pie, nx=nx, relro=relro, stack_canary=None),
    )


def _ev(eid: str, kind: BehaviorType, ok: bool | None = True) -> BehaviorEvent:
    return BehaviorEvent(eid, 1.0, kind, 1, "sample", ok, {})


def test_empty_input_scores_zero() -> None:
    report = score()
    assert report.total == 0
    assert report.contributions == []


def test_unknown_mitigation_adds_nothing() -> None:
    # None means "could not determine". It must not be scored as a weakness.
    report = score(elf=_elf(nx=None, relro=None, pie=None))
    assert report.total == 0


def test_explicit_nx_and_relro_weakness_scored() -> None:
    report = score(elf=_elf(nx=False, relro="none", pie=False))
    reasons = [c.reason for c in report.contributions]
    assert any("NX disabled" in r for r in reasons)
    assert any("No RELRO" in r for r in reasons)
    assert report.component_totals["static"] == 3 + 2 + 1


def test_string_indicators_scored_by_kind() -> None:
    indicators = [
        Indicator(IndicatorKind.URL, "http://a.test", 4),
        Indicator(IndicatorKind.SHELL_COMMAND, "/bin/sh", 20),
        Indicator(IndicatorKind.SHELL_COMMAND, "curl x", 40),
    ]
    strings = StringReport(count=3, truncated=False, indicators=indicators,
                           by_kind={"URL": 1, "SHELL_COMMAND": 2})
    report = score(strings=strings)
    assert report.component_totals["static"] == 2 + 3


def test_yara_severity_points_and_evidence() -> None:
    match = YaraMatch("LAB-001", "LAB-001", "high", "d", "r", (), (0,))
    report = score(yara=[match])
    (c,) = report.contributions
    assert c.points == 8 and c.evidence == ("LAB-001",)


def test_static_component_is_capped() -> None:
    matches = [YaraMatch(f"R{i}", f"R{i}", "high", "d", "r", (), (0,)) for i in range(10)]
    report = score(yara=matches)
    assert report.component_totals["static"] == CAPS["static"]


def test_behavior_and_privilege_contributions() -> None:
    timeline = [
        _ev("p1", BehaviorType.PROCESS_CREATED),
        _ev("w1", BehaviorType.FILE_CREATED),
        _ev("u1", BehaviorType.PRIVILEGE_CHANGE, ok=True),
        _ev("u2", BehaviorType.PRIVILEGE_CHANGE, ok=False),
    ]
    report = score(timeline=timeline)
    assert report.component_totals["behavior"] == 3 + 1
    assert report.component_totals["privilege"] == 2 + 5 + 2  # two attempts + success bonus


def test_external_connection_counts_loopback_does_not() -> None:
    external = Connection("tcp", "ipv4", "127.0.0.1", 1, "10.0.0.5", 443, "ESTABLISHED", 1)
    loopback = Connection("tcp", "ipv4", "127.0.0.1", 1, "127.0.0.1", 80, "ESTABLISHED", 2)
    report = score(connections=[external, loopback])
    assert report.component_totals["network"] == 5
    assert len(report.contributions) == 1


def test_correlation_points_from_findings() -> None:
    finding = Finding("WRITE_THEN_CONNECT", "t", ("a", "b"), "i")
    report = score(findings=[finding])
    (c,) = report.contributions
    assert c.component == "correlation" and c.points == 5
    assert c.evidence == ("a", "b")


def test_total_is_capped_at_100() -> None:
    # Fill every component past its cap: static 25 + behavior 40 + network 15 + privilege 10
    # + correlation 10 = 100. Going beyond any cap must not raise the total above 100.
    timeline = [_ev(f"p{i}", BehaviorType.PROCESS_CREATED) for i in range(50)]
    timeline += [_ev(f"u{i}", BehaviorType.PRIVILEGE_CHANGE, ok=True) for i in range(6)]
    matches = [YaraMatch(f"R{i}", f"R{i}", "high", "d", "r", (), (0,)) for i in range(10)]
    conns = [Connection("tcp", "ipv4", "127.0.0.1", 1, "10.0.0.5", 443, "ESTABLISHED", i)
             for i in range(4)]
    findings = [Finding("WRITE_THEN_CONNECT", "t", ("a", "b"), "i") for _ in range(3)]
    report = score(timeline=timeline, yara=matches, connections=conns, findings=findings)
    assert report.component_totals == CAPS
    assert report.total == 100


def test_scoring_is_reproducible() -> None:
    timeline = [_ev("p1", BehaviorType.PROCESS_CREATED), _ev("w1", BehaviorType.FILE_CREATED)]
    assert score(timeline=timeline) == score(timeline=timeline)


def test_component_totals_sum_to_total_when_under_cap() -> None:
    timeline = [_ev("p1", BehaviorType.PROCESS_CREATED)]
    report = score(timeline=timeline)
    assert report.total == sum(report.component_totals.values()) == 3


def test_string_contribution_carries_offset_evidence() -> None:
    strings = StringReport(
        count=1, truncated=False,
        indicators=[Indicator(IndicatorKind.URL, "http://lab.example.test", 16)],
        by_kind={"URL": 1},
    )
    report = score(strings=strings)
    (c,) = report.contributions
    assert c.evidence == ("string@0x10",)
