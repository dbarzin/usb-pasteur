from __future__ import annotations

from pathlib import Path

import pytest

from usb_pasteur.engines import EngineResult, FakeEngine, Verdict, aggregate
from usb_pasteur.engines.fake import EICAR


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ([], Verdict.SKIPPED),
        ([Verdict.CLEAN], Verdict.CLEAN),
        ([Verdict.CLEAN, Verdict.MALICIOUS], Verdict.MALICIOUS),
        ([Verdict.SUSPICIOUS, Verdict.ERROR], Verdict.SUSPICIOUS),
        ([Verdict.CLEAN, Verdict.ERROR], Verdict.ERROR),
        ([Verdict.SKIPPED, Verdict.CLEAN], Verdict.CLEAN),
    ],
)
def test_aggregate(verdicts: list[Verdict], expected: Verdict) -> None:
    assert aggregate(EngineResult("e", v) for v in verdicts) is expected


def test_fake_engine(tmp_path: Path) -> None:
    eicar = tmp_path / "eicar.com"
    eicar.write_bytes(EICAR)
    clean = tmp_path / "clean.txt"
    clean.write_text("hello")
    engine = FakeEngine()
    assert engine.scan(eicar).verdict is Verdict.MALICIOUS
    assert engine.scan(clean).verdict is Verdict.CLEAN


def test_fake_engine_does_not_follow_links(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        FakeEngine().scan(link)
