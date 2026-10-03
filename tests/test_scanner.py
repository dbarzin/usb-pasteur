from __future__ import annotations

import hashlib
import os
from pathlib import Path

from usb_pasteur.engines import Engine, EngineResult, FakeEngine, FileInfo, Verdict
from usb_pasteur.scanner import FileResult, Scanner


def test_scan_tree(usb_tree: Path) -> None:
    (usb_tree / "big.iso").write_bytes(b"0" * 2000)
    (usb_tree / "link").symlink_to("/etc/passwd")
    os.mkfifo(usb_tree / "fifo")
    progress: list[int] = []

    def on_progress(result: FileResult, scanned: int) -> None:
        progress.append(scanned)

    scanner = Scanner([FakeEngine()], workers=2, max_file_size=1000)
    summary = scanner.scan_tree(usb_tree, on_progress)

    verdicts = {f.path.name: f.verdict for f in summary.files}
    assert verdicts == {
        "readme.txt": Verdict.CLEAN,
        "report.pdf": Verdict.CLEAN,
        "eicar.com": Verdict.MALICIOUS,
        "big.iso": Verdict.SKIPPED,
    }
    assert [f.path.name for f in summary.infected] == ["eicar.com"]
    assert len(progress) == 4
    assert progress == sorted(progress)


def test_engine_failure_is_an_error(tmp_path: Path) -> None:
    class Broken(Engine):
        name = "broken"

        def scan(self, file: FileInfo) -> EngineResult:
            raise RuntimeError("boom")

    (tmp_path / "file").write_text("x")
    summary = Scanner([Broken()], workers=1, max_file_size=100).scan_tree(tmp_path)
    assert summary.files[0].verdict is Verdict.ERROR
    assert summary.files[0].results[0].error == "boom"


def test_many_files(tmp_path: Path) -> None:
    for i in range(50):
        (tmp_path / f"f{i}").write_text(str(i))
    summary = Scanner([FakeEngine()], workers=3, max_file_size=100).scan_tree(tmp_path)
    assert summary.count(Verdict.CLEAN) == 50


def test_file_info(usb_tree: Path) -> None:
    summary = Scanner([FakeEngine()], workers=1, max_file_size=1000).scan_tree(usb_tree)
    infos = {f.path.name: f.info for f in summary.files}
    readme = infos["readme.txt"]
    assert readme is not None
    assert readme.rel_path == "readme.txt"
    assert readme.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert readme.sha1 == hashlib.sha1(b"hello").hexdigest()
    assert readme.md5 == hashlib.md5(b"hello").hexdigest()
    report = infos["report.pdf"]
    assert report is not None and report.rel_path == "docs/report.pdf"
