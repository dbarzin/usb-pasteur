from __future__ import annotations

import time
from pathlib import Path

import pytest

from usb_pasteur.engines import EngineError, EngineKind, EngineSpec, FakeEngine, Verdict
from usb_pasteur.inventory import take_inventory
from usb_pasteur.pipeline import PipelineOptions
from usb_pasteur.results import FileResult
from usb_pasteur.workers import WorkerPool

from .conftest import FAKE, started_pool
from .engines import FailingLoadEngine, MisbehavingEngine


def make_files(root: Path, names: list[str]) -> None:
    for name in names:
        (root / name).write_text(name)


def run(pool: WorkerPool, root: Path) -> dict[str, FileResult]:
    entries = take_inventory(root, 1000, 10, 10**6).files
    results: list[FileResult] = []
    pool.scan(root, entries, results.append)
    assert len(results) == len(entries)
    return {r.rel_path: r for r in results}


def misbehaving(behavior: str, timeout: float = 60.0) -> list[EngineSpec]:
    return [
        EngineSpec("fake", FakeEngine),
        EngineSpec("misbehaving", MisbehavingEngine, (behavior, "bad-", timeout)),
    ]


def test_start_reports_engines() -> None:
    with started_pool(FAKE) as pool:
        [engine] = pool.engines
        assert engine.name == "fake"
        assert engine.kind is EngineKind.CONTENT
        assert engine.version == "fake"
        assert len(pool.pids) == 2
        assert pool.engine_info()[0].name == "fake"


def test_load_failure_refuses_to_start() -> None:
    pool = WorkerPool([EngineSpec("failing", FailingLoadEngine)], PipelineOptions(), 1, 60.0)
    with pytest.raises(EngineError, match="failing: no signatures"):
        pool.start()


def test_engine_exception(tmp_path: Path) -> None:
    make_files(tmp_path, ["ok.txt", "bad-raise.txt"])
    with started_pool(misbehaving("raise")) as pool:
        results = run(pool, tmp_path)
    assert results["ok.txt"].verdict is Verdict.CLEAN
    bad = results["bad-raise.txt"]
    assert bad.verdict is Verdict.ERROR
    assert "RuntimeError: boom" in bad.detail


def test_invalid_result(tmp_path: Path) -> None:
    make_files(tmp_path, ["bad-result.txt"])
    with started_pool(misbehaving("bad")) as pool:
        results = run(pool, tmp_path)
    assert results["bad-result.txt"].verdict is Verdict.ERROR
    assert "invalid engine result" in results["bad-result.txt"].detail


def test_late_clean_answer_is_an_error(tmp_path: Path) -> None:
    make_files(tmp_path, ["bad-slow.txt"])
    # The engine answers after its timeout, before the watchdog grace delay
    with started_pool(misbehaving("slow", timeout=0.2), engine_grace=5) as pool:
        results = run(pool, tmp_path)
    assert results["bad-slow.txt"].verdict is Verdict.ERROR
    assert "timeout (0.2s) exceeded" in results["bad-slow.txt"].detail


def test_hung_engine_is_killed(tmp_path: Path) -> None:
    make_files(tmp_path, ["bad-hang.txt", "a.txt", "b.txt", "c.txt"])
    start = time.monotonic()
    with started_pool(misbehaving("hang", timeout=0.5), workers=2) as pool:
        pids = set(pool.pids)
        results = run(pool, tmp_path)
        assert pool.restarts == 1
        assert set(pool.pids) != pids
        # The replacement worker scans normally
        assert run(pool, tmp_path)["a.txt"].verdict is Verdict.CLEAN
    assert time.monotonic() - start < 30
    hung = results["bad-hang.txt"]
    assert hung.verdict is Verdict.ERROR
    assert hung.detail == "engine timeout in engine misbehaving"
    assert hung.results[0].engine == "misbehaving"
    assert all(results[n].verdict is Verdict.CLEAN for n in ("a.txt", "b.txt", "c.txt"))


def test_file_timeout(tmp_path: Path) -> None:
    make_files(tmp_path, ["bad-hang.txt"])
    with started_pool(misbehaving("hang"), workers=1, file_timeout=0.5) as pool:
        results = run(pool, tmp_path)
    assert results["bad-hang.txt"].verdict is Verdict.ERROR
    assert "file scan timeout (0.5s" in results["bad-hang.txt"].detail


def test_crashed_worker(tmp_path: Path) -> None:
    make_files(tmp_path, ["bad-crash.txt", "ok1.txt", "ok2.txt"])
    with started_pool(misbehaving("crash"), workers=1) as pool:
        results = run(pool, tmp_path)
        assert pool.restarts == 1
    crashed = results["bad-crash.txt"]
    assert crashed.verdict is Verdict.ERROR
    assert crashed.detail == "scan worker crashed (exit code 3) in engine misbehaving"
    assert results["ok1.txt"].verdict is Verdict.CLEAN
    assert results["ok2.txt"].verdict is Verdict.CLEAN


def test_every_worker_crashes(tmp_path: Path) -> None:
    make_files(tmp_path, [f"bad-{i}.txt" for i in range(6)])
    with started_pool(misbehaving("crash"), workers=2) as pool:
        results = run(pool, tmp_path)
    assert all(r.verdict is Verdict.ERROR for r in results.values())
