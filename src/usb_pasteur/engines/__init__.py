"""Detection engines."""

from usb_pasteur.engines.base import (
    Engine,
    EngineError,
    EngineKind,
    EngineResult,
    EngineSpec,
    FileInfo,
    SignatureInfo,
    Verdict,
    aggregate,
)
from usb_pasteur.engines.fake import FakeEngine

__all__ = [
    "Engine",
    "EngineError",
    "EngineKind",
    "EngineResult",
    "EngineSpec",
    "FakeEngine",
    "FileInfo",
    "SignatureInfo",
    "Verdict",
    "aggregate",
]
