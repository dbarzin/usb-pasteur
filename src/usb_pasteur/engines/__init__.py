"""Detection engines."""

from usb_pasteur.engines.base import Engine, EngineResult, Verdict, aggregate
from usb_pasteur.engines.fake import FakeEngine

__all__ = ["Engine", "EngineResult", "FakeEngine", "Verdict", "aggregate"]
