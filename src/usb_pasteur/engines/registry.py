"""Build the engines enabled in the configuration."""

from __future__ import annotations

from collections.abc import Sequence

from usb_pasteur.config import Config
from usb_pasteur.engines.base import Engine, EngineKind, EngineSpec
from usb_pasteur.engines.clamav import ClamavEngine
from usb_pasteur.engines.fake import FakeEngine
from usb_pasteur.engines.hashes import HashlookupEngine, MalwareBazaarEngine
from usb_pasteur.engines.yara import YaraEngine


class NoEngineError(Exception):
    pass


def engine_specs(config: Config) -> list[EngineSpec]:
    """Recipes of the enabled engines, hash engines first.

    Raise NoEngineError without any content engine: hash lookups alone only
    recognize known files and would let any new malware through.
    """
    if config.kiosk.fake_scan:
        return [EngineSpec(FakeEngine.name, FakeEngine, (config.scan.fake_delay,))]
    engines = config.engines
    specs = []
    if engines.malwarebazaar.enabled:
        specs.append(
            EngineSpec(
                MalwareBazaarEngine.name, MalwareBazaarEngine, (engines.malwarebazaar.database,)
            )
        )
    if engines.hashlookup.enabled:
        specs.append(
            EngineSpec(HashlookupEngine.name, HashlookupEngine, (engines.hashlookup.bloom,))
        )
    if engines.clamav.enabled:
        av = engines.clamav
        specs.append(
            EngineSpec(
                ClamavEngine.name,
                ClamavEngine,
                (
                    av.socket,
                    av.mode,
                    av.timeout,
                    av.max_file_size,
                    av.suspicious_names,
                    av.error_names,
                ),
            )
        )
    if engines.yara.enabled:
        specs.append(EngineSpec(YaraEngine.name, YaraEngine, (engines.yara,)))
    if not any(spec.factory_kind() is EngineKind.CONTENT for spec in specs):
        raise NoEngineError(
            "no content engine is enabled (engines.clamav, engines.yara): "
            "set kiosk.fake_scan = true for development"
        )
    return specs


def load_engines(specs: Sequence[EngineSpec]) -> list[Engine]:
    """Create and load the engines; EngineError is raised if one cannot load."""
    engines = []
    for spec in specs:
        engine = spec.create()
        engine.load()
        engines.append(engine)
    return engines
