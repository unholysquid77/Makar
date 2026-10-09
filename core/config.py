"""Configuration loading.

Every tunable number in the forensic pipeline lives in ``configs/*.yaml``.
Nothing under ``core/`` may hardcode a threshold -- when the Shifting Waters
twist lands we want to retune by editing YAML, not by editing detectors.

Access is by dotted path so call sites read like the spec section they
implement::

    cfg.get("detection.geospatial.speed_ratio_hard")
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

#: Repository root, resolved from this file's location.
ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "configs"
DEFAULT_CONFIG = CONFIG_DIR / "default.yaml"

_MISSING = object()


class ConfigError(KeyError):
    """Raised when a config path is absent and no default was supplied."""


def _deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge ``overlay`` into ``base``, returning a new dict.

    Scalars and lists in ``overlay`` replace their counterparts outright;
    only mappings are merged. Replacing a list wholesale is intentional: a
    partial merge of, say, ``nodes.ids`` would be meaningless.
    """
    out = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _coerce(text: str) -> Any:
    """Parse a CLI/env override value using YAML scalar rules."""
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return text


class MakarConfig:
    """Immutable-by-convention view over the merged configuration tree."""

    __slots__ = ("_data", "_sources")

    def __init__(self, data: dict[str, Any], sources: list[str] | None = None) -> None:
        self._data = data
        self._sources = sources or []

    # -- access ---------------------------------------------------------

    def get(self, path: str, default: Any = _MISSING) -> Any:
        """Return the value at a dotted ``path``.

        Raises :class:`ConfigError` when the path is absent and no ``default``
        is given, so a typo in a detector fails loudly instead of silently
        disabling a check.
        """
        node: Any = self._data
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                if default is _MISSING:
                    raise ConfigError(f"missing config path: {path!r}")
                return default
        return node

    def section(self, path: str) -> MakarConfig:
        """Return a sub-config rooted at ``path``."""
        node = self.get(path)
        if not isinstance(node, dict):
            raise ConfigError(f"config path is not a section: {path!r}")
        return MakarConfig(node, self._sources)

    def float_(self, path: str, default: Any = _MISSING) -> float:
        return float(self.get(path, default))

    def int_(self, path: str, default: Any = _MISSING) -> int:
        return int(self.get(path, default))

    def bool_(self, path: str, default: Any = _MISSING) -> bool:
        return bool(self.get(path, default))

    def list_(self, path: str, default: Any = _MISSING) -> list[Any]:
        value = self.get(path, default)
        return list(value) if value is not None else []

    def __contains__(self, path: str) -> bool:
        return self.get(path, None) is not None

    def __getitem__(self, path: str) -> Any:
        return self.get(path)

    def as_dict(self) -> dict[str, Any]:
        """Deep copy of the whole tree, safe to serialise into a report."""
        return copy.deepcopy(self._data)

    @property
    def sources(self) -> list[str]:
        """Which files/overrides produced this config, for provenance."""
        return list(self._sources)

    # -- derivation -----------------------------------------------------

    def with_overrides(self, overrides: dict[str, Any]) -> MakarConfig:
        """Return a new config with dotted-path ``overrides`` applied."""
        data = copy.deepcopy(self._data)
        for path, value in overrides.items():
            node = data
            parts = path.split(".")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
                if not isinstance(node, dict):
                    raise ConfigError(f"cannot override through scalar at {path!r}")
            node[parts[-1]] = value
        labels = [f"override:{k}={v}" for k, v in overrides.items()]
        return MakarConfig(data, [*self._sources, *labels])

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"MakarConfig(sections={sorted(self._data)}, sources={self._sources})"


def load_config(
    path: str | Path | None = None,
    *,
    overrides: dict[str, Any] | None = None,
    use_env: bool = True,
) -> MakarConfig:
    """Load ``configs/default.yaml``, then an optional overlay, then overrides.

    Precedence, lowest to highest:

    1. ``configs/default.yaml``
    2. the overlay file in ``path`` (a scenario or twist profile)
    3. ``MAKAR__``-prefixed environment variables, e.g.
       ``MAKAR__detection__geospatial__speed_ratio_hard=1.5``
    4. explicit ``overrides``
    """
    with DEFAULT_CONFIG.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    sources = [str(DEFAULT_CONFIG.relative_to(ROOT))]

    if path is not None:
        overlay_path = Path(path)
        if not overlay_path.is_absolute() and not overlay_path.exists():
            overlay_path = CONFIG_DIR / overlay_path
        if not overlay_path.exists():
            raise ConfigError(f"config overlay not found: {path}")
        with overlay_path.open("r", encoding="utf-8") as fh:
            data = _deep_merge(data, yaml.safe_load(fh) or {})
        sources.append(str(overlay_path))

    if use_env:
        env_overrides: dict[str, Any] = {}
        for key, raw in os.environ.items():
            if key.startswith("MAKAR__"):
                dotted = key.removeprefix("MAKAR__").replace("__", ".")
                env_overrides[dotted] = _coerce(raw)
        if env_overrides:
            cfg = MakarConfig(data, sources).with_overrides(env_overrides)
            data, sources = cfg.as_dict(), cfg.sources

    cfg = MakarConfig(data, sources)
    if overrides:
        cfg = cfg.with_overrides(overrides)
    return cfg


#: Process-wide default, loaded lazily so importing ``core`` stays cheap.
_default: MakarConfig | None = None


def default_config() -> MakarConfig:
    """Return (and memoise) the process-wide default configuration."""
    global _default
    if _default is None:
        _default = load_config()
    return _default
