"""Architectural guards.

These are the tests that keep the reported numbers meaningful. Everything else
measures how well the system performs; these check that it is not cheating.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: Packages that must never reach the detection pipeline.
FORBIDDEN_IN_CORE = {"generator", "evaluation"}

#: The answer key. Only the evaluator and the scoring scripts may read it.
GROUND_TRUTH = "ground_truth.json"


def _python_files(package: str) -> list[Path]:
    return sorted((ROOT / package).rglob("*.py"))


def _imported_roots(path: Path) -> set[str]:
    """Top-level package names imported by a module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


@pytest.mark.parametrize("path", _python_files("core"), ids=lambda p: str(p.relative_to(ROOT)))
def test_core_never_imports_the_generator_or_evaluator(path: Path) -> None:
    """``core/`` is the detection pipeline and must not see the answer key.

    The world model is legitimate master data and is passed *in* as an
    argument. The injection log is not, and the only way to be sure is to
    forbid the import outright -- a convention in a docstring would not
    survive a late-night change.
    """
    offending = _imported_roots(path) & FORBIDDEN_IN_CORE
    assert not offending, (
        f"{path.relative_to(ROOT)} imports {sorted(offending)}. The detection "
        f"pipeline must not depend on the generator or the evaluator."
    )


@pytest.mark.parametrize(
    "package", ["core", "backend", "blockchain", "reporting"],
)
def test_ground_truth_is_only_read_by_the_evaluator(package: str) -> None:
    """No module outside ``evaluation/`` and ``scripts/`` may name the answer key."""
    for path in _python_files(package):
        text = path.read_text(encoding="utf-8")
        # Mentions in prose are fine; a string literal naming the file is not.
        assert f'"{GROUND_TRUTH}"' not in text and f"'{GROUND_TRUTH}'" not in text, (
            f"{path.relative_to(ROOT)} references {GROUND_TRUTH}. Only "
            f"evaluation/ and the scoring scripts may read the answer key."
        )


def test_evaluation_is_the_only_package_that_loads_the_log() -> None:
    """Positive control: the evaluator *does* read it, so the guard is real."""
    text = (ROOT / "evaluation" / "ground_truth.py").read_text(encoding="utf-8")
    assert "InjectionLog" in text


def test_no_hardcoded_detection_thresholds_in_core() -> None:
    """Tunables live in config, so the twist is a retune rather than a rewrite.

    Checked structurally: every detector engine must reach for ``ctx.cfg`` or
    ``cfg.`` at least once. A detector with no configuration lookup is either
    trivial or has a constant baked in.
    """
    engines = [
        ROOT / "core" / "temporal" / "engine.py",
        ROOT / "core" / "geospatial" / "engine.py",
        ROOT / "core" / "detection" / "route.py",
        ROOT / "core" / "detection" / "cargo.py",
        ROOT / "core" / "detection" / "duplicates.py",
        ROOT / "core" / "detection" / "statistical.py",
        ROOT / "core" / "detection" / "provenance.py",
        ROOT / "core" / "graph" / "engine.py",
    ]
    for path in engines:
        text = path.read_text(encoding="utf-8")
        assert "cfg." in text, (
            f"{path.relative_to(ROOT)} never reads configuration. Detection "
            f"thresholds must be tunable without editing code."
        )


def test_every_evidence_code_is_mapped_and_labelled() -> None:
    """A code with no layer or no label would break fusion and the UI silently."""
    from core.types import EVIDENCE_CODE_TYPE, EVIDENCE_LABEL, EvidenceCode

    codes = list(EvidenceCode)
    unmapped = [c for c in codes if c not in EVIDENCE_CODE_TYPE]
    unlabelled = [c for c in codes if c not in EVIDENCE_LABEL]
    assert not unmapped, f"evidence codes with no layer: {unmapped}"
    assert not unlabelled, f"evidence codes with no label: {unlabelled}"


def test_every_evidence_layer_has_a_fusion_weight() -> None:
    """An unweighted layer would contribute nothing and nobody would notice."""
    from core.config import load_config
    from core.types import EvidenceType

    weights = load_config().get("fusion.weights")
    missing = [t for t in EvidenceType if str(t) not in weights]
    assert not missing, f"evidence layers with no fusion weight: {missing}"


def test_format_evidence_is_exculpatory() -> None:
    """FORMAT must weigh negative, or 'not every oddity is an attack' is a slogan."""
    from core.config import load_config

    weights = load_config().get("fusion.weights")
    assert weights["FORMAT"] < 0, (
        "FORMAT evidence must carry a negative weight so that benign messiness "
        "lowers the tampering score rather than raising it."
    )


def test_statistical_evidence_cannot_convict_alone() -> None:
    """Spec 13: the statistical layer generates evidence, never a verdict."""
    from core.config import load_config

    cfg = load_config()
    weight = cfg.float_("fusion.weights.STATISTICAL")
    ceiling = cfg.float_("detection.statistical.max_severity")
    threshold = cfg.float_("fusion.thresholds.suspicious")
    prior = cfg.float_("fusion.prior_tampering_rate")

    import math

    # Best case for the statistical layer: its severity ceiling, at full
    # aggregation, with nothing else contributing.
    base_logit = math.log(prior / (1 - prior))
    best = 1.0 / (1.0 + math.exp(-(base_logit + weight * ceiling)))
    assert best < threshold, (
        f"statistical evidence alone reaches {best:.3f}, at or above the "
        f"suspicion threshold {threshold}. It must never be sufficient."
    )
