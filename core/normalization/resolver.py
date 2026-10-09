"""Entity resolution against the operator's master data.

A deliberate scoping decision, worth stating plainly because it affects how
the evaluation should be read: the resolver is given the **world model** --
the ports, vessels, routes, owners and containers the shipping company
operates. That is legitimate master data. A real forensic analyst absolutely
knows which ports their line calls at and who their customers are.

What the system is *never* given is the injection log. The world model says
what exists; it says nothing about which records were touched. Everything the
detectors conclude is derived from the manifest's internal consistency
against that reference data.
"""

from __future__ import annotations

from difflib import SequenceMatcher

from core.models import World
from core.normalization.parsers import is_blank


def _fold(text: str) -> str:
    """Aggressive casefold for matching: drop punctuation and spacing."""
    return "".join(ch for ch in text.casefold() if ch.isalnum())


class Resolution:
    """Outcome of resolving one free-text value to a known entity."""

    __slots__ = ("value", "entity_id", "method", "score")

    def __init__(self, value: str | None, entity_id: str | None, method: str, score: float) -> None:
        #: Canonical display value, e.g. ``"Meridian Freight Pvt Ltd"``.
        self.value = value
        #: Canonical identifier, e.g. ``"OWNER_01"`` or ``"PORT_COL"``.
        self.entity_id = entity_id
        #: ``exact`` | ``alias`` | ``fuzzy`` | ``unknown`` | ``blank``
        self.method = method
        self.score = score

    @property
    def resolved(self) -> bool:
        return self.entity_id is not None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"Resolution({self.value!r}, {self.entity_id!r}, {self.method}, {self.score:.2f})"


_BLANK = Resolution(None, None, "blank", 0.0)


class EntityResolver:
    """Folds manifest spellings back onto canonical world entities."""

    def __init__(self, world: World, fuzzy_threshold: float = 0.88) -> None:
        self.world = world
        self.fuzzy_threshold = fuzzy_threshold

        # --- owners: canonical name, aliases, and folded forms ---
        self._owner_exact: dict[str, str] = {}
        self._owner_display: dict[str, str] = {}
        for owner in world.owners.values():
            self._owner_display[owner.owner_id] = owner.name
            self._owner_exact[_fold(owner.name)] = owner.owner_id
            self._owner_exact[_fold(owner.owner_id)] = owner.owner_id
            for alias in owner.aliases:
                self._owner_exact.setdefault(_fold(alias), owner.owner_id)
        self._owner_folded = list(self._owner_exact.items())

        # --- ports: id and display name ---
        self._port_exact: dict[str, str] = {}
        for port in world.ports.values():
            self._port_exact[_fold(port.port_id)] = port.port_id
            self._port_exact[_fold(port.name)] = port.port_id
        self._port_folded = list(self._port_exact.items())

        self._cargo_exact = {_fold(c): c for c in world.cargo_types}
        self._routes = set(world.routes)
        self._vessels = set(world.vessels)
        self._containers = set(world.containers)
        self._shipments = set(world.shipments)

    # -- generic ---------------------------------------------------------

    def _fuzzy(
        self, needle: str, table: list[tuple[str, str]]
    ) -> tuple[str | None, float]:
        """Best fuzzy match above threshold, or ``(None, score)``."""
        best_id: str | None = None
        best_score = 0.0
        for folded, entity_id in table:
            score = SequenceMatcher(None, needle, folded).ratio()
            if score > best_score:
                best_score, best_id = score, entity_id
        if best_score >= self.fuzzy_threshold:
            return best_id, best_score
        return None, best_score

    # -- owners ----------------------------------------------------------

    def resolve_owner(self, value: str | None) -> Resolution:
        """Resolve an owner spelling, alias or typo to a canonical owner.

        A blank token (``"N/A"``, ``"null"``, ``"--"``) resolves to *absent*,
        never to "unknown entity". Reporting an empty cell as a reference to a
        nonexistent company would be a false alarm, and false alarms are the
        expensive failure mode here.
        """
        if is_blank(value):
            return _BLANK
        folded = _fold(str(value))
        if not folded:
            return _BLANK

        owner_id = self._owner_exact.get(folded)
        if owner_id:
            canonical = self._owner_display[owner_id]
            # "exact" means the export already wrote the canonical string.
            # Anything else -- punctuation drift, abbreviation, case drift --
            # is an alias we folded back, and is worth reporting as benign.
            method = "exact" if str(value).strip() in (canonical, owner_id) else "alias"
            return Resolution(canonical, owner_id, method, 1.0)

        owner_id, score = self._fuzzy(folded, self._owner_folded)
        if owner_id:
            return Resolution(self._owner_display[owner_id], owner_id, "fuzzy", score)
        return Resolution(value.strip(), None, "unknown", score)

    def owner_id_for(self, value: str | None) -> str | None:
        return self.resolve_owner(value).entity_id

    # -- ports -----------------------------------------------------------

    def resolve_port(self, value: str | None) -> Resolution:
        """Resolve a port id or display name to a canonical port id.

        The manifest legitimately carries display names in location columns
        and ids in ``port_id``, so both count as exact.
        """
        if is_blank(value):
            return _BLANK
        folded = _fold(str(value))
        if not folded:
            return _BLANK

        port_id = self._port_exact.get(folded)
        if port_id:
            port = self.world.ports[port_id]
            method = "exact" if str(value).strip() in (port.port_id, port.name) else "alias"
            return Resolution(port.name, port_id, method, 1.0)

        port_id, score = self._fuzzy(folded, self._port_folded)
        if port_id:
            return Resolution(self.world.ports[port_id].name, port_id, "fuzzy", score)
        return Resolution(value.strip(), None, "unknown", score)

    def port_id_for(self, value: str | None) -> str | None:
        return self.resolve_port(value).entity_id

    # -- other entity classes --------------------------------------------

    def resolve_cargo_type(self, value: str | None) -> Resolution:
        if is_blank(value):
            return _BLANK
        folded = _fold(str(value))
        if not folded:
            return _BLANK
        canonical = self._cargo_exact.get(folded)
        if canonical:
            method = "exact" if str(value).strip() == canonical else "alias"
            return Resolution(canonical, canonical, method, 1.0)
        match, score = self._fuzzy(folded, list(self._cargo_exact.items()))
        if match:
            return Resolution(match, match, "fuzzy", score)
        return Resolution(str(value).strip(), None, "unknown", score)

    # ``known_*`` treats a blank token as "not referenced" rather than as a
    # reference to something missing -- see :meth:`resolve_owner`.

    def known_route(self, route_id: str | None) -> bool:
        return not is_blank(route_id) and route_id in self._routes

    def known_vessel(self, vessel_id: str | None) -> bool:
        return not is_blank(vessel_id) and vessel_id in self._vessels

    def known_container(self, container_id: str | None) -> bool:
        return not is_blank(container_id) and container_id in self._containers

    def known_shipment(self, shipment_id: str | None) -> bool:
        return not is_blank(shipment_id) and shipment_id in self._shipments
