"""Great-circle geometry.

Kept dependency-light on purpose: Haversine on a spherical earth is accurate
to roughly 0.5% over shipping distances, which is far inside the tolerance
of a feasibility check whose speed envelope is itself configurable. Shapely
and PyProj are used only where real geodesic work is needed (buffering,
projection) rather than for every distance in the hot loop.
"""

from __future__ import annotations

import math

#: Mean earth radius, kilometres.
EARTH_RADIUS_KM = 6371.0088

#: One nautical mile in kilometres. Vessel speeds are expressed in knots
#: (nautical miles per hour), so distances convert through this.
KM_PER_NAUTICAL_MILE = 1.852


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in kilometres between two ``(lat, lon)`` points."""
    lat1, lon1 = a
    lat2, lon2 = b
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlambda = math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(min(1.0, h)))


def haversine_nm(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in nautical miles."""
    return haversine_km(a, b) / KM_PER_NAUTICAL_MILE


def sea_distance_nm(
    a: tuple[float, float], b: tuple[float, float], route_factor: float = 1.25
) -> float:
    """Approximate sailed distance in nautical miles.

    A great-circle line runs through land masses, so the true sea lane is
    always longer. ``route_factor`` inflates the straight-line distance to
    compensate; it is configurable because an under-estimate here produces
    false IMPOSSIBLE_TRANSIT flags, which is the expensive kind of error.
    """
    return haversine_nm(a, b) * route_factor


def bearing_deg(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Initial great-circle bearing from ``a`` to ``b``, in degrees."""
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlon = lon2 - lon1
    x = math.sin(dlon) * math.cos(lat2)
    y = math.cos(lat1) * math.sin(lat2) - math.sin(lat1) * math.cos(lat2) * math.cos(dlon)
    return (math.degrees(math.atan2(x, y)) + 360.0) % 360.0


def interpolate(
    a: tuple[float, float], b: tuple[float, float], fraction: float
) -> tuple[float, float]:
    """Point a given ``fraction`` of the way along the great circle from a to b.

    Used to place a vessel between two ports for the map's timeline slider
    (spec 26.6) and to synthesise plausible mid-ocean coordinates.
    """
    fraction = max(0.0, min(1.0, fraction))
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])

    d = haversine_km(a, b) / EARTH_RADIUS_KM
    if d < 1e-12:
        return a

    sin_d = math.sin(d)
    f1 = math.sin((1 - fraction) * d) / sin_d
    f2 = math.sin(fraction * d) / sin_d

    x = f1 * math.cos(lat1) * math.cos(lon1) + f2 * math.cos(lat2) * math.cos(lon2)
    y = f1 * math.cos(lat1) * math.sin(lon1) + f2 * math.cos(lat2) * math.sin(lon2)
    z = f1 * math.sin(lat1) + f2 * math.sin(lat2)

    lat = math.atan2(z, math.hypot(x, y))
    lon = math.atan2(y, x)
    return (math.degrees(lat), math.degrees(lon))


def required_speed_knots(distance_nm: float, elapsed_seconds: float) -> float | None:
    """Speed needed to cover ``distance_nm`` in ``elapsed_seconds``.

    Returns ``None`` when the elapsed time is non-positive: that is a
    *temporal* contradiction (reverse chronology) and must be reported by the
    temporal engine, not silently converted into an infinite speed here.
    """
    if elapsed_seconds <= 0:
        return None
    return distance_nm / (elapsed_seconds / 3600.0)


def coords_valid(lat: float | None, lon: float | None) -> bool:
    """True when both coordinates are present and within valid ranges."""
    if lat is None or lon is None:
        return False
    if math.isnan(lat) or math.isnan(lon):
        return False
    return -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0
