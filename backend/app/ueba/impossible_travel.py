"""
Impossible-travel detection using haversine distance.

Flags auth events where the same user appears in two locations whose
physical distance cannot be covered in the elapsed time at any realistic speed.

Thresholds are configurable via environment variables:
  UEBA_MAX_SPEED_KMH      — max plausible travel speed (default: 900 km/h, ~aircraft)
  UEBA_MIN_DISTANCE_KM    — minimum distance to flag (default: 500 km, ignore intra-region)
"""
from __future__ import annotations

import math
import os

_EARTH_RADIUS_KM = 6_371.0
_MAX_SPEED_KMH   = float(os.getenv("UEBA_MAX_SPEED_KMH",   "900"))   # commercial aircraft
_MIN_DISTANCE_KM = float(os.getenv("UEBA_MIN_DISTANCE_KM", "500"))   # ignore intra-region


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two lat/lon points."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    )
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def is_impossible_travel(
    prev_lat: float,
    prev_lon: float,
    prev_ts: float,
    curr_lat: float,
    curr_lon: float,
    curr_ts: float,
) -> bool:
    """Return True when implied travel speed exceeds _MAX_SPEED_KMH."""
    distance_km = haversine_km(prev_lat, prev_lon, curr_lat, curr_lon)
    if distance_km < _MIN_DISTANCE_KM:
        return False

    elapsed_h = (curr_ts - prev_ts) / 3_600.0
    if elapsed_h <= 0:
        return True  # same instant, different continent

    return (distance_km / elapsed_h) > _MAX_SPEED_KMH
