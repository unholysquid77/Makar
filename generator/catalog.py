"""Reference data for the synthetic world.

Real ports with real coordinates, real trade corridors, and cargo profiles
with plausible weight/value densities. This matters more than it looks: the
statistical engine has to discover what "normal" means with no labels, so
the generated world must contain genuine structure to discover. A manifest of
uniform random weights would make outlier detection either trivial or
meaningless, and would not survive a judge asking why the numbers look the
way they do.
"""

from __future__ import annotations

from typing import NamedTuple


class PortSpec(NamedTuple):
    port_id: str
    name: str
    country: str
    lat: float
    lon: float
    #: Rough annual throughput class, used for dwell distribution and for
    #: peer-grouping ports of comparable size.
    capacity_teu: int
    dwell_mean_hours: float
    dwell_sigma_hours: float


#: Indian Ocean / Gulf / South-East Asia network. Coordinates are the actual
#: port locations, not the city centroids, where the two differ meaningfully.
PORT_CATALOG: tuple[PortSpec, ...] = (
    PortSpec("PORT_MUM", "Mumbai", "India", 19.0760, 72.8777, 5_100_000, 22.0, 9.0),
    PortSpec("PORT_NSA", "Nhava Sheva", "India", 18.9490, 72.9525, 6_400_000, 26.0, 11.0),
    PortSpec("PORT_MUN", "Mundra", "India", 22.8394, 69.7219, 6_500_000, 20.0, 8.0),
    PortSpec("PORT_KOC", "Kochi", "India", 9.9312, 76.2673, 740_000, 16.0, 7.0),
    PortSpec("PORT_CHE", "Chennai", "India", 13.0827, 80.2707, 1_600_000, 24.0, 10.0),
    PortSpec("PORT_KOL", "Kolkata", "India", 22.5726, 88.3639, 800_000, 30.0, 13.0),
    PortSpec("PORT_COL", "Colombo", "Sri Lanka", 6.9271, 79.8612, 7_200_000, 18.0, 8.0),
    PortSpec("PORT_MLE", "Male", "Maldives", 4.1755, 73.5093, 120_000, 14.0, 6.0),
    PortSpec("PORT_KHI", "Karachi", "Pakistan", 24.8607, 67.0011, 2_100_000, 28.0, 12.0),
    PortSpec("PORT_CTG", "Chittagong", "Bangladesh", 22.3569, 91.7832, 3_200_000, 34.0, 14.0),
    PortSpec("PORT_YGN", "Yangon", "Myanmar", 16.8409, 96.1735, 1_100_000, 32.0, 13.0),
    PortSpec("PORT_DXB", "Jebel Ali", "UAE", 25.0107, 55.0617, 14_100_000, 16.0, 7.0),
    PortSpec("PORT_AUH", "Khalifa", "UAE", 24.4539, 54.3773, 3_000_000, 18.0, 8.0),
    PortSpec("PORT_DMM", "Dammam", "Saudi Arabia", 26.4207, 50.0888, 1_800_000, 22.0, 9.0),
    PortSpec("PORT_JEA", "Jeddah", "Saudi Arabia", 21.4858, 39.1925, 4_800_000, 20.0, 9.0),
    PortSpec("PORT_SAL", "Salalah", "Oman", 17.0151, 54.0924, 4_300_000, 14.0, 6.0),
    PortSpec("PORT_SIN", "Singapore", "Singapore", 1.2644, 103.8200, 37_200_000, 12.0, 5.0),
    PortSpec("PORT_TPP", "Tanjung Pelepas", "Malaysia", 1.3667, 103.5500, 10_500_000, 14.0, 6.0),
    PortSpec("PORT_PKL", "Port Klang", "Malaysia", 3.0000, 101.4000, 13_200_000, 16.0, 7.0),
    PortSpec("PORT_JKT", "Tanjung Priok", "Indonesia", -6.1045, 106.8800, 7_800_000, 24.0, 10.0),
    PortSpec("PORT_BKK", "Laem Chabang", "Thailand", 13.0827, 100.8833, 8_700_000, 20.0, 9.0),
    PortSpec("PORT_HPH", "Haiphong", "Vietnam", 20.8449, 106.6881, 5_900_000, 22.0, 9.0),
    PortSpec("PORT_HKG", "Hong Kong", "Hong Kong", 22.3193, 114.1694, 17_300_000, 13.0, 6.0),
    PortSpec("PORT_SHA", "Shanghai", "China", 31.2304, 121.4737, 47_300_000, 15.0, 6.0),
)


#: Geographically coherent trade corridors. Routes are drawn as contiguous
#: subsequences of these, so every route is a plausible sailing order rather
#: than a random permutation of ports.
CORRIDORS: tuple[tuple[str, ...], ...] = (
    # West India -> Gulf
    ("PORT_MUN", "PORT_NSA", "PORT_MUM", "PORT_KHI", "PORT_DMM", "PORT_DXB", "PORT_AUH"),
    # West India -> South-East Asia (the Mumbai-Colombo-Singapore spine)
    ("PORT_NSA", "PORT_MUM", "PORT_COL", "PORT_PKL", "PORT_SIN", "PORT_TPP", "PORT_JKT"),
    # Bay of Bengal -> South-East Asia
    ("PORT_KOL", "PORT_CTG", "PORT_YGN", "PORT_CHE", "PORT_COL", "PORT_SIN"),
    # Gulf -> Far East
    ("PORT_DXB", "PORT_SAL", "PORT_MLE", "PORT_COL", "PORT_SIN", "PORT_HKG", "PORT_SHA"),
    # Red Sea -> India
    ("PORT_JEA", "PORT_SAL", "PORT_MUN", "PORT_MUM", "PORT_KOC", "PORT_CHE"),
    # Intra-Asia feeder loop
    ("PORT_SIN", "PORT_BKK", "PORT_HPH", "PORT_HKG", "PORT_SHA"),
    # South India -> Maldives -> Gulf
    ("PORT_KOC", "PORT_MLE", "PORT_SAL", "PORT_DXB", "PORT_AUH"),
    # East coast India -> Gulf
    ("PORT_CHE", "PORT_COL", "PORT_KOC", "PORT_MUM", "PORT_DXB"),
)


class VesselClass(NamedTuple):
    label: str
    cruise_knots: float
    max_knots: float
    capacity_containers: int
    capacity_weight_kg: float


#: Speed envelopes are the real constraint the feasibility engine leans on,
#: so they are per-class rather than one global number. A feeder genuinely
#: cannot do 24 knots; a ULCV genuinely can.
VESSEL_CLASSES: tuple[VesselClass, ...] = (
    VesselClass("Feeder", 14.0, 19.0, 700, 9_000_000.0),
    VesselClass("Handysize", 16.0, 21.0, 1_200, 15_000_000.0),
    VesselClass("Panamax", 19.0, 24.0, 4_500, 55_000_000.0),
    VesselClass("Post-Panamax", 21.0, 26.0, 9_000, 110_000_000.0),
    VesselClass("ULCV", 22.0, 28.0, 18_000, 200_000_000.0),
)

VESSEL_NAME_PREFIX: tuple[str, ...] = (
    "MV",
    "MSC",
    "OOCL",
    "CMA",
    "ONE",
    "HMM",
    "Maersk",
    "Evergreen",
    "Wan Hai",
    "SITC",
)

VESSEL_NAME_SUFFIX: tuple[str, ...] = (
    "Meridian",
    "Horizon",
    "Equinox",
    "Monsoon",
    "Albatross",
    "Pioneer",
    "Lodestar",
    "Trident",
    "Zephyr",
    "Mariner",
    "Sentinel",
    "Corsair",
    "Kestrel",
    "Nimbus",
    "Orion",
    "Cascade",
    "Beacon",
    "Tempest",
    "Vanguard",
    "Harbinger",
)


class CargoProfile(NamedTuple):
    """Weight and value density for one cargo type.

    ``weight_mean_kg`` is per container. ``value_per_kg`` sets declared value,
    so a container of pharmaceuticals is light and expensive while a container
    of cement is heavy and cheap -- exactly the kind of structure that lets
    peer-group outlier detection work without labels.
    """

    name: str
    weight_mean_kg: float
    weight_sigma_kg: float
    value_per_kg: float
    value_sigma_frac: float
    #: True for cargo that is plausibly split/merged at transhipment hubs,
    #: which the conservation engine must tolerate given a LOADED/UNLOADED.
    splittable: bool


CARGO_PROFILES: tuple[CargoProfile, ...] = (
    CargoProfile("ELECTRONICS", 9_500.0, 1_800.0, 42.0, 0.25, False),
    CargoProfile("PHARMACEUTICALS", 6_200.0, 1_200.0, 180.0, 0.30, False),
    CargoProfile("TEXTILES", 11_800.0, 2_400.0, 9.5, 0.22, True),
    CargoProfile("GARMENTS", 10_400.0, 2_100.0, 14.0, 0.25, True),
    CargoProfile("MACHINERY", 19_600.0, 3_900.0, 22.0, 0.28, False),
    CargoProfile("AUTOMOTIVE_PARTS", 16_300.0, 3_100.0, 18.0, 0.24, True),
    CargoProfile("STEEL_COILS", 25_800.0, 2_600.0, 1.4, 0.15, False),
    CargoProfile("COPPER_CATHODE", 24_100.0, 2_200.0, 8.6, 0.12, False),
    CargoProfile("CEMENT", 27_200.0, 1_900.0, 0.12, 0.10, True),
    CargoProfile("PAPER_PULP", 22_400.0, 2_800.0, 0.85, 0.14, True),
    CargoProfile("RICE", 24_600.0, 2_300.0, 0.55, 0.12, True),
    CargoProfile("TEA", 13_200.0, 2_600.0, 4.8, 0.30, True),
    CargoProfile("COFFEE", 14_100.0, 2_700.0, 5.6, 0.28, True),
    CargoProfile("SPICES", 12_600.0, 2_900.0, 7.2, 0.35, True),
    CargoProfile("RUBBER", 18_900.0, 2_500.0, 1.9, 0.18, True),
    CargoProfile("PALM_OIL", 23_800.0, 1_700.0, 1.1, 0.16, True),
    CargoProfile("CHEMICALS", 20_700.0, 3_200.0, 3.4, 0.26, False),
    CargoProfile("FROZEN_SEAFOOD", 17_400.0, 2_400.0, 11.5, 0.27, False),
    CargoProfile("FURNITURE", 8_900.0, 2_200.0, 6.4, 0.30, True),
    CargoProfile("GLASSWARE", 15_600.0, 2_800.0, 3.1, 0.24, False),
)


#: Owner companies. Each gets a canonical name plus the alias spellings the
#: noise injector may substitute -- abbreviations, case drift, punctuation
#: drift and one plausible typo. The entity resolver has to fold these back
#: together, and must not report doing so as tampering (spec 6.3).
OWNER_SEEDS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "Meridian Freight Pvt Ltd",
        "India",
        ("Meridian Freight", "MERIDIAN FREIGHT PVT. LTD.", "Meridian Frieght Pvt Ltd"),
    ),
    (
        "Harbour Line Logistics",
        "Singapore",
        ("Harbour Line", "HARBOUR LINE LOGISTICS", "Harbor Line Logistics"),
    ),
    (
        "Deccan Export Corporation",
        "India",
        ("Deccan Export Corp", "DECCAN EXPORT CORPORATION", "Deccan Exports Corporation"),
    ),
    (
        "Al Nahda Trading LLC",
        "UAE",
        ("Al Nahda Trading", "AL NAHDA TRADING L.L.C.", "Al-Nahda Trading LLC"),
    ),
    (
        "Serendib Cargo Holdings",
        "Sri Lanka",
        ("Serendib Cargo", "SERENDIB CARGO HOLDINGS", "Serendip Cargo Holdings"),
    ),
    (
        "Pearl Delta Shipping",
        "Hong Kong",
        ("Pearl Delta", "PEARL DELTA SHIPPING", "Pearl Detla Shipping"),
    ),
    (
        "Bay Trade Enterprises",
        "Bangladesh",
        ("Bay Trade", "BAY TRADE ENTERPRISES", "Bay Trade Enterprise"),
    ),
    (
        "Indus Maritime Agencies",
        "Pakistan",
        ("Indus Maritime", "INDUS MARITIME AGENCIES", "Indus Martime Agencies"),
    ),
    (
        "Golden Teak Exporters",
        "Myanmar",
        ("Golden Teak", "GOLDEN TEAK EXPORTERS", "Golden Teek Exporters"),
    ),
    (
        "Strait Commodity Partners",
        "Malaysia",
        ("Strait Commodity", "STRAIT COMMODITY PARTNERS", "Straits Commodity Partners"),
    ),
    (
        "Nusantara Bulk Lines",
        "Indonesia",
        ("Nusantara Bulk", "NUSANTARA BULK LINES", "Nusantra Bulk Lines"),
    ),
    (
        "Siam Gulf Forwarding",
        "Thailand",
        ("Siam Gulf", "SIAM GULF FORWARDING", "Siam Gulf Forwardings"),
    ),
    (
        "Red Sea Mercantile",
        "Saudi Arabia",
        ("Red Sea Merc", "RED SEA MERCANTILE", "Red See Mercantile"),
    ),
    (
        "Coromandel Shipping Co",
        "India",
        ("Coromandel Shipping", "COROMANDEL SHIPPING CO.", "Coromandal Shipping Co"),
    ),
    (
        "Dhivehi Island Traders",
        "Maldives",
        ("Dhivehi Island", "DHIVEHI ISLAND TRADERS", "Dhivehi Islands Traders"),
    ),
    (
        "Yangtze Union Cargo",
        "China",
        ("Yangtze Union", "YANGTZE UNION CARGO", "Yangzte Union Cargo"),
    ),
    (
        "Mekong River Freight",
        "Vietnam",
        ("Mekong River", "MEKONG RIVER FREIGHT", "Mekhong River Freight"),
    ),
    (
        "Arabian Coast Logistics",
        "Oman",
        ("Arabian Coast", "ARABIAN COAST LOGISTICS", "Arabian Coasts Logistics"),
    ),
    (
        "Konkan Container Services",
        "India",
        ("Konkan Container", "KONKAN CONTAINER SERVICES", "Konkan Containers Services"),
    ),
    (
        "Equator Bulk Carriers",
        "Singapore",
        ("Equator Bulk", "EQUATOR BULK CARRIERS", "Equitor Bulk Carriers"),
    ),
)


#: Statuses a record may carry, with the event types that produce them.
STATUS_BY_EVENT: dict[str, str] = {
    "CREATED": "AT_PORT",
    "LOADED": "AT_PORT",
    "DEPARTED": "IN_TRANSIT",
    "ARRIVED": "AT_PORT",
    "TRANSFERRED": "AT_PORT",
    "INSPECTED": "HELD",
    "UNLOADED": "AT_PORT",
    "DELIVERED": "DELIVERED",
    "CANCELLED": "CANCELLED",
}

CARGO_PROFILE_BY_NAME: dict[str, CargoProfile] = {p.name: p for p in CARGO_PROFILES}
PORT_SPEC_BY_ID: dict[str, PortSpec] = {p.port_id: p for p in PORT_CATALOG}
