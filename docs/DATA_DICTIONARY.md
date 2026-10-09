# Makar — Data Dictionary

Every field in the manifest, every evidence code the engines can emit, and
every attack class the generator can inject.

Regenerate the dataset this describes with:

```bash
python scripts/generate.py --seed 481516 --records 5000 --out out
```

---

## 1. Manifest record

One row = **one claimed cargo event for one container**. A container's full
history is the set of rows sharing its `container_id`, ordered by `timestamp`.

Delivered as `manifest_suspect.csv` and `manifest_suspect.json`, 25 columns in
the order below.

### 1.1 Required fields

| field | type | nullable | description |
|---|---|---|---|
| `record_id` | string | no | Primary key, `R######`. Dense and time-ordered in the clean manifest, so a deletion leaves a visible gap. |
| `cargo_type` | enum | yes | One of 20 cargo classes (§4). Determines the weight and value distributions a record is judged against. |
| `owner` | string | yes | Cargo owner's display name. May arrive as an alias, abbreviation or typo — the resolver folds these back. |
| `origin` | string | yes | Port the shipment started from, by display name. |
| `destination` | string | yes | Port the shipment is bound for, by display name. |
| `current_location` | string | yes | Port this event happened at, by display name. |
| `weight` | float | yes | Container gross weight in kg. Subject to conservation checks. |
| `container_count` | int | yes | Containers in the parent shipment. |
| `declared_value` | float | yes | Declared value in USD. Its ratio to `weight` is a tight invariant within a cargo class. |
| `status` | enum | yes | `IN_TRANSIT` · `AT_PORT` · `DELIVERED` · `HELD` · `CANCELLED`. Derived from `event_type`. |
| `timestamp` | datetime | yes | When the event occurred. The primary ordering key. |

### 1.2 Extended fields

| field | type | nullable | description |
|---|---|---|---|
| `shipment_id` | string | yes | Parent shipment, `SHIP_#####`. Live bookings use `SHIP_L#####`. |
| `container_id` | string | yes | The physical container, `CONT_######`. The unit almost all consistency reasoning is scoped to. |
| `route_id` | string | yes | Declared route, `ROUTE_##`. Resolves to an ordered port sequence. |
| `vessel_id` | string | yes | Carrying vessel, `VESSEL_##`. Supplies the speed envelope for feasibility checks. |
| `port_id` | string | yes | Canonical port id, `PORT_XXX`. The machine-readable counterpart of `current_location`. |
| `event_type` | enum | yes | Lifecycle event (§3). |
| `arrival_timestamp` | datetime | yes | Arrival of **this port call**. Shared by every record of the same call — which is how calls are grouped. |
| `departure_timestamp` | datetime | yes | Departure of this port call. `null` at a route terminus or while a voyage is in progress. May legitimately be in the future: it is a *schedule*. |
| `latitude` | float | yes | Event latitude, decimal degrees. |
| `longitude` | float | yes | Event longitude, decimal degrees. |
| `previous_location` | string | yes | Preceding port on the route. Empty at origin. |
| `next_location` | string | yes | Following port on the route. Empty at destination. |
| `source_node` | string | yes | Provenance node that reported the event: `A` · `B` · `C` · `D`. |
| `schema_version` | string | no | Manifest schema version, `1.0`. |

Two further fields exist on the typed model but are not in the delivered
export: `block_id` and `record_hash` are provenance bookkeeping, assigned by
the chain rather than by the reporting system.

### 1.3 Nullability, and what it means

The distinction matters because it is what stops the system flagging empty
cells as attacks.

**Structurally empty** — carries no information, never evidenced:
`departure_timestamp` (terminus or in-progress), `previous_location`
(origin), `next_location` (destination), `block_id`, `record_hash`.

**Benignly blankable** — populated in a clean export, may be lost by untidy
tooling; a blank here raises `FIELD_BLANK`, which is *exculpatory*:
`declared_value`, `vessel_id`, `container_count`, `status`, `latitude`,
`longitude`.

**Never legitimately empty** — `record_id`. A row without one gets a synthetic
id and `ID_FORMAT_INVALID`.

### 1.4 Formats the loader accepts

Real exports are messy, so the suspect manifest is too. All of these parse to
the same value, and each raises a low-severity `FORMAT` finding rather than an
error.

**Timestamps.** Convention: dashes mean day-first, slashes mean month-first —
two upstream systems with different locales.

| form | example |
|---|---|
| ISO with Z *(canonical)* | `2026-01-03T04:00:00Z` |
| ISO, no zone | `2026-01-03T04:00:00` |
| space separator | `2026-01-03 04:00:00` |
| sub-second | `2026-01-03T04:00:00.000Z` |
| explicit offset | `2026-01-03T04:00:00+00:00` |
| month-first slashes | `01/03/2026 04:00:00` |
| day-first dashes | `03-01-2026 04:00:00` |
| epoch seconds | `1767412800` |

**Numbers.** `12500.5` · `12,500.50` · `  12500.50  ` · `12500.50 kg` ·
`1.2500000000e+04` · `$1,250.00`

**Blank tokens.** `""` · `-` · `--` · `?` · `N/A` · `NULL` · `null` ·
`none` · `nil` · `unknown` · `unspecified` · `tbd` · `nan`

---

## 2. World model

The operator's master data: what legitimately exists. Supplied to the
detectors as `world.json`. **The injection log is not** — see §6.

| entity | id form | key fields |
|---|---|---|
| Port | `PORT_XXX` | `name`, `country`, `latitude`, `longitude`, `capacity_teu`, `dwell_mean_hours`, `dwell_sigma_hours` |
| Vessel | `VESSEL_##` | `name`, `cruise_speed_knots`, `max_speed_knots`, `capacity_containers`, `capacity_weight_kg` |
| Route | `ROUTE_##` | `port_sequence` (ordered), `vessel_id` |
| Owner | `OWNER_##` | `name`, `country`, `aliases` |
| Shipment | `SHIP_#####` | `owner_id`, `route_id`, `vessel_id`, `origin`, `destination`, `container_ids`, `created_at` |
| Container | `CONT_######` | `shipment_id`, `cargo_type`, `initial_weight_kg`, `declared_value`, `max_weight_kg` |

Default world: 18 ports, 26 vessels, 24 routes, 20 owners. Ports are real
locations with real coordinates across the Indian Ocean, Gulf and South-East
Asia; routes are contiguous slices of eight real trade corridors, so every
route is a geographically monotonic sailing order rather than a random port
set.

---

## 3. Event types

| event | meaning | in port? | mutates cargo? |
|---|---|---|---|
| `CREATED` | Container booked and sealed at origin | yes | no |
| `LOADED` | Cargo loaded | yes | **yes** |
| `DEPARTED` | Vessel cleared the port | no | no |
| `ARRIVED` | Vessel berthed | yes | no |
| `TRANSFERRED` | Custody or shipment reassigned | yes | **yes** |
| `INSPECTED` | Customs or safety inspection | yes | no |
| `UNLOADED` | Cargo discharged, in whole or part | yes | **yes** |
| `DELIVERED` | Delivered to consignee | yes | no |
| `CANCELLED` | Shipment cancelled | yes | no |

**Lifecycle order** is `CREATED → LOADED → DEPARTED → ARRIVED → TRANSFERRED →
UNLOADED → DELIVERED → CANCELLED`. `INSPECTED` imposes no ordering — it can
happen at any point during a port call.

Ordering is enforced **per (container, shipment)**, not per container:
containers are reused between bookings, and one delivered on `SHIP_00100` and
created again on `SHIP_00240` is normal.

Cargo state may change only across a call containing a cargo-mutating event.
A change without one is `WEIGHT_NOT_CONSERVED`.

---

## 4. Cargo classes

Weight is per container in kg; value density is USD/kg. These are what make
peer-group outlier detection meaningful — 27 tonnes is normal for cement and
impossible for pharmaceuticals.

| cargo type | weight (mean ± σ) | USD/kg | splittable |
|---|---|---:|---|
| `ELECTRONICS` | 9,500 ± 1,800 | 42.00 | no |
| `PHARMACEUTICALS` | 6,200 ± 1,200 | 180.00 | no |
| `TEXTILES` | 11,800 ± 2,400 | 9.50 | yes |
| `GARMENTS` | 10,400 ± 2,100 | 14.00 | yes |
| `MACHINERY` | 19,600 ± 3,900 | 22.00 | no |
| `AUTOMOTIVE_PARTS` | 16,300 ± 3,100 | 18.00 | yes |
| `STEEL_COILS` | 25,800 ± 2,600 | 1.40 | no |
| `COPPER_CATHODE` | 24,100 ± 2,200 | 8.60 | no |
| `CEMENT` | 27,200 ± 1,900 | 0.12 | yes |
| `PAPER_PULP` | 22,400 ± 2,800 | 0.85 | yes |
| `RICE` | 24,600 ± 2,300 | 0.55 | yes |
| `TEA` | 13,200 ± 2,600 | 4.80 | yes |
| `COFFEE` | 14,100 ± 2,700 | 5.60 | yes |
| `SPICES` | 12,600 ± 2,900 | 7.20 | yes |
| `RUBBER` | 18,900 ± 2,500 | 1.90 | yes |
| `PALM_OIL` | 23,800 ± 1,700 | 1.10 | yes |
| `CHEMICALS` | 20,700 ± 3,200 | 3.40 | no |
| `FROZEN_SEAFOOD` | 17,400 ± 2,400 | 11.50 | no |
| `FURNITURE` | 8,900 ± 2,200 | 6.40 | yes |
| `GLASSWARE` | 15,600 ± 2,800 | 3.10 | no |

*Splittable* cargo may be partially discharged at a transhipment hub, which is
why such a weight change is legitimate **when accompanied by an `UNLOADED`
event**. Weight is capped at 30,000 kg per container.

---

## 5. Evidence codes

49 codes across 10 reasoning layers. Severity is in `[0, 1]` and expresses the
detector's confidence that what it saw is *abnormal* — not that the record was
tampered with. Fusion weights live in `configs/default.yaml`.

### `BLOCKCHAIN` — weight 4.50

| code | meaning |
|---|---|
| `RECORD_HASH_MISMATCH` | Committed, but content now hashes differently: the record was **edited**. Reported as *inconclusive* at low severity when a hashed field was lost in the export, since a hash cannot tell "lost" from "edited". |
| `RECORD_NOT_IN_CHAIN` | Event time inside the sealed window with no commitment: **inserted**. |
| `NODE_STATE_DIVERGENCE` | A node commits a different hash than the majority. |
| `BLOCK_CHAIN_BROKEN` | Block hash linkage failed verification. |

### `TEMPORAL` — weight 2.20

| code | meaning |
|---|---|
| `SIMULTANEOUS_PRESENCE` | One container in two ports at overlapping times. Needs two records to agree to be impossible. |
| `REVERSE_CHRONOLOGY` | Arrival after departure for the same port call. |
| `IMPOSSIBLE_TRANSIT` | Two different ports with ≤ 0 elapsed time, so no speed is even defined. |
| `FUTURE_EVENT` | `timestamp` or `arrival_timestamp` after the analysis clock. `departure_timestamp` is excluded — it is a schedule. |
| `EVENT_ORDER_VIOLATION` | An event before `CREATED` or after `DELIVERED`, within the same shipment. |
| `DWELL_TIME_ANOMALY` | Port call far outside that port's learned dwell distribution. *Anomalous, not malicious* — ×0.35 multiplier. |
| `TIMESTAMP_MISSING` | No parseable timestamp. |
| `SEQUENCE_GAP` | Missing id in an otherwise dense sequence. Corroborating only — ×0.40. |

### `DUPLICATE` — weight 2.20

| code | meaning |
|---|---|
| `EXACT_DUPLICATE` | Identical canonical payload hash. |
| `STRUCTURAL_DUPLICATE` | Identical on owner, cargo, route, weight, timestamp, location; bookkeeping fields differ. |
| `FUZZY_DUPLICATE` | Field similarity above threshold, same event at the same port, inside the time window. |

### `SPATIAL` — weight 2.00

| code | meaning |
|---|---|
| `SPEED_INFEASIBLE` | Leg requires more than the vessel's maximum speed. Sea distance inflated ×1.25 over great-circle first. |
| `COORDINATE_PORT_MISMATCH` | Coordinates far from the declared port. ×0.80. |
| `COORDINATE_OUT_OF_RANGE` | Latitude/longitude outside valid ranges. |

### `ROUTE` — weight 2.00

| code | meaning |
|---|---|
| `OFF_ROUTE_PORT` | Port is not a call on the declared route. |
| `ROUTE_SEQUENCE_BREAK` | Route legs visited out of order. |
| `DESTINATION_CONTRADICTION` | Declared destination is not the route terminus. |
| `UNKNOWN_ROUTE` | Route absent from the world model. |

### `CARGO` — weight 1.95

| code | meaning |
|---|---|
| `WEIGHT_NOT_CONSERVED` | Weight changed across a transition with no cargo event. |
| `CARGO_DRIFT_UNEXPLAINED` | Cumulative drift across a run of transitions where **every individual step is inside** the per-step tolerance. The only finding a gradual siphon produces. |
| `VALUE_NOT_CONSERVED` | Declared value changed unexplained. |
| `CONTAINER_COUNT_NOT_CONSERVED` | Shipment container count changed. |
| `OWNER_CHANGED_WITHOUT_TRANSFER` | Owner changed with no `TRANSFERRED` event. |
| `CARGO_TYPE_MUTATED` | Cargo class changed mid-shipment. |
| `WEIGHT_EXCEEDS_CAPACITY` | Weight above the container's rated payload. |

### `GRAPH` — weight 1.85

| code | meaning |
|---|---|
| `ORPHAN_RECORD` | Two or more independent relationships failed: nothing accounts for the claim. |
| `LINEAGE_BREAK` | One failed relationship. ×0.70. |
| `MISSING_EXPECTED_EVENT` | A port call is missing an event its position implies. Lands on the *surviving* neighbours — ×0.70. |
| `GRAPH_CONFLICT` | Dependency conflict in the graph. |
| `UNKNOWN_ENTITY_REFERENCE` | References a container, shipment, vessel or port not in the world model. |

### `IDENTITY` — weight 1.20

`UNKNOWN_OWNER` · `OWNER_ALIAS_COLLISION` · `ID_FORMAT_INVALID`

### `STATISTICAL` — weight 0.80

| code | meaning |
|---|---|
| `PEER_GROUP_OUTLIER` | Robust z-outlier within its own cargo class, including on derived value-per-kg. |
| `ROBUST_Z_OUTLIER` | Robust z-outlier against the pooled baseline. |
| `IQR_OUTLIER` | Outside Tukey fences. ×0.60. |
| `ISOLATION_FOREST_OUTLIER` | Multivariate isolation. |
| `LOF_OUTLIER` | Sparse local neighbourhood. ×0.70. |
| `DBSCAN_NOISE` | Unclustered. ×0.50. |
| `DISTRIBUTION_SHIFT` | Shift against baseline. |

Severities are capped at 0.55 and the weight is the lowest of any
evidence-bearing layer: **statistical evidence alone can never convict.**

### `FORMAT` — weight **−0.90**

`FIELD_BLANK` · `TIMESTAMP_FORMAT_VARIANT` · `NAME_UNNORMALISED` ·
`NUMERIC_FORMAT_VARIANT` · `CASE_INCONSISTENCY`

The weight is negative on purpose: messiness is affirmative evidence of a
sloppy export rather than of a deliberate edit, so a scruffy legitimate row
is scored as *less* suspicious than a tidy forgery.

---

## 6. Private injection log

`ground_truth.json`. **Read only by `evaluation/` and the scoring scripts.
Nothing under `core/` imports it.**

| field | description |
|---|---|
| `seed`, `generated_at`, `config_digest` | Reproducibility metadata. |
| `clean_record_count`, `suspect_record_count` | Before and after. |
| `entries[]` | One per act of tampering or noise. |
| `summary` | Counts by attack class. |

Each entry: `entry_id`, `attack_class`, `attack_name`, `record_id`,
`source_record_id` (for copies), `deleted_record_id` (for removals), `fields`,
`before`, `after`, `cluster_id` (coordinated attacks), `target_time`, `notes`.

### 6.1 Attack classes

| class | description |
|---|---|
| `MODIFIED` | An existing record's values were changed. |
| `DELETED` | A record was removed from a coherent sequence. |
| `DUPLICATED` | A record was copied, exactly or with small perturbation. |
| `FABRICATED` | A record was invented with no legitimate lineage. |
| `NOISE` | **Benign** formatting irregularity. Flagging one of these is a false alarm. |

### 6.2 Attack names

**Single-record:** `weight_inflation` · `weight_deflation` ·
`value_inflation` · `value_deflation` · `owner_substitution` ·
`destination_rewrite` · `location_teleport` · `timestamp_future` ·
`timestamp_backdate` · `timestamp_reverse_chronology` ·
`timestamp_forward_shift` · `cargo_type_swap` · `container_count_tamper` ·
`record_deletion` · `exact_duplicate` · `near_duplicate` ·
`fabricated_record`

**Compound / coordinated**, prefixed `compound_`:
`modified_duplicated` · `deleted_route_manipulation` ·
`fabricated_timestamp_manipulation` · `near_duplicate_owner_change` ·
`multi_record_coordinated` · `cross_port_temporal`

Coordinated attacks target a narrow band of cargo-event time and share a
`cluster_id`, which is what makes attack-window inference possible.

**Noise kinds:** `blank` · `timestamp_format` · `number_format` ·
`owner_alias` · `case`

All noise is **lossless** — it changes how a value is written, never what it
is. (An earlier version used `%g` formatting and silently truncated
30,566.92 to 30,566.9, which injected a second class of tampering while
calling it harmless.)

### 6.3 Inserted record ids

Inserted rows draw from a pool mixing ids freed by deletions
(`corruption.id_recycle_probability`, default 0.35) with appended ids. If
every insertion appended, duplicate detection would collapse to
`WHERE id > 4987` and prove nothing. The id sequence is therefore used only in
the direction where it is legitimately informative: a **gap** suggests a
deletion.

---

## 7. Live stream

`generator/stream.py` produces events after the batch clock, carrying patterns
**absent from the batch data**. New bookings (`SHIP_L#####`,
`CONT_L#####`) are returned on the plan and must be registered in the world
model before processing — a real deployment receives a booking in master data
before its events flow.

| pattern | class | what it defeats |
|---|---|---|
| `weight_siphon` | `MODIFIED` | The per-step conservation **tolerance** — each step is inside it, the total is not. |
| `ghost_transfer` | `FABRICATED` | **Lineage** — a transfer at a port the container never reached. |
| `identity_swap` | `MODIFIED` | **Identity continuity** — two containers exchange ids mid-voyage. |

---

## 8. Provenance chain

`chain.json`, with per-node copies in `node_chains.json`.

**Block header:** `block_id`, `index`, `timestamp`, `previous_hash`,
`manifest_root`, `route_root`, `state_root`, `record_count`, `block_hash`.
**Body:** `record_hashes`, `record_ids`, `node_signatures` (Ed25519).

- `manifest_root` — Merkle root over the block's record hashes.
- `route_root` — Merkle root over the itineraries the block touches.
- `state_root` — `H(previous_state_root ‖ manifest_root ‖ route_root)`. The
  single value nodes compare.

Blocks hold **hashes only, never values**. Sealed over the first
`blockchain.sealed_fraction` (default 0.85) of the timeline; the remainder is
genuinely uncommitted.

Four nodes `A B C D` in the config topology. `nodes.compromised` (default
`[C]`) rewrites that node's chain to endorse the attacker's hashes, with every
root recomputed — so it passes its own integrity check and is revealed only by
cross-node comparison.
