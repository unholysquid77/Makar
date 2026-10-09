# Makar — Demo Guide & Platform Walkthrough

Everything you need to present this: the script, every feature, every formula,
every number, and the answers to the questions you are going to get asked.

**Keep this open on a second screen.** §10 is a one-page cheat sheet.

---

## 1. The 60-second pitch

> A shipping company's manifest is the single source of truth for customs,
> insurance, billing and port scheduling. After a cyberattack, nobody knows
> which of 5,000 records can still be trusted.
>
> Makar takes the suspect manifest and reconstructs a trustworthy one. It
> fuses eight independent reasoning layers — temporal, spatial, route, cargo
> conservation, duplicates, statistics, graph lineage, and a tamper-evident
> provenance chain — into one calibrated probability per record, with the
> arithmetic shown.
>
> Every record in the output is marked **ORIGINAL**, **REPAIRED**, **REMOVED**
> or **UNRECOVERABLE**. Nothing is silently changed.
>
> **Precision 0.99, recall 0.91, and zero false alarms on records that were
> only messy** — which is the half of this problem that's easy to lose. And
> when the attacker went live mid-event, it caught **45 out of 45** real-time
> edits without alerting on a single legitimate operator correction.

**If you say one thing, say this:** *every flag, repair and removal is
explainable, because no detector is allowed to reach a verdict on its own.*

---

## 2. Before you present

```bash
# 1. Generate the dataset (1.5 s)
.venv/Scripts/python.exe scripts/generate.py --seed 481516 --records 5000 --out out

# 2. Score it, render the report, replay the live feed (~11 s)
.venv/Scripts/python.exe scripts/evaluate.py  --out out --ablation
.venv/Scripts/python.exe scripts/report.py    --out out --top 25
.venv/Scripts/python.exe scripts/stream_sim.py --out out --events 900

# or all of it in one go
.venv/Scripts/python.exe scripts/demo.py
```

Then two terminals:

```bash
.venv/Scripts/python.exe -m backend.main      # API  :8000
```

```bash
npm --prefix frontend run dev                 # UI   :5173
```

### Pre-flight checklist

- [ ] `frontend/.env.local` has `VITE_CARTO_API_KEY=...` — **without it the map
      has no basemap tiles** (all forensic geometry still draws, and the UI
      says so, but it looks much better with it)
- [ ] API responds: `curl localhost:8000/health`
- [ ] Open **Command Center** and confirm it reads 5,051 records
- [ ] Open **Live** and press *Generate feed* once, so the first run is warm
- [ ] Have `out/report.md` open in an editor as a fallback if the UI misbehaves
- [ ] `python -m pytest tests/ -q` → **131 passed** (good thing to have on screen)

---

## 3. The ten-minute demo script

Numbers below are from seed `481516`. They will match exactly if you
regenerated with that seed.

### Step 1 — Command Center *(45 s)*

> "5,051 records came in. 225 are suspicious. But the output isn't a score —
> it's a **reconstructed manifest**: 4,826 original, 103 repaired, 100 removed,
> 22 unrecoverable. Every record carries exactly one of those, with a reason."

Point at the **disposition bar** under the metrics.

> "82 deletions were inferred too — records that aren't there at all, so they
> have no row to flag."

### Step 2 — Investigate one record *(2 min — this is the heart of it)*

Click the top row of **Highest-Risk Records**.

> "This is the screen that answers 'why did you flag this?'. It reads top to
> bottom in the order the system reasoned: **Observation → Evidence →
> Inference → Decision.**"

- **Observation** — the record as delivered, plus the raw export row
- **Evidence** — each finding, its severity, and which engine produced it
- **Inference** — the signed breakdown: `+57 blockchain hash mismatch`,
  `+10 route legs out of sequence`. *Those are log-odds × 10 — they genuinely
  sum toward the stated probability, they're not a ranking.*
- **Decision** — the disposition and why

> "And the green lines are **exculpatory**. Formatting noise carries a
> *negative* weight, so a messy record scores *lower*. Not every oddity is an
> attack — that's not a slogan here, it's a negative number in the model."

**Scroll to Blame arbitration.** This is your strongest two sentences:

> "When a container is reported in two ports at once, *both* records carry the
> evidence — but only one is lying. We measured this: with two detectors
> running, **every single false positive was the innocent half of a real
> conflict**. 72 conflict pairs had exactly one tampered end; zero had neither.
>
> So blame goes to whichever record the rest of the manifest supports less —
> measured against the chain, its route, the company it keeps at that port
> call, and its own lineage. That took false positives from **198 to 2**."

### Step 3 — Bloodhound *(1 min)*

Click **Trace in graph**.

> "Follow the evidence outward. Record → container → the port where the
> contradiction happened → the record that contradicts it → the block that
> committed the original."

Click **Conflict** — shows only contradictory edges.

> "Red edges are contradictions, drawn heavier because they're the finding.
> Hub nodes like ports appear but aren't expanded *through* — a naive two-hop
> expansion returned 1,995 nodes, because a port touches every record at that
> port. Now it's 22."

### Step 4 — Geo map *(45 s)*

Click **Locate on map**.

> "Solid line is what the manifest *claimed*. Dashed is what we believe
> actually happened. The map never asserts a repair as an observation."

Drag the **world state** slider.

> "Scrubs the world state through cargo-event time."

### Step 5 — Reconstruction *(1 min)*

Click **Rebuild**.

> "Here's the repair — and, more importantly, **every candidate it beat**, with
> per-criterion scores. A repair is only defensible if you can see what it was
> chosen over."

Find a candidate tagged **chain-confirmed**:

> "This one is special. The chain commits **hashes, never values** — it can
> prove a record changed, it can't tell us what it used to say. But once the
> forensic engines *construct* a candidate, hashing it either confirms the
> repair outright or refutes it. The engines do the work; the chain certifies
> the answer."

### Step 6 — Provenance *(45 s)*

> "Four nodes. A, B and D agree. **C doesn't.**"

> "And here's the subtlety — node C passes its *own* integrity check. It was
> rewritten competently: record hashes replaced, every Merkle root and block
> hash recomputed. Its chain is internally valid. Only comparing state roots
> *across* the network finds it. Local verification is necessary and not
> sufficient."

Point at the **sealed coverage bar**.

> "The chain only covers 85% of the timeline. The last 15% is genuinely
> uncommitted — the forensic engines carry those records alone."

### Step 7 — The twist: Live feed *(2.5 min — finish here)*

Open **Live** → *Generate feed* → **Max** → **Play**.

> "Mid-event we were told the attacker is **inside the system, editing records
> in real time**. The feed now carries incoming *and updated* records."

Let it run. Point at **Live reconstructed manifest** updating.

> "The manifest and the report stay current as records arrive — maintained in
> place, not rebuilt."

Point at the **revision** badges in the feed.

> "These are updates to records already delivered. Two kinds, identical in
> shape: an attacker rewriting a weight after the fact, and an operator
> supplying a value that was missing. **45 out of 45 attacker edits caught.
> Zero false alarms on 32 operator corrections.**"

**The killer line:**

> "And we didn't do that by writing rules for what a bad edit looks like. A
> manifest record describes an event that *already happened* — a loading at
> 09:00 doesn't justify revising that event's weight at 14:00. So any
> already-populated value being rewritten is an edit of history, and whether
> it moved the record *toward* consistency or *away from* it decides which
> kind it was."

Point at **Operator load**.

> "Last thing. Precision isn't enough — a *correct* alert repeated forty times
> is still a flood. So alerts group per container: 68 findings became 58
> notifications. In the unit test, 40 findings on one container produce
> **exactly one** notification, and the alert still reports all 40 events."

### Step 8 — Evaluation console *(30 s, optional but strong)*

> "Scored against a private injection log that nothing in the detection
> pipeline can read — a test walks the AST to prove `core/` never imports it.
>
> And here's the ablation. Turn the provenance chain off and recall drops from
> 0.91 to 0.37. We put that on screen because a system with one dominant
> feature that *hides* its ablation is asking to be caught."

---

## 4. Platform tour — every feature

### 4.1 Data generator (`generator/`)

| piece | what it does |
|---|---|
| `world.py` | 18 real ports with real coordinates, 26 vessels across 5 size classes, 24 routes drawn as contiguous slices of 8 real trade corridors, 20 owners with alias spellings |
| `manifest.py` | Simulates each voyage: arrive → dwell → depart → sail, with dwell from the port's own distribution and transit from the vessel's speed envelope |
| `corruption.py` | 4 attack classes + 6 compound/coordinated patterns + 5 kinds of benign noise. Writes the private injection log |
| `stream.py` | The live feed: 4 novel patterns absent from batch data, plus record revisions |

**Why the world is built first:** consistency reasoning can only detect
tampering if the clean data was genuinely consistent. Cargo classes have real
weight and value densities — 27 tonnes is normal for cement and impossible for
pharmaceuticals — which is what makes peer-group outlier detection mean
anything.

**Reproducibility:** one seed regenerates everything byte-for-byte. A test
forks two subprocesses with *different* `PYTHONHASHSEED` values to prove it.

### 4.2 Normalisation (`core/normalization/`)

Parses 8 timestamp formats (including an ambiguous day-first/month-first
pair), decorated numerics, and 13 blank tokens. Resolves owner aliases and
typos, port names and ids, cargo classes.

**The important property:** every repair is recorded as low-severity `FORMAT`
evidence, and `FORMAT` carries a **negative** fusion weight.

> Measured: 255 FORMAT findings against 291 injected noise entries, with
> **zero** landing on clean records.

### 4.3 The eight detectors (`core/detection/`, `core/temporal/`, …)

| engine | catches | notable |
|---|---|---|
| **temporal** | future events, reverse chronology, simultaneous presence, lifecycle violations, dwell anomalies | dwell baselines are *learned from the data*, not read from the world model |
| **geospatial** | legs no vessel could sail, coordinates that contradict the declared port | sea distance = great-circle × 1.25, because no ship sails through land |
| **route** | off-route ports, sequence breaks, destination contradictions | |
| **cargo** | weight/value/count/owner/cargo-type conservation, capacity | plus cumulative drift, which catches gradual siphoning |
| **duplicate** | exact → structural → fuzzy | blocked on container or (owner, cargo) inside a time window: 12.5 M comparisons → near-linear |
| **statistical** | robust z per peer group, value-density, IQR, Isolation Forest, LOF, DBSCAN | capped **below** the suspicion threshold — can corroborate, can never convict |
| **graph** | orphans, lineage breaks, missing expected events, deletion inference | |
| **provenance** | hash mismatch, absent commitment, node divergence | the only near-proof layer |

**49 evidence codes across 10 layers.** Detectors are registered by name; the
active set is a YAML list.

### 4.4 Arbitration → Fusion → Classification (`core/confidence/`)

The only layer allowed to turn evidence into an inference.

### 4.5 Reconstruction (`core/reconstruction/`)

Five candidate strategies: `neighbor_interpolation`, `conservation_solve`,
`route_schedule`, `historical_median`, `remove`. Scored on seven criteria.

> The strongest strategy is almost embarrassingly simple and is the right one:
> **records of a port call share their cargo state, so an adjacent record still
> holds the value that was overwritten.**

### 4.6 Provenance chain (`blockchain/`)

Permissioned, 4 named nodes, Ed25519 signatures, SHA-256 Merkle roots. Not a
cryptocurrency — no mining, no token.

### 4.7 Live path (`core/streaming.py`, `core/alerting.py`)

Container-scoped incremental analysis, revision semantics, alert grouping, live
manifest and report. **Same detectors, same fusion weights as batch** — a test
asserts the weights are identical.

### 4.8 Interfaces

Command Center · Geo Forensic Map · Bloodhound · Attack Timeline · Record
Ledger · Record Investigation · Reconstruction · Provenance Monitor · Live
Feed · Evaluation Console.

---

## 5. The mathematics

### 5.1 Robust statistics — why not mean and standard deviation

There is no labelled "normal", so normal is estimated from the manifest — which
is the same data that was tampered with.

```
MAD(x)   = median( |xᵢ − median(x)| )
σ̂        = 1.4826 × MAD(x)              ← consistent estimator of σ for normal data
z_robust = (x − median(x)) / σ̂
```

A mean is dragged visibly by one weight inflated 7×. A median has a **50%
breakdown point** — it survives contamination far beyond any plausible attack
rate.

**Fallback chain:** `MAD → IQR/1.349 → stdev`. MAD is exactly zero whenever
more than half a sample shares one value (common for `container_count`), and a
zero scale would make every non-modal value infinitely extreme.

### 5.2 Geospatial feasibility

```
d_gc    = 2R · asin( √( sin²(Δφ/2) + cosφ₁·cosφ₂·sin²(Δλ/2) ) )     R = 6371.0088 km
d_sea   = d_gc / 1.852 × 1.25                                        nautical miles
v_req   = d_sea / ((t_arrival − t_departure) / 3600)                 knots
ratio   = v_req / v_max(vessel)
```

The 1.25 factor inflates the straight line because no ship sails through land.
**Under-estimating the distance manufactures violations**, which is the
expensive kind of error.

If elapsed time ≤ 0, no speed is defined — that's a *temporal* contradiction,
reported by the temporal engine. **One physical violation is counted once.**

### 5.3 Severity ramps

```
severity(ratio) = clamp( (ratio − soft) / (hard − soft), 0, 1 ) × ceiling
```

A linear ramp between two configured points, deliberately. A judge can check
the arithmetic by hand; a logistic curve with fitted parameters could not be.

### 5.4 Evidence fusion — the core formula

Additive in **log-odds**, which is the only form that makes the displayed
breakdown honest.

**Step 1 — within a layer, aggregate by distinct code:**

```
per_code[c] = max severity among findings with code c
aggregate_t = Σ_rank  per_code[rank] × saturation^rank        saturation = 0.75
            capped at 1.30
```

Repeated instances of *one* code are redundant. Distinct codes are
**independent constraints** and genuinely corroborate — an unexplained weight
change and a cargo-type change are both `CARGO`, and treating them as one
finding scored them the same as either alone.

**Step 2 — across layers, same discount by rank:**

```
contribution_t = w_t × aggregate_t
positive_total = Σ_rank  contribution[rank] × saturation^rank
logit(p)       = logit(prior) + positive_total + Σ negatives
```

`prior = 0.05` (the observed base rate), so `logit(prior) = −2.94`.

**Step 3 — display:**

```
points = log_odds × 10        →  +57, +19, −05
```

**Step 4 — decisive floors:**

Some findings are not matters of degree. A container cannot be in two ports at
once; two records cannot share one content hash by accident. If such a code
fires above its configured severity, the probability is **floored**:

```
p = max(p, floor[code])
```

### 5.5 Layer weights

| layer | weight | reasoning |
|---|---:|---|
| `BLOCKCHAIN` | **4.50** | cryptographic — a hash mismatch is near-proof |
| `DUPLICATE` | 2.20 | |
| `TEMPORAL` | 2.20 | simultaneous presence needs two records to be impossible |
| `SPATIAL` | 2.00 | |
| `ROUTE` | 2.00 | |
| `CARGO` | 1.95 | |
| `GRAPH` | 1.85 | |
| `IDENTITY` | 1.20 | |
| `STATISTICAL` | 0.80 | evidence only, never a verdict |
| `FORMAT` | **−0.90** | **negative** — messiness argues *against* deliberate editing |

Per-code multipliers damp weak codes inside strong layers, e.g.
`DWELL_TIME_ANOMALY × 0.35` (spec: *anomalous, not automatically malicious*).

### 5.6 Blame arbitration

For each conflict pair, a corroboration score in [0, 1] from weighted signals:

| signal | weight |
|---|---:|
| content hash matches its chain commitment | 3.0 |
| port lies on the declared route | 1.5 |
| other records share its port call | 1.5 |
| no independent lineage/provenance problem | 2.0 |
| neighbouring records are themselves clean | 1.0 |

```
corroboration = points_earned / points_available
Δ             = corr(self) − corr(counterpart)
multiplier    = max(0.15, 1 − Δ)      applied to this record's share
```

Never zero — the better-corroborated record is still *part of* a real
contradiction, and silencing it would hide the conflict.

### 5.7 Provenance chain

```
manifest_root = MerkleRoot(record_hashes)
route_root    = MerkleRoot(itinerary_hashes)
state_root    = SHA256( prev_state_root ‖ manifest_root ‖ route_root )
block_hash    = SHA256( header fields, excluding block_hash and signatures )
```

Editing a record → changes its hash → changes the Merkle root → changes the
block hash → **breaks every subsequent link**.

Node consistency: majority vote on `state_root`; walk the chains to find the
first differing block; compare record hashes inside it to localise.

### 5.8 Reconstruction scoring

```
score = Σ_k ( w_k × criterion_k ) / Σ_k |w_k|
```

| criterion | weight |
|---|---:|
| `blockchain_state` | 1.3 |
| `cargo_conservation` | 1.2 |
| `route_consistency` | 1.0 |
| `temporal_consistency` | 1.0 |
| `neighbor_agreement` | 1.0 |
| `graph_consistency` | 0.9 |
| `historical_pattern` | 0.7 |

**Special case:** if the candidate's content hash equals the committed hash,
`score = 1.0` — that's a proof, not a score.

Select if `score ≥ 0.70` (repair) or `≥ 0.65` (removal); otherwise
`UNRECOVERABLE`. **Never guess** — a plausible wrong value is worse than an
acknowledged gap.

### 5.9 Cumulative cargo drift (catches gradual siphoning)

```
drift = |w_end − w_start| / w_start          over a run with no cargo event
fires only if  drift > 0.045
          AND  every individual step ≤ 0.02   ← the per-step tolerance
```

That second condition is the whole point: this check exists **only** to catch
drift hiding *below* the per-step tolerance. If any single step breaches it,
the per-step check already owns it — and re-reporting it here blamed the last
record of the run, which is usually innocent (measured: 14 extra false
positives).

### 5.10 Live revisions (the twist)

Each changed field is classified by *how* it changed:

| transition | meaning |
|---|---|
| `null → value` | late-arriving field — routine |
| `value → null` | data loss |
| `value → different value` | **an already-reported fact rewritten** |

```
Δanomaly = Σ severities(container, after) − Σ severities(container, before)
```

| altered a populated field | Δanomaly | severity |
|---|---|---:|
| yes | > +0.05 (degraded) | 0.90 |
| yes | ≈ 0 | 0.62 |
| yes | < −0.05 (improved) | 0.15 |
| no | — | 0.10 |

### 5.11 Alert escalation

An open alert absorbs a new finding **silently** unless:

```
Δprobability ≥ 0.12   OR   a new evidence layer appears   OR   p ≥ 0.90
```

```
compression = flagged_events / notifications
```

---

## 6. Every number

### Batch detection — three seeds, two never used for tuning

| seed | precision | recall | F1 | FP clean | FP noisy | classification | repair | deletion |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `481516` *(tuned on)* | 0.991 | 0.914 | **0.951** | 2 / 4,522 | **0 / 285** | 90.6% | 90.0% | 94.5% |
| `271828` *(held out)* | 0.979 | 0.925 | **0.951** | 5 / 4,537 | **0 / 271** | 87.2% | 96.6% | 98.2% |
| `999331` *(held out)* | 0.986 | 0.851 | **0.914** | 3 / 4,532 | **0 / 273** | 92.9% | 88.2% | 96.4% |

### By attack type (seed 481516)

| attack | injected | detected | recall |
|---|---:|---:|---:|
| `FABRICATED` | 44 | 44 | **100%** |
| `DELETED` (by slot) | 55 | 52 | 94.5% |
| `MODIFIED` | 125 | 112 | 89.6% |
| `DUPLICATED` | 75 | 67 | 89.3% |

### Ablation

| configuration | precision | recall | F1 |
|---|---:|---:|---:|
| all detectors | 0.991 | 0.914 | 0.951 |
| **forensics only, no chain** | 0.978 | **0.369** | 0.536 |

### Live stream (977 events, 884 legitimate)

| metric | value |
|---|---:|
| precision | **1.000** |
| recall | 0.688 |
| F1 | **0.815** |
| false alarms on untouched containers | **0** |
| mean latency | **0.60 ms** |
| p95 latency | 1.49 ms |

| pattern | event recall | campaign recall |
|---|---:|---:|
| `live_revision` | **100%** | **100%** |
| `ghost_transfer` | 100% | **100%** |
| `identity_swap` | 25% | 57% |
| `weight_siphon` | 26% | 50% |

| revisions | events | outcome |
|---|---:|---|
| attacker edits a reported value | 45 | **45 caught** |
| operator corrects a missing value | 32 | **0 false alarms** |

### System

| | |
|---|---:|
| batch pipeline | **2.9 s** for 5,051 records |
| slowest stage | statistical, 1,555 ms |
| graph | 5,900 nodes / 36,116 edges |
| chain | 85 blocks, 4,238 committed, 85% coverage |
| nodes | A, B, D agree · **C divergent** (3 blocks, 6 records) |
| attack windows | 11 across 150 buckets |
| inferred deletions | 82 |
| tests | **131 passing** |

---

## 7. Questions you will get, and the answers

**"How do you know it's not just overfitting to your own generator?"**
> Thresholds were tuned on seed 481516. The other two seeds were generated
> *after* tuning stopped and never used to adjust anything. F1 0.951 / 0.951 /
> 0.914. Also nothing in `core/` can import the generator — there's a test that
> walks the AST and fails if it does.

**"Isn't the blockchain doing all the work?"**
> It's doing a lot, and the ablation is on screen: recall drops 0.91 → 0.37
> without it. Three things stop it trivialising the problem. It commits
> **hashes, not values** — it can prove a record changed, never what it said,
> so reconstruction gets no help at all. It covers **85%** of the timeline. And
> **it's under attack itself** — one node is compromised, so chain evidence is
> only trustworthy where a majority agrees.

**"Why should I trust a 94% probability?"**
> You shouldn't trust it blindly, which is why the calibration table is on the
> Evaluation console. Above 0.5 we're systematically *under*-confident — the
> 0.6–0.7 bin is right 100% of the time. We report that rather than correcting
> it, because fitting a correction needs the answer key and would make every
> number circular. Under-confidence is the safe direction.

**"What happens with no ground truth at all?"**
> That's the operating assumption. Every baseline is learned from the manifest
> with median/MAD. Nothing is trained on labels — the only fitted models are
> unsupervised, capped below the suspicion threshold, and the lowest-weighted
> layer in the system.

**"Why did you flag this record and not that one? They look the same."**
> Open the record, scroll to Blame arbitration. Both carry the evidence; blame
> went to the one the rest of the manifest supports less, and both
> corroboration scores are shown with the reasons.

**"How do you handle false positives?"** *(the brief's main concern)*
> Four mechanisms. Formatting noise carries a **negative** weight. Statistical
> evidence can never convict alone. Blame arbitration took clean false
> positives from 198 → 2. And live alerts group per entity so a campaign is one
> notification, not forty. Result: **zero false alarms on noise-only records
> across three seeds.**

**"How fast is it, really?"**
> 2.9 s for a 5,000-record batch; **0.60 ms per live event**, and that's
> independent of manifest size because live reasoning is container-scoped.

**"What did the twist actually change?"**
> The data model, not the architecture. Records stopped being immutable. Three
> things: revision semantics in the stream processor, an alert layer between
> detection and the operator, and live manifest/report state. **Zero changes to
> the fusion weights, the classifier or the reconstruction engine** — there's a
> test asserting the live path uses the same weights as batch.

**"Could the attacker just make consistent edits?"**
> Yes, and we say so. If every record is edited consistently, consistency
> reasoning can't see it — that's what the provenance chain is for, and in the
> uncommitted 15% a fully consistent forgery would survive. The honest answer
> is that it raises the cost of the attack enormously: you'd have to edit every
> related record in every container, and still break the chain.

**"Why Python and not something faster?"**
> The bottleneck is scikit-learn fitting three models (1.5 s), not Python. It
> can be sampled or dropped with one line of YAML — it's the weakest layer. The
> live path is already sub-millisecond.

**"What would you do next?"**
> Close the no-chain recall gap. The most promising unexploited signal is
> cross-container: a vessel's total manifested weight against its capacity, and
> per-port throughput conservation. Both need a second scope the live path
> doesn't build yet.

---

## 8. Weaknesses — own them, don't hide them

Judges reward candour here. Say these *before* you're asked.

1. **Recall leans on the chain.** 0.91 → 0.37 without it. The forensic engines
   are precise (0.978) but miss internally consistent edits.
2. **Gradual siphoning is caught late** — ~5 transitions in, once cumulative
   drift clears tolerance. 50% campaign recall.
3. **Consistent lies survive after onset.** Identity swap: 25% event recall,
   57% campaign. Once the state is consistently wrong there's nothing left to
   contradict. Property of the approach, not a bug.
4. **Timestamp repair is weak** (14–43% vs 96.7% for weight). A neighbour's
   weight *is* the overwritten value; a neighbour's timestamp only *bounds* it.
   We don't guess harder.
5. **Node consensus assumes one attacker.** Two of four → no majority; three →
   the majority is *wrong*. The agreement fraction is reported so you can see
   how much the result deserves.
6. **Container reuse across bookings is out of scope** — it needs every
   continuity check scoped per shipment leg.
7. **The world is synthetic and we wrote it.** Mitigated by real ports, real
   corridors, real cargo densities, lossless noise — and above all by the
   held-out seeds.

---

## 9. If something breaks mid-demo

| symptom | fix |
|---|---|
| Map is black | Missing `VITE_CARTO_API_KEY`. The UI says so; geometry still renders. Carry on. |
| UI shows "Cannot reach the Makar API" | API isn't running: `python -m backend.main` |
| 404 with a generate hint | No dataset: `python scripts/generate.py --seed 481516 --records 5000 --out out` |
| Evaluation console empty | Scorer hasn't run: `python scripts/evaluate.py --out out --ablation` |
| Live panel says no session | Press **Generate feed** first |
| Graph empty | Bloodhound needs a selected record — pick one from the ledger |
| Everything is broken | `out/report.md` has the whole analysis in Markdown. Present from that. |

---

## 10. One-page cheat sheet

```
WHAT          Reconstructs a trustworthy cargo manifest from a tampered one.
              Every record: ORIGINAL / REPAIRED / REMOVED / UNRECOVERABLE.

BATCH         P 0.991   R 0.914   F1 0.951        5,051 records in 2.9 s
HELD OUT      F1 0.951 (271828) · 0.914 (999331)  ← never used for tuning
FALSE ALARMS  0 on noise-only records, ALL THREE SEEDS
PER ATTACK    fabricated 100% · deleted 94.5% · modified 89.6% · duplicated 89.3%
ABLATION      no chain → recall 0.91 → 0.37       (we show this on purpose)

LIVE          P 1.000   F1 0.815   0.60 ms/event   0 false alarms
TWIST         45/45 attacker edits caught · 0/32 corrections false-alarmed
ALERTS        68 findings → 58 notifications (40:1 when a campaign repeats)

SCALE         8 detectors · 49 evidence codes · 10 layers
              graph 5,900 nodes / 36,116 edges
              chain 85 blocks, 85% coverage, node C divergent
              131 tests passing

THREE IDEAS   1. Baselines learned from the data, median/MAD (50% breakdown)
              2. Messiness is EXCULPATORY — FORMAT weighs −0.90
              3. Symmetric evidence, asymmetric blame (198 → 2 false positives)

TWIST IDEA    A record describes an event that already happened.
              Rewriting a populated value afterwards is an edit of history.
              Whether it moved toward or away from consistency says which kind.

BEST LINE     "No detector is allowed to reach a verdict on its own."
```
