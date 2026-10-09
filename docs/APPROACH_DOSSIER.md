# Makar — Approach Dossier

**The Lost Manifest — Cargo Tampering Detection & Reconstruction**

---

## 1. Approach, and the reasoning behind it

### 1.1 The problem as we read it

Four questions, and the fourth is the hard one:

1. **Detect** — which records are inconsistent, impossible or out of pattern?
2. **Identify** — which were tampered with, how, and with what confidence?
3. **Reconstruct** — what was the original manifest?
4. **Report** — explain it well enough to survive questioning.

Detection is tractable. Reconstruction is harder, because it demands a
*specific* original value rather than a flag. And the brief is explicit that
there is **no labelled ground truth** and that false alarms are expensive —
every wrongly flagged record is a legitimate shipment held up at a port. So
the target is not "find the most tampering", it is **high recall at very low
false-alarm cost, with every decision explainable**.

### 1.2 The core architectural commitment

One rule shapes the whole codebase:

> **Observation → Evidence → Inference → Decision.** Detectors observe and
> emit evidence. Only the confidence layer turns evidence into an inference.
> Only the reconstruction layer turns an inference into a decision.

No detector may classify a record. That sounds like bureaucracy; it is the
property that made the system tunable. Because every detector produces
severities rather than verdicts, the weighting can be retuned, a layer can be
ablated, and blame can be *redistributed between records* — all without
touching detector code. Three of the four largest accuracy improvements we
measured were changes at the fusion layer, which would have been impossible if
detection and classification were entangled.

### 1.3 The pipeline

```
suspect manifest (CSV/JSON, deliberately messy)
  ↓ normalise          typed records + FORMAT evidence
  ↓ provenance view    majority chain + cross-node consistency
  ↓ 8 detectors        independent evidence layers
  ↓ arbitrate          decide who to blame in a contradiction
  ↓ fuse               calibrated probability + auditable breakdown
  ↓ classify           which kind of tampering, by decision table
  ↓ reconstruct        candidate original states, scored and selected
  ↓ attack timeline    group anomalies into windows
reconstructed manifest + report
```

Eight detectors, registered by name and enabled from YAML: `temporal`,
`geospatial`, `route`, `cargo`, `duplicate`, `statistical`, `graph`,
`provenance`. 49 evidence codes across 10 layers.

### 1.4 The three ideas that carry the result

**Baselines are learned from the manifest, with robust statistics.** There is
no labelled normal, so normal is estimated from the data — which is the same
data that was tampered with. Every baseline uses median/MAD, whose 50%
breakdown point survives contamination far beyond any plausible attack rate. A
mean is dragged visibly by a single weight inflated 7×; a median is not. The
fallback chain is MAD → IQR → standard deviation, because MAD is exactly zero
whenever more than half a sample shares one value (common for
`container_count`) and a zero scale would report every non-modal value as
infinitely extreme.

**Messiness is exculpatory.** `FORMAT` evidence carries a **negative** fusion
weight. "Not every oddity is an attack" is a scoring requirement, and the
strongest way to honour it is to make untidiness affirmative evidence of a
sloppy export rather than merely neutral — so a scruffy legitimate row scores
*lower* than a tidy forgery. Normalisation raises 255 FORMAT findings against
291 injected noise entries with **zero landing on clean records**, and the
noise false-alarm rate is **0 across all three seeds**.

**Symmetric evidence, asymmetric blame.** When a container is reported in two
ports at once, both records carry the finding — the observation genuinely
concerns both — but only one is usually the lie. A separate arbitration pass
decides which, using corroboration from independent layers: does the chain
endorse this record's hash, is its port on its declared route, do other
records share its port call, is its own lineage intact, are its neighbours
clean?

This was found by measurement, not designed up front. With temporal +
geospatial detectors alone:

| code | items on clean records | pairs with exactly one tampered end | pairs with neither tampered |
|---|---:|---:|---:|
| `SIMULTANEOUS_PRESENCE` | 32 | 72 | **0** |
| `SPEED_INFEASIBLE` | 21 | 46 | **0** |

**Every single false positive was the innocent half of a genuine conflict.**
The detectors were never wrong that a contradiction existed; they could not
tell which side was lying. That is not a detection defect and must not be
fixed by weakening the detectors — it is a blame-assignment problem belonging
to the layer that makes decisions. Arbitration took clean-record false
positives from **198 to 2**.

---

## 2. Alternatives considered, and why we rejected them

### 2.1 Supervised classifier on the injection log — rejected

Train on `before`/`after` pairs and predict tampering.

Rejected because it answers a different question. The brief states there is no
labelled ground truth; a model trained on our own injection log learns *our
generator*, not tampering. It would score superbly on our data and fail on any
attack we did not think to write — which the live feed proves, since three of
its patterns appear nowhere in the batch data. It is also unexplainable, and
"the model said so" does not survive "why did you flag this record?".

ML is used, but only unsupervised and only as *one weak evidence source*:
Isolation Forest, LOF and DBSCAN contribute at the lowest weight in the system
with severities capped below the suspicion threshold, so they can corroborate
and can never convict.

### 2.2 Raising layer weights so a single strong signal convicts — tried, measured, rejected

Eight byte-identical duplicates were being missed at p ≈ 0.21, because with a
5% prior (log-odds −2.94) no single layer could convict unless its weight
exceeded ~3.0.

We raised the weights. It failed instructively: lifting `TEMPORAL` far enough
for simultaneous presence to convict alone also lifted `DWELL_TIME_ANOMALY`,
which must *never* convict alone.

| version | precision | recall | F1 | FP (clean) |
|---|---:|---:|---:|---:|
| original weights | 0.991 | 0.897 | 0.942 | 2 |
| **raised weights** | 0.965 | 0.910 | 0.937 | **7** |
| original + decisive floors | **0.991** | **0.910** | **0.949** | **2** |

The fix was to separate the concerns: weights stay tuned for *corroboration*,
and a short list of **deterministic impossibilities floors the probability**
instead of arguing with the prior. A container cannot be in two ports at once;
two records cannot share one content hash by accident. Those are not matters
of degree.

### 2.3 Cargo-conservation floors — tried, measured, rejected

Having added floors, we tried extending them to large unexplained weight
changes. Measured across three seeds: **11 extra false positives for 0.003
recall** (precision 0.985 → 0.936). A large unexplained weight change is
strong evidence but *not a logical impossibility*, so it belongs in the
weighted score, not above it. Reverted.

The exception that earned a floor is `CARGO_DRIFT_UNEXPLAINED`, which fires
only when *every* individual step is inside the per-step tolerance — the one
case the per-step check cannot see by construction.

### 2.4 Fitting a calibration correction — rejected

Above p = 0.5 the system is systematically *under*-confident; the 0.6–0.7 bin
is right 100% of the time. Correcting that requires fitting against labels,
and the only labels available are the answer key. Fitting on it would make
every reported number circular — a worse sin than being conservative.
Under-confidence is also the safe direction: a stated 70% is at least 70%. The
curve is reported as measured, gap included.

### 2.5 Withholding the world model — rejected

It sounds purer to give the detectors nothing but the manifest. But a real
analyst at a shipping line knows which ports the line calls at, which vessels
it operates and who its customers are. That is master data, not an answer key.
Withholding it would model a problem nobody has, and would make "this record
references a container that does not exist" undetectable *in principle*.

The line is drawn precisely: the world model says **what exists**; the
injection log says **what was altered**. Nothing under `core/` imports from
`generator/`, and `evaluation/` is the only consumer of `ground_truth.json`.

### 2.6 A blockchain that stores values — rejected

Committing field values would make reconstruction a lookup and the whole
forensic exercise pointless. Blocks commit **hashes only**, and the chain is
sealed over only 85% of the timeline. The chain can prove a record changed; it
cannot say what it used to contain.

The asymmetry this creates is one of the nicer properties in the system: the
forensic engines must *construct* a candidate original, and then hashing it
either **confirms** the repair outright or refutes it. Detection gets help;
reconstruction gets none.

### 2.7 Appending all inserted record ids — rejected

The realistic default — an attacker inserting rows gets fresh primary keys —
would have made duplicate detection collapse into `WHERE id > 4987`. Inserted
rows therefore draw from a pool mixing ids freed by deletions with appended
ids (35% recycling by default), so the detector must reason about content and
lineage. The id sequence is used only where it is legitimately informative: a
*gap* suggests a deletion.

### 2.8 Container reuse across bookings — scoped out, deliberately

Containers genuinely are reused, and the live feed tried it first. It produced
false alarms on *legitimate* events, because a container's history then spans
two bookings with different owners, routes and cargo — so owner continuity,
route sequence and cargo conservation all break legitimately.

Two checks were rescoped because they were cheap and correct anyway (lifecycle
ordering and the orphan test now key on `(container, shipment)`). The rest were
left container-scoped and the feed books new containers instead. This is a
scoping decision, not an oversight: a repositioned empty container leaves no
manifest record at all, so the gap between bookings cannot be validated from
the manifest, and inventing a rule for it would be unfounded. It is listed as
a known limitation in §4.

### 2.9 Streamlit for the interface — rejected

Fast to build and wrong for the job. The brief asks for a forensic
investigation surface where the graph, the map and the timeline cross-link —
select a container in the graph, locate it on the map, jump to its attack
window. That is a stateful, linked UI. React + TypeScript + MapLibre +
Cytoscape cost more up front and deliver the thing actually asked for.

---

## 3. Strengths

**False-alarm discipline.** Zero false alarms on noise-only records across
three seeds; 2–5 on ~4,500 clean records. This is the half of the problem most
easily lost while chasing recall, and it is where most of our engineering went.

**Every decision is auditable.** Each record carries its evidence list with
per-finding severities and the engine that produced each, a signed log-odds
breakdown that sums to the stated probability, the arbitration decision with
both corroboration scores, and — for repairs — every candidate considered with
per-criterion scores. The answer to "why this record and not that one?" is on
screen, not in a model.

**Honest reporting of its own weaknesses.** The ablation shows recall falling
0.910 → 0.369 without the chain. The calibration gap is printed. Collateral
flags are separated from false alarms. A system with one dominant feature that
hides the ablation is asking to be caught.

**Reconstruction actually reconstructs.** 89.9–96.6% of repairs reproduce the
pre-attack value exactly, field by field, with weight at 96.7% and destination
at 100%. The strongest strategy is almost embarrassingly simple and is the
right one: records of a port call share their cargo state, so an adjacent
record *still holds the value that was overwritten*.

**Generalises to unseen attacks.** The live feed carries three patterns absent
from the batch data and all three are caught, with zero false alarms on
untouched containers, because detection rests on consistency constraints
rather than attack signatures.

**Reproducible end to end.** One seed regenerates the world, the manifest, the
corruption, the chain and the compromised node byte for byte.

---

## 4. Weaknesses, stated plainly

**Recall depends heavily on chain coverage.** Without the provenance layer,
recall is 0.369. The forensic engines are precise (0.978) but miss edits that
break no consistency constraint — a weight changed to another plausible weight,
with its neighbours changed consistently. Honest framing: tamper-evidence is
doing real work, and a deployment without it would need a lower threshold and
would accept more false alarms.

**Gradual siphoning is only caught late.** The cumulative-conservation check
fires once drift clears the tolerance, roughly five transitions in — campaign
recall 50% within a 900-event window. A siphon that stops early, or one
calibrated below the cumulative tolerance too, survives. Tightening the
tolerance trades directly against false alarms on legitimate rounding drift;
the current value is where that trade was measured.

**Consistent lies are undetectable after onset.** An identity swap is caught
when it contradicts prior history. Once the state is consistently wrong, later
events are internally consistent and there is nothing left to contradict.
Event recall 25%, campaign recall 57%. This is a property of consistency
reasoning, not a bug we can fix — and it is why campaign recall is the metric
we report.

**Timestamp repair is weak.** 14–43% field accuracy against 96.7% for weight.
A neighbour's weight *is* the overwritten value; a neighbour's timestamp only
*bounds* the correct one. We do not guess harder, because a plausible wrong
timestamp is worse than an acknowledged gap.

**Node consensus assumes a single attacker.** With four nodes and one
compromised node, majority works. With two there is no majority; with three
the majority is *wrong*. The checker reports its own agreement fraction so a
reader can see how much weight the result deserves, but the limitation is real.

**Container reuse is out of scope** (§2.8).

**The world is synthetic, and we wrote it.** We mitigated by using real ports
with real coordinates, real trade corridors, cargo-class weight and value
densities that make peer-group detection meaningful, and lossless formatting
noise. But the strongest honest claim is the held-out seeds: thresholds were
tuned on one world and reported on two never used for tuning.

---

## 5. Scalability and implementation

### 5.1 Measured performance

5,051 records, 594 injection entries, on one laptop core:

| stage | ms |
|---|---:|
| normalise | 154 |
| index | 20 |
| temporal | 98 |
| duplicate | 98 |
| graph | 82 |
| provenance | 54 |
| cargo | 22 |
| geospatial | 13 |
| route | 13 |
| **statistical** | **1,426** |
| arbitrate | 78 |
| fuse + classify | 69 |
| reconstruct | 585 |
| timeline | 7 |
| **total** | **≈ 2.7 s** |

Live path: **1.6 ms per event**, independent of manifest size.

### 5.2 Where the complexity is

Every sequential engine is **O(n) over records grouped by container**, with
grouping done once in a shared context. The two places quadratic behaviour
could creep in are handled explicitly:

- **Duplicate detection** blocks candidates on `(container)` or
  `(owner, cargo_type)` and compares only within a time window. All-pairs over
  5,000 records would be 12.5M comparisons; blocking makes it near-linear.
- **Graph queries** never expand *through* hub nodes. A naive two-hop
  expansion from one record returned **1,995 nodes and 5,708 edges**, because a
  port touches every record at that port. Hub-aware expansion returns 22 nodes
  — the port itself is relevant context, the other 400 records sharing it are
  not.

The statistical engine dominates at 1.4 s, and is the obvious first target: it
fits Isolation Forest, LOF and DBSCAN over the full matrix. It is also the
weakest evidence layer, so it is the cheapest thing to sample or drop under
load — `detection.enabled` removes it with one line of YAML.

### 5.3 Scaling beyond one machine

The architecture already assumes partition-by-container: all consistency
reasoning is container-scoped, so sharding by `container_id` parallelises
nearly perfectly. The genuinely global steps are duplicate detection (needs a
shared hash index — a single `GROUP BY content_hash` in SQL) and peer-group
statistics (needs per-cargo-class aggregates, which are mergeable). Nothing in
the design requires the whole manifest in one process; it is held in memory
here because at this scale that is simply faster.

### 5.4 Configuration as the extension mechanism

Every threshold lives in `configs/default.yaml`. Nothing under `core/`
hardcodes a tunable constant. Detectors register by name and the active set is
a YAML list, so a new reasoning layer is a new registered detector plus one
line plus a fusion weight — and nothing downstream knows which detectors ran.
Overrides work from YAML overlays, `MAKAR__`-prefixed environment variables,
or the CLI.

This was built for adaptability rather than elegance, and it paid for itself
when the live feed arrived (§6).

### 5.5 Stack

Python 3.11 · FastAPI · Pydantic v2 · NumPy / pandas / scikit-learn ·
NetworkX · PyNaCl (Ed25519) · SHA-256 · React 18 + TypeScript + Tailwind ·
MapLibre GL + CARTO · Cytoscape.js. No database server, no external services,
no API keys. The LLM layer is provider-agnostic and **disabled by default** —
every number in this dossier was produced with it off.

---

## 6. What changed for the live feed

The brief requires the prototype to work on a live feed after the twist, with
at least one attack type absent from the batch data. We treated that as the
real test of whether detection generalises.

### 6.1 What we injected

Three patterns, each chosen to defeat a *different* batch assumption rather
than to be a variant of a known attack:

| pattern | attacks | why it is hard |
|---|---|---|
| `weight_siphon` | the per-step conservation **tolerance** | every step is legal; only the total is not |
| `ghost_transfer` | **lineage** | every field is plausible; only the missing arrival is not |
| `identity_swap` | **identity continuity** | no single record is wrong |

### 6.2 What we changed in response

**One new detector rule**, and it is a general constraint rather than a siphon
detector: `CARGO_DRIFT_UNEXPLAINED` holds the *cumulative* change across a run
of transitions to a much tighter bound than the sum of the per-step bounds. It
fires **only when every individual step is inside the per-step tolerance**,
because that is the only case the existing check cannot already see. Without
that condition it re-reported single large edits and blamed the last record of
the run, which is usually innocent — measured, 14 extra false positives.

**Four correctness fixes the live data exposed**, all of which improved the
batch path or left it unchanged:

1. **A scheduled departure is not a future event.** `departure_timestamp` is a
   forecast, so it was excluded from the future-event check. Every live event
   was tripping it.
2. **Lifecycle ordering scoped to `(container, shipment)`.** Containers are
   reused; one delivered on one booking and created on the next is normal.
3. **Absence is not evidence when the history is still arriving.** The orphan
   test's "no other record places this container here" now requires *later
   events to exist*. In a batch, absence means absence; on a live feed it may
   mean *not yet*, and every genuine new arrival looked orphaned.
4. **Evidence attaches to the record carrying the changed value**, not to the
   port call's representative. The live path reports findings about the event
   it just ingested, so a mutation attributed to an earlier sibling was
   silently dropped.

Fix 3 is the one worth generalising: **a consistency engine must distinguish
"this did not happen" from "this has not happened yet."** We arrived at the
same principle independently in batch mode, where deletion inference requires
a later port call before claiming a missing departure.

**No change to the fusion weights, the classifier or the reconstruction
engine.** The live path runs the same detectors with the same weights. That it
needed no retuning is the strongest evidence that detection rests on
constraints rather than on signatures.

### 6.3 Result

900 events, 48 attacks, 852 legitimate, **0 false alarms on untouched
containers**, 1.6 ms mean latency.

| pattern | event recall | campaign recall |
|---|---:|---:|
| `ghost_transfer` | 100% | **100%** |
| `identity_swap` | 25% | **57%** |
| `weight_siphon` | 26% | **50%** |

Two measurement points we insisted on rather than quietly benefiting from:

**Event recall understates campaign attacks.** A siphon or swap spans many
events for one container; the onset is detectable, and after it the state is
consistently wrong with nothing left to contradict. Campaign recall — "was
this container caught being attacked at all?" — is the operationally
meaningful number, so both are reported.

**Collateral flags are not false alarms.** Once an injected record sits in a
container's history, later legitimate records of that container genuinely
contradict it. Four such flags occurred. Counting them as false alarms would
penalise the system for noticing the contamination it exists to notice, so
they are reported separately — and separately they are zero against untouched
containers.

### 6.4 If the twist is something else

The live-feed requirement is what the brief specifies, so it is what we built
and measured against. If *Shifting Waters* turns out to introduce a different
change — new fields, a different corruption profile, a different threat model,
multi-party manifests — the adaptation surface is the same one the live feed
used:

- a new reasoning layer is a registered detector plus one YAML line plus a
  fusion weight; nothing downstream needs to know it exists;
- every threshold is config, so a changed corruption profile is a retune and
  not a rewrite, and `MAKAR__`-prefixed env vars allow it without touching
  files;
- the evidence model is open — new codes join existing layers, or declare a
  new layer with its own weight;
- detectors can be ablated individually, so a layer invalidated by the twist
  is removed rather than worked around.

The live feed is the evidence that this is real and not an aspiration: it
needed one new constraint and four bug fixes, and zero changes to fusion,
classification or reconstruction.

---

## 7. What we would do next

In the order we would actually do it:

1. **Close the no-chain recall gap.** The forensic engines miss internally
   consistent edits. The most promising unexploited signal is cross-container
   correlation at a shared port call — a vessel's total manifested weight
   against its capacity, and per-port throughput conservation.
2. **Cut the statistical engine's 1.4 s.** Fit the models on a sample and
   score the full set, or drop to the univariate robust checks, which carry
   most of its weight anyway.
3. **Container reuse**, by scoping every continuity check to a shipment leg
   (§2.8).
4. **Byzantine-tolerant node consensus**, so the provenance layer degrades
   gracefully rather than silently inverting when a majority is compromised.
5. **Calibration on a held-out generated world** rather than on the answer
   key — legitimate, since a separate seed is not the data being scored.
