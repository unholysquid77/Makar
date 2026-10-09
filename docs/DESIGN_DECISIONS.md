# Makar — Design Decisions

Running log of decisions that are not obvious from the code, with the
alternatives rejected. Feeds section 2 of the Approach Dossier.

---

## D1. The world model is reference data; the injection log is not

**Decision.** The detection pipeline is given the synthetic *world model* —
ports, vessels, routes, owners, containers. It is never given the injection
log.

**Why.** A real forensic analyst at a shipping line knows which ports the
line calls at, which vessels it operates and who its customers are. That is
master data, not an answer key. Withholding it would model a problem nobody
actually has, and would make "this record references a container that does
not exist" undetectable in principle.

**What stays withheld.** The injection log is the only thing that says *which
records were touched*. Nothing under `core/` imports from
`generator.corruption`, and the evaluator is the only consumer of
`ground_truth.json`.

**Rejected.** Giving detectors nothing but the manifest. It sounds purer, but
it conflates two different unknowns — "what exists in the world" (knowable)
and "what was altered" (the thing being inferred).

---

## D2. Baselines are learned from the manifest, with robust statistics

**Decision.** Dwell-time, weight and value baselines are estimated from the
suspect manifest itself using median / MAD, not read from the world model and
not computed with mean / standard deviation.

**Why.** The problem statement is explicit that there is no labelled ground
truth and the system must work out what normal looks like for itself. The
catch is that the data used to learn "normal" is the same data that was
tampered with. A mean is dragged by a single weight inflated 7×; a median has
a 50% breakdown point, which is far beyond any plausible attack rate.

`core/stats.py` falls back MAD → IQR → standard deviation, because MAD is
exactly zero whenever more than half a sample shares one value (common for
`container_count`), and a zero scale would report every non-modal value as
infinitely extreme.

**Rejected.** Reading `port.dwell_mean_hours` from the world model. It would
work here and be slightly more accurate, but it is the kind of shortcut that
stops working the moment operational patterns change — and it answers a
weaker version of the question than the one being asked.

---

## D3. Formatting noise is modelled at the file layer and carries negative weight

**Decision.** Structural attacks are applied to typed records; formatting
noise is applied to serialised rows. `FORMAT` evidence carries a *negative*
fusion weight.

**Why.** Real exports are messy at the file layer: a thousands separator, a
day-first date, `"N/A"` where a number belongs. Modelling noise there forces
the normaliser to earn its findings against genuinely ambiguous strings.

The negative weight is the important half. "Not every oddity is an attack" is
a scoring requirement, and the strongest way to honour it is to make
messiness *affirmative evidence of a sloppy export* rather than merely
neutral. A tidy forgery then gets less benefit of the doubt than a scruffy
legitimate row.

**Measured effect.** Normalisation raises 255 FORMAT findings against 291
injected noise entries, with **zero** landing on clean records. The 36 not
reported are deliberate: structurally-empty fields (a final port call has no
departure) are counted in data-quality stats but never evidenced, because
doing so would attach a finding to roughly a third of a clean manifest.

---

## D4. Blank tokens resolve to *absent*, never to "unknown entity"

**Decision.** `is_blank()` recognises `""`, `-`, `--`, `N/A`, `null`,
`NULL`, `unknown`, `nan`, `?` and friends. Entity resolution returns "blank"
for these, distinct from "unknown".

**Why.** The first implementation reported `vessel_id = "N/A"` as *"Vessel
'N/A' does not exist in the world model"* at severity 0.68 — nineteen
confident false alarms generated purely by an empty cell. A wrongly flagged
record is a legitimate shipment held up at a port, so this class of bug is
the expensive one.

---

## D5. One physical violation is counted once

**Decision.** Both spec §9.3 and §10 describe a `distance / elapsed_time`
check. It is computed once, in the geospatial engine, as `SPEED_INFEASIBLE`.
The temporal engine raises `IMPOSSIBLE_TRANSIT` only for the degenerate case
where elapsed time is ≤ 0 and no speed is even defined.

**Why.** Independent evidence layers are only meaningfully independent if
they are not re-reporting the same measurement. Counting one impossible leg
as both temporal and spatial evidence would inflate the fused probability for
free, and would make the per-layer breakdown in the UI dishonest.

---

## D6. Records are collapsed into port calls before journey reasoning

**Decision.** `core/detection/segments.py` groups a container's records into
port calls; legs run departure→arrival between consecutive calls.

**Why.** A single port call is described by three or four records
(ARRIVED/INSPECTED/UNLOADED/DEPARTED). Computing a speed per record pair
would produce nonsense zero-distance legs inside a port call. It also gives a
useful signature for free: a record teleported to a distant port becomes its
own one-record call wedged between two legitimate ones, producing two
impossible legs rather than one ambiguous anomaly.

---

## D7. Conflict arbitration: symmetric evidence, asymmetric blame

**Decision.** When two records are mutually contradictory (same container in
two ports at once; a leg no vessel could sail), the detection layer attributes
evidence to **both** records. A separate arbitration pass, before fusion, then
decides which record to *blame*, using corroboration from independent layers,
and damps the severity carried by the better-corroborated record.

**Why.** This was found empirically, not assumed. With temporal + geospatial
detectors alone, the record-level false positives on clean data were:

| code                    | items on clean records | pairs with exactly one tampered end | pairs with neither end tampered |
|-------------------------|-----------------------:|------------------------------------:|--------------------------------:|
| `SIMULTANEOUS_PRESENCE` |                     32 |                                  72 |                           **0** |
| `SPEED_INFEASIBLE`      |                     21 |                                  46 |                           **0** |
| `EVENT_ORDER_VIOLATION` |                      3 |                   3/3 on a tampered container |                   — |

Every single false positive was the *innocent half of a genuine conflict*.
The detectors were never wrong that a contradiction existed; they could not
tell which of the two records was lying. That is not a detection defect and
must not be fixed by weakening the detectors — it is a blame-assignment
problem, and it belongs to the layer that makes decisions.

Corroboration signals used to arbitrate: whether the claimed port lies on the
record's declared route, whether neighbouring records in the container
timeline are themselves clean, whether the port call rests on one lone record
or several, whether the content hash matches the provenance chain, and whether
cargo conservation holds across the call.

**Rejected.** (a) Attributing evidence to only one end, chosen by a heuristic
at detection time — that buries an inference inside an observation, which is
precisely the layering violation the architecture exists to prevent.
(b) Lowering `SIMULTANEOUS_PRESENCE` severity — it is one of the most
convincing signals in the system, since it takes two records to agree to be
impossible. Weakening it to hide a blame-assignment bug would trade real
recall for cosmetic precision.

---

## D8. Statistical and dwell signals are capped, and down-weighted per code

**Decision.** `STATISTICAL` carries a low fusion weight, its severities are
capped by config, and individual codes can be down-weighted independently of
their type via `fusion.code_multipliers`.

**Why.** Spec §13 is explicit that the statistical engine generates evidence
and must not independently classify a record, and §9.5 says a long dwell is
*anomalous, not automatically malicious*. `DWELL_TIME_ANOMALY` is `TEMPORAL`
by nature, so it would otherwise inherit the full temporal weight. Relabelling
its type to dodge that would be dishonest; a per-code multiplier expresses
"this is a real temporal observation that happens to be weak evidence of
intent" without lying about what layer produced it.

---

## D9. The provenance chain commits hashes only, and covers a prefix of history

**Decision.** Blocks store `record_hashes` and `record_ids` — never field
values. The chain is sealed up to `blockchain.sealed_fraction` of the
timeline; records after that cut-off have **no** chain coverage.

**Why this is not cheating.** A tamper-evident log is a real security
property, not an oracle: nodes commit record hashes as events are reported,
and an attacker who later edits the database cannot retroactively change
committed hashes. Withholding it would model a weaker system than the one the
spec asks for (spec §21–23), and `BLOCKCHAIN` carries the highest fusion
weight precisely because it is the hardest evidence available.

Three things stop it from trivialising the problem:

1. **It commits hashes, not plaintext.** The chain can prove that `R847`
   changed. It cannot say the weight used to be 18,200 kg. *Detection* gets
   help; *reconstruction* gets none, and reconstruction is half the task.
2. **Coverage is partial.** The unsealed tail (default 15% of the manifest)
   has no chain evidence whatsoever, and the forensic engines must carry it
   alone.
3. **The chain is itself under attack.** One node is compromised and carries
   rewritten blocks (spec §23), so chain evidence is only trustworthy where a
   majority of nodes agree. A single node's chain proves nothing.

**Consequence for evaluation.** Because this layer is strong, the evaluator
reports metrics **twice** — with the provenance layer and with it disabled —
so the forensic engines' standalone performance is visible rather than hidden
behind a hash comparison. An ablation is the honest way to present a system
with one dominant feature.

---

## D10. Deletion is absence in *time*, not absence at a *port*

**Decision.** Records are grouped two different ways, for two different
questions (`core/detection/segments.py`):

* `port_calls()` groups by `port_id` — used for voyage **legs**.
* `event_calls()` groups by **time** (the shared `arrival_timestamp` of a port
  call, with gap-based fallback), merges same-port clusters inside the dwell
  window, and takes the call's port by majority vote — used for **missing-event**
  inference.

**Why.** Measured, not assumed. With port-based grouping, deletion inference
flagged 94 containers of which only 38 had a real deletion — **31 had a
*modification***. A record relocated to a distant port split its real port
call in two, so the original call lost its closing `DEPARTED` and the next one
lost its opening `ARRIVED`: one location edit manufactured two phantom
deletions.

Grouping by time fixes it at the root. A record whose *port* was rewritten
still occupies the time slot it always did, so the call stays whole, and the
wrong port is reported by the route and geospatial engines — where it belongs.

Two further filters were needed, both justified by the domain rather than by
convenience:

* **Merge same-port clusters within the dwell window.** One port call is one
  contiguous presence at one port. Without this, a near-duplicate inserted a
  few hours after the record it copied formed its own cluster and read as a
  call missing nearly all its events.
* **Only assess calls at ports on the container's declared route.** A cluster
  at an off-route port is a relocated or fabricated record, not a port call
  with records missing from it.

**Measured effect**, container-level deletion detection:

| version | precision | recall | `MISSING_EXPECTED_EVENT` count |
|---|---:|---:|---:|
| port-grouped | 0.52 | 0.73 | 178 |
| time-grouped | 0.52 | 0.98 | 135 |
| + merge + route filter | **0.88** | **0.98** | **62** |

(55 deletions were injected, so 62 findings is close to the floor.)

---

## D11. Classification is a decision table over provenance and lineage, not an argmax over severity

**Decision.** `core/confidence/classifier.py` decides *which kind* of
tampering occurred with an ordered set of decisive rules, and a decisive rule
wins outright. Pattern-matching on severities is only the fallback.

The rules, in order:

| # | condition | label | reasoning |
|---|---|---|---|
| 1 | duplicate evidence, and arbitration **blamed** this side | `DUPLICATED` | it is the copy, not the original |
| 2 | orphan occupying a port call its container never had | `FABRICATED` | the event was invented, not edited |
| 3 | committed to the chain, content now differs | `MODIFIED` | it existed, and it changed |
| 4 | never committed, inside the sealed window | `FABRICATED` | it was inserted after the fact |
| 5 | — | severity patterns | no decisive signal available |

**Why each piece exists — all three were failures found by measurement:**

*Decisive rules must win.* Initially a decisive rule merely contributed a
score, then competed with the fallback. A fabricated record carries
`FUTURE_EVENT` at 0.92, which outvoted `FABRICATED` at 0.85 and relabelled it
`MODIFIED`. Severity measures *how abnormal*; it says nothing about *what
kind*, and letting it arbitrate the label was a category error.

*Arbitration resolves duplicate pairs.* Both halves of a duplicate pair carry
duplicate evidence. The arbitration pass has already decided which side the
manifest supports, so reusing that answer costs nothing — the blamed side is
the copy.

*Time slots separate fabrication from relocation.* The hardest case: a
fabricated row given an id freed by a deletion. The chain holds a commitment
for that id, so it reports a hash mismatch — real, but describing the *id*,
not the record. Both a teleported record and a fabricated one lose their port
and route relationships, so lineage alone cannot separate them. What does:
records of one real port call share that call's `arrival_timestamp`, so a
record sharing a slot was a real event that was *rewritten*, while one sharing
no slot was *invented*.

**Measured effect**, classification accuracy over 219 detected records:

| version | accuracy | FABRICATED recall |
|---|---:|---:|
| argmax over severity | 72.6% | 0/44 |
| + chain as discriminator | 78.1% | 12/44 |
| + decisive rules win | 85.4% | 29/44 |
| + invented-slot test | **90.4%** | **44/44** |

Repair accuracy rose with it (89.8% → 91.9% exact records), since a correct
class drives the right candidate strategies.

---

## D12. Deterministic impossibilities floor the probability instead of arguing with the prior

**Decision.** `fusion.decisive_floors` lists codes that are physical or
logical impossibilities. When one fires above its configured severity, the
fused probability is floored at a configured value rather than being left to
log-odds arithmetic.

**Why.** The prior sits at the observed 5% base rate, so its log-odds are
−2.94. That means *no single layer* could convict on its own unless its weight
exceeded ~3.0 — and eight byte-identical duplicates were being missed at
p ≈ 0.21 for exactly that reason. But two records sharing one content hash in
a manifest with unique ids is not a 21% proposition.

The first attempt raised the layer weights. That failed, and the failure is
instructive: lifting `TEMPORAL` far enough for simultaneous presence to
convict alone also lifted `DWELL_TIME_ANOMALY`, which must never convict
alone. Measured, it traded 6 extra false positives for 3 extra detections —
F1 0.942 → 0.937.

Flooring separates the two concerns. Weights stay tuned for *corroboration*;
floors express *"this finding is not a matter of degree"*. Spec 1.2 asks for
deterministic, explainable evidence to be preferred over opaque scoring, and
this is that preference made mechanical.

An inconclusive hash mismatch is explicitly excluded from being decisive — if
a hashed field was lost in the export, the mismatch proves nothing (D3).

**Measured effect** (tuning seed):

| version | precision | recall | F1 | FP (clean) |
|---|---:|---:|---:|---:|
| original weights | 0.991 | 0.897 | 0.942 | 2 |
| raised weights | 0.965 | 0.910 | 0.937 | 7 |
| original weights + floors | **0.991** | **0.910** | **0.949** | **2** |

---

## D13. Weights are calibrated on one seed and reported on seeds never seen

**Decision.** All tuning was done against seed 481516. Results are reported
across that seed plus two held-out seeds generated only after tuning stopped.

| seed | precision | recall | F1 | FP clean | FP noisy | classification | repair | deletion recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 481516 (tuned on) | 0.991 | 0.910 | 0.949 | 2 | 0 | 90.5% | 89.9% | 94.5% |
| 271828 (held out) | 0.987 | 0.917 | 0.951 | 3 | 0 | 87.1% | 96.6% | 98.2% |
| 999331 (held out) | 0.986 | 0.843 | 0.909 | 3 | 0 | 93.3% | 89.2% | 96.4% |

Held-out performance tracks the tuning seed, so the thresholds are not fitted
to one world. Recall varies most (0.843–0.917), which is expected: it depends
on how many of a given seed's edits happen to fall in the uncommitted tail,
where no chain evidence exists.

**Zero false alarms on noise-only records across all three seeds** is the
result worth stating plainly, since it is the half of the problem most easily
lost while chasing recall.

---

## D14. Calibration is reported, not corrected

**Decision.** The reliability table is printed as measured. No Platt scaling
or isotonic regression is applied.

**Why.** Above p = 0.5 the system is systematically *under*-confident — the
0.6–0.7 bin is right 100% of the time. Correcting that requires fitting
against labels, and the only labels available are the answer key. Fitting on
it would make every reported number circular, which is a worse sin than
being conservative.

Under-confidence is also the safe direction: it means a stated 70% is at
least 70%, so a threshold set on these scores does not quietly admit more
false alarms than intended. The gap is stated in the evaluation console so a
reader can judge it directly.

---

## D15. The live feed's novel attacks were answered with general constraints

**Decision.** The stream carries three attack patterns absent from the batch
data, each defeating a *different* batch assumption. None was answered with a
rule that recognises it.

| pattern | what it defeats | what catches it |
|---|---|---|
| `weight_siphon` | the per-transition conservation **tolerance** — many steps, each legal, large in total | a general cumulative-conservation constraint over a run of transitions |
| `ghost_transfer` | **lineage** — a cargo event at a port the container never reached | "cargo cannot be handled where it never arrived" |
| `identity_swap` | **identity continuity** — two containers exchange ids mid-voyage | cargo-type and weight conservation across consecutive port calls |

`CARGO_DRIFT_UNEXPLAINED` is the only new detector logic the twist required,
and it is a conservation constraint, not a siphon detector. It fires only when
**every individual step is inside the per-transition tolerance** — because
that is the only case the per-transition check cannot already see. Without
that condition it re-reported single large edits and attributed them to the
last record of the run, which is usually innocent: measured, 14 extra false
positives across three seeds.

**Results** (900 events, 48 attacks, 852 legitimate):

| pattern | event recall | campaign recall |
|---|---:|---:|
| `ghost_transfer` | 100% | 100% |
| `identity_swap` | 25% | 57% |
| `weight_siphon` | 26% | 50% |

Zero false alarms on clean containers; 1.6 ms mean latency per event.

**Two measurement points stated rather than hidden:**

*Event recall understates campaign attacks.* A siphon or swap spans many
events for one container. The *onset* is detectable because it contradicts
prior history; once the state is consistently wrong, later events are
internally consistent and there is nothing left to contradict. Campaign recall
("was this container caught being attacked at all?") is the operationally
meaningful number, so both are reported.

*Collateral flags are not false alarms.* Once an injected record sits in a
container's history, later legitimate records of that container genuinely
contradict it. Four such flags occurred. Counting them as false alarms would
penalise the system for noticing the contamination it exists to notice, so
they are reported separately from false alarms on untouched containers (of
which there were none).

**Known limitation.** The siphon is deliberately the hardest of the three and
is only caught once cumulative drift clears the tolerance — roughly five
transitions in. A siphon that stops early, or one calibrated below the
cumulative tolerance as well, would survive. The honest mitigation is a
tighter cumulative tolerance, which trades directly against false alarms on
legitimate rounding drift; the current value is set where that trade is
measured, not assumed.

---

## D16. Container reuse across bookings is out of scope, and the feed reflects that

**Decision.** The live feed books **new** containers rather than reusing batch
containers.

**Why.** Reusing them was tried first and produced false alarms on legitimate
events: a container's history then spans two bookings with different owners,
routes and cargo, so owner continuity, route sequence and cargo conservation
all break legitimately. Containers genuinely are reused in reality, and
supporting it properly means scoping *every* continuity check to a shipment
leg rather than to a container's whole life.

Two of those checks were rescoped because they were cheap and correct anyway:
the lifecycle-ordering check and the orphan test (see D17). The rest —
conservation, route sequence, speed feasibility across a gap between bookings
— were left container-scoped and the feed avoids the case. That is a scoping
decision, not an oversight: a repositioned empty container leaves no manifest
record at all, so the gap between bookings cannot be validated from the
manifest, and inventing a rule for it would be unfounded.

---

## D17. Absence is not evidence on a live feed

**Decision.** The orphan test's "no other record places this container here"
condition only counts when **later events exist** for that container.

**Why.** In a batch the whole history is present, so absence means absence. On
a live feed it may simply mean *not yet* — the rest of the port call has not
been reported. Without the qualifier, every genuine new arrival in the stream
looked orphaned, and the live path's precision collapsed.

The same principle applies to the final port call of an in-progress voyage in
*batch* mode, where the deletion inference already requires a later call
before claiming a missing departure (D10). It is the same idea arrived at from
two directions, and it is worth stating as a rule: **a consistency engine must
distinguish "this did not happen" from "this has not happened yet."**


---

## D18. Determinism had to be verified across *processes*, not within one

**Decision.** `tests/test_pipeline.py` runs the generator twice in separate
subprocesses with different `PYTHONHASHSEED` values and requires byte-identical
output.

**Why.** The original determinism test ran both generations in one process, so
they shared a hash seed — and that is exactly the bug it missed.

Freed record ids were released into the insertion pool by iterating
`set(deletions_pending)`. Set iteration order follows string hashing, which
Python randomises per process, and the pool's `take()` pops a random *index*.
So a different id got recycled on every run: the world, the clean manifest, the
route histories and the provenance chain were all byte-identical, while
**`manifest_suspect.csv` differed**.

It surfaced only because wiping `out/` and re-running the documented README
flow produced a different false-alarm split (2 clean / 0 noisy became
1 clean / 1 noisy) with every other figure unchanged. A one-record difference
in which id got recycled, nothing more — but "use a fixed random seed so the
data can be regenerated exactly" is an explicit requirement, and a judge
re-running the generator and getting different numbers would have been fatal.

The fix is one `sorted()`. The lesson is that a reproducibility test which
cannot observe hash-order dependence is not a reproducibility test.

Final figures after the fix (mean F1 rose 0.936 → 0.939, since id recycling
changed which records the chain could speak to):

| seed | precision | recall | F1 |
|---|---:|---:|---:|
| `481516` | 0.991 | 0.914 | 0.951 |
| `271828` | 0.979 | 0.925 | 0.951 |
| `999331` | 0.986 | 0.851 | 0.914 |
