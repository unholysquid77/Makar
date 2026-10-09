# Shifting Waters — what changed, what it cost

> *"New intelligence reveals that the attacker has started modifying records in
> real time."*

---

## The short version

Makar was already streaming. The twist's five requirements landed against a
system that had a live path, so the honest answer is that **three were already
met, two were not, and the two that were not are the interesting half.**

| requirement | before the twist | after |
|---|---|---|
| **Streaming** — process records continuously | ✅ incremental processor, container-scoped | unchanged |
| **Real time** — seconds, not hours | ✅ 1.6 ms/event | **0.60 ms/event** |
| **Unknown attacks** — unseen patterns | ✅ 3 novel patterns, constraint-based | **4 patterns** |
| **Precision** — don't disrupt real operations | ⚠️ 0 false alarms, but **no alert control** | alert layer: findings → problems |
| **Live report** — manifest and report stay current | ❌ per-event verdicts only | live manifest + live report |
| *(implied)* **"incoming *and updated* records"** | ❌ append-only feed | **revision semantics** |

Headline: **45/45 after-the-fact edits caught, 0/32 operator corrections
false-alarmed**, stream F1 0.567 → **0.815**, precision still **1.000**.

---

## 1. The gap that mattered: records became mutable

The phrase in the brief is *"incoming **and updated** records"*, and the
scenario is an attacker editing in place. Our feed only appended. That is not
a tuning gap, it is a **semantic** one: the batch design assumes a record is
an immutable report of an event that happened. The twist makes records
mutable.

Three things had to change, in order.

### 1.1 A record_id arriving twice is an update, not an insert

`StreamProcessor.ingest` now checks whether the id is already known. If it is,
the superseded version is **removed from the container's working set and from
the live manifest** before the new one is scored. Without that, a revision
reads as an exact duplicate of itself and the container appears to hold two
contradictory records — the system would have confidently detected an attack
that did not happen.

### 1.2 Telling an attacker's edit from an operator's correction

This is the whole precision problem. Both arrive identically: a row under a
record_id already seen. Alerting on *any* change would bury the operator the
first time someone supplied a field that was missing from the original
delivery, which is exactly the "disrupts real operations" failure the brief
names.

**The first approach was wrong, and the way it was wrong is instructive.**

We re-ran the consistency engines over the record as it *was* and as it now
*is*, and used the change in anomaly weight as the evidence. Elegant, general,
and it caught **10%** of known malicious edits.

The reason is specific: cargo conservation **deliberately stands down** across
a port call containing a `LOADED`, `UNLOADED` or `TRANSFERRED` event, because
cargo legitimately changes there. That is correct batch behaviour — and it
means the check is blind exactly where the attacker is working. Of 30 known
edits, 15 measured a consistency delta of exactly `0.00`.

**The right framing is about time, not consistency.** A manifest record
describes an event that has *already happened*. A `LOADED` event at 09:00 does
not justify revising that event's weight at 14:00 — the loading is over. So
every changed field is classified by *how* it changed:

| transition | meaning | treatment |
|---|---|---|
| `null → value` | a late-arriving field | routine, no alert |
| `value → null` | data loss in transit | data-quality finding |
| `value → different value` | **an already-reported fact rewritten** | the signal |

The measured consistency delta did not get discarded — it became the
*modulator*:

| altered a populated field | and consistency… | severity | reading |
|---|---|---:|---|
| yes | degraded | 0.90 | an edit that made things worse |
| yes | improved | 0.15 | what a genuine correction looks like |
| yes | unchanged | 0.62 | unexplained edit of history — worth a look, not a conviction |
| no (only filled) | — | 0.10 | routine |

Detection went **10% → 100%**, with corrections still at **0%** false alarms.

Note what is *not* in that table: any knowledge of what a malicious edit looks
like. No list of suspicious fields, no thresholds on weight ratios. It
generalises to revision attacks nobody wrote a rule for, which is the point of
the twist.

### 1.3 The chain is decisive where it reaches

A revision that breaks a hash the chain **already committed** is in a
different class entirely — the edit provably happened after the block was
sealed. That gets its own code and a near-certain floor. Symmetrically, a
revision that *restores* the committed hash is a provable correction and is
accepted silently.

---

## 2. The gap we had not noticed: operator load

Precision is necessary and not sufficient. A *correct* alert repeated forty
times for the same container is still a flood, and an operator who starts
ignoring the feed is no better off than one being lied to. Our live path
raised one notification per flagged event. On a campaign-style attack that is
forty interruptions for one problem.

So a layer went in **between detection and the operator** — `core/alerting.py`.
Findings are folded into an **open alert per entity**, and that alert updates
in place. A second finding on the same container notifies only if it carries
new information:

- the probability rose by at least `escalation_delta` (0.12), **or**
- an evidence *layer* appeared that the alert did not already have, **or**
- the probability crossed `critical_probability` (0.90).

Everything else is absorbed. The alert's own record still grows — event count,
peak probability, every code seen — so nothing is lost; it simply stops
interrupting anyone.

Grouping is by **container**, because that is the unit a campaign targets and
the unit an investigator actions. A siphon across twelve events is one
problem, not twelve.

Measured on a 977-event feed: **68 findings → 58 notifications**, 10 folded in
(15% suppression). The unit test pins the extreme case: 40 findings on one
container produce **exactly one** notification, and the alert still reports all
40 events.

The compression ratio of 1.17× is honest rather than impressive, and the
reason is worth saying out loud: most attacks in this feed hit *different*
containers, and one alert per real problem is the correct answer. Suppression
only has something to compress where a campaign repeats on one entity. Pushing
that number higher would mean grouping unrelated problems together, which
would be worse.

---

## 3. The gap the brief names outright: live report

The reconstructed manifest and the suspicious activity report had to **stay
current**, not be rebuildable. The processor now holds the disposition of
every record and revises it in place:

- `live_manifest()` — one row per record, each with exactly one of `ORIGINAL`,
  `REPAIRED`, `REMOVED`, `UNRECOVERABLE`, plus a revision count
- `live_summary()` — dispositions, revisions seen, corrections accepted
- `live_report()` — the same shape as the batch report: ranked records with
  evidence, affected owners and ports, open alerts, accepted corrections

Exposed as `GET /api/stream/manifest`, `/api/stream/report`,
`/api/stream/alerts`, and rendered live in the UI's Live panel.

The invariant a test pins: **a revised record occupies exactly one row.** It is
replaced, never appended.

---

## 4. What we traded away for speed

The brief asks this directly. The live path is ~4,500× faster per record than
the batch path, and these are the five things it gives up:

**1. Multivariate statistical models.** Batch fits Isolation Forest, LOF and
DBSCAN over the whole feature matrix — 1,426 ms, over half the batch runtime.
Live keeps an incremental robust z-score against running per-cargo-class
samples. *Lost:* anomalies visible only in combinations of fields. *Kept:* the
univariate robust check, which carries most of that layer's weight anyway —
and the layer is the lowest-weighted in the system by design.

**2. Cross-container reasoning.** Live detectors run on a context holding one
container's history, typically a dozen records. That is what makes cost
independent of manifest size. *Lost:* findings that need two different
containers — a vessel's total manifested weight against its capacity, per-port
throughput conservation. *Kept:* everything container-scoped, which is almost
every constraint in the system.

**3. Whole-graph construction.** The batch path builds the full cargo
intelligence graph (5,900 nodes, 36,116 edges) and annotates it with evidence.
Live does not rebuild it per event. *Lost:* Bloodhound queries reflect the last
batch analysis, not the last second. *Mitigation:* re-running `/api/analyze`
folds the live records in.

**4. Retrospective re-arbitration.** Blame arbitration runs within the
arriving record's container scope. A later event cannot retroactively
exonerate a record scored an hour ago. *Lost:* the batch path's ability to
revisit every conflict with full hindsight. *Why it is acceptable:* the live
threshold is lower precisely because a live alert is triage, and the batch
re-run is the adjudication.

**5. Deletion inference.** Inferring a deletion needs the *shape* of a
completed voyage — a port call missing an event it should have had. Live
histories are partial by definition, and the orphan test already requires
later events to exist before absence counts as evidence (you cannot
distinguish "did not happen" from "has not happened yet"). *Lost:* live
deletion detection. *Kept:* it is recovered on the next batch run.

---

## 5. What did **not** change

Worth stating, because it is the strongest evidence that the original design
was right:

- **No change to the fusion weights.** The live path fuses with the same
  log-odds weights as the batch path. A test asserts they are identical, so
  the two cannot silently diverge.
- **No change to the classifier.** The same decision table over provenance and
  lineage.
- **No change to the reconstruction engine.** The same candidate generation and
  scoring.
- **No second rule set.** The live path runs the *same registered detectors*.

The only genuinely new detection logic the twist required is the revision
semantics above. Everything else was already constraint-based, which is why it
transferred without retuning.

**The architecture did not need rethinking. The data model did** — records
stopped being immutable — and that change was contained to the stream
processor because detection never assumed immutability in the first place.

---

## 6. Numbers

977 events (884 legitimate), replayed through the incremental processor.

### Detection

| metric | value |
|---|---:|
| precision | **1.000** |
| recall | 0.688 |
| F1 | **0.815** *(was 0.567)* |
| false alarms on untouched containers | **0** |
| collateral flags on already-attacked containers | 4 |
| mean latency | **0.60 ms** |
| p95 latency | 1.49 ms |

### By attack pattern

| pattern | what it defeats | event recall | campaign recall |
|---|---|---:|---:|
| `live_revision` | immutability — editing after the fact | **100%** | **100%** |
| `ghost_transfer` | lineage | 100% | **100%** |
| `identity_swap` | identity continuity | 25% | 57% |
| `weight_siphon` | the per-step conservation *tolerance* | 26% | 50% |

### Revisions

| | events | outcome |
|---|---:|---|
| attacker edits an already-reported value | 45 | **45 caught (100%)** |
| operator corrects a missing value | 32 | **0 false alarms (0%)** |

### Operator load

| metric | value |
|---|---:|
| findings above the alert threshold | 68 |
| operator notifications | 58 |
| folded into an existing alert | 10 (15%) |
| open alerts | 44 |

---

## 7. Known limits, stated plainly

**Consistent lies survive after onset.** An identity swap is caught when it
contradicts prior history. Once the state is consistently wrong, later events
are internally consistent and there is nothing left to contradict. That is a
property of consistency reasoning, not a bug — and it is why campaign recall
is reported alongside event recall.

**Gradual siphoning is caught late.** Roughly five transitions in, once
cumulative drift clears the tolerance. A siphon calibrated below the cumulative
tolerance too would survive. Tightening it trades directly against false alarms
on legitimate rounding drift.

**Alert compression is modest here (1.17×)** because the attacks are spread
across containers. It is a floor, not a ceiling: the mechanism compresses 40:1
when a campaign concentrates.

**No cross-container live constraints.** See trade-off 2. The most promising
unexploited signal is a vessel's total manifested weight against its capacity,
which needs a second scope the live path does not currently build.
