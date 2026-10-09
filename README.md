# Makar

**Distributed cargo forensics, provenance & reconstruction.**

> Makar takes a suspect cargo manifest and reconstructs a trustworthy one,
> fusing provenance, temporal, spatial, graph, statistical and
> cargo-consistency evidence. Every record in the output is marked
> `ORIGINAL`, `REPAIRED`, `REMOVED` or `UNRECOVERABLE` — nothing is silently
> changed.

Built for **The Lost Manifest — Cargo Tampering Detection & Reconstruction**.

---

## Results

Measured against a private injection log the detection pipeline never reads.
Thresholds were tuned on seed `481516`; the other two seeds were generated
**after** tuning stopped and never used to adjust anything.

| seed | precision | recall | F1 | false alarms (clean) | false alarms (noisy) | classification | repair (exact) | deletion recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `481516` *(tuned on)* | 0.991 | 0.914 | **0.951** | 2 / 4,522 | **0 / 285** | 90.6% | 90.0% | 94.5% |
| `271828` *(held out)* | 0.979 | 0.925 | **0.951** | 5 / 4,537 | **0 / 271** | 87.2% | 96.6% | 98.2% |
| `999331` *(held out)* | 0.986 | 0.851 | **0.914** | 3 / 4,532 | **0 / 273** | 92.9% | 88.2% | 96.4% |

**Zero false alarms on noise-only records across all three seeds.** Half this
problem is not flagging the legitimate shipment with a blank cell and a
day-first date, and that is the number that says so.

Per attack type on the tuning seed:

| attack | injected | detected | recall |
|---|---:|---:|---:|
| `FABRICATED` | 44 | 44 | **100%** |
| `DELETED` (by slot) | 55 | 52 | **94.5%** |
| `DUPLICATED` | 75 | 67 | **89.3%** |
| `MODIFIED` | 125 | 112 | **89.6%** |

### Ablation — the provenance chain is not doing all the work

The chain is the strongest single evidence source, so reporting only the
headline would hide how much the consistency engines contribute.

| configuration | precision | recall | F1 |
|---|---:|---:|---:|
| all detectors | 0.991 | 0.914 | 0.951 |
| **forensics only, chain disabled** | 0.978 | 0.369 | 0.536 |

The chain commits **hashes, never values**, and covers only 85% of the
timeline. It can prove a record changed; it cannot say what the record used to
contain. Reconstruction is therefore entirely the forensic engines' work — and
where the chain *does* reach, hashing a candidate repair either **confirms** it
outright or refutes it.

### Live stream — and the Shifting Waters twist

Mid-event the attacker went live: *"the attacker has started modifying records
in real time"*, with a feed of incoming **and updated** records.

977 events (884 legitimate), **0 false alarms on untouched containers**,
**0.60 ms** mean latency per event.

| metric | value |
|---|---:|
| precision | **1.000** |
| recall | 0.688 |
| F1 | **0.815** |

| pattern | what it defeats | event recall | campaign recall |
|---|---|---:|---:|
| `live_revision` | immutability — editing after the fact | **100%** | **100%** |
| `ghost_transfer` | lineage | 100% | **100%** |
| `identity_swap` | identity continuity | 25% | 57% |
| `weight_siphon` | the per-step conservation *tolerance* | 26% | 50% |

**The twist's hardest requirement was precision, not detection.** The feed
carries attacker edits and legitimate operator corrections, identical in shape
— both are simply a row arriving under a record_id already seen:

| | events | outcome |
|---|---:|---|
| attacker rewrites an already-reported value | 45 | **45 caught (100%)** |
| operator supplies a value that was missing | 32 | **0 false alarms (0%)** |

No rule describes what a malicious edit looks like. A manifest record describes
an event that *already happened*, so rewriting a populated field afterwards is
an edit of history — and whether it moved the record *toward* consistency or
*away* from it decides which kind it was.

**Operator load** is treated as its own problem: a correct alert repeated forty
times is still a flood. Findings fold into one open alert per container, so 68
findings became 58 notifications — and 40 findings on a single container
produce exactly **one**.

Campaign recall is the operationally meaningful figure for siphons and swaps:
the *onset* contradicts prior history, but once the state is consistently wrong
there is nothing left to contradict. Both are reported.

→ **[docs/TWIST_RESPONSE.md](docs/TWIST_RESPONSE.md)** — what changed, what it
cost, and the five things traded away for speed.

## How to Run

Requires **Python 3.11+** and **Node 18+**. No external services, no database
server, no API keys.

### 1. Install

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.txt
npm --prefix frontend install
```

On macOS/Linux use `.venv/bin/python` instead of `.venv/Scripts/python.exe`.

### 2. Generate the dataset

```bash
.venv/Scripts/python.exe scripts/generate.py --seed 481516 --records 5000 --out out
```

Builds the synthetic world, the clean manifest, the corrupted suspect
manifest, the provenance chain and the four-node network. The same seed
reproduces all of it exactly.

### 3. Analyse and score

```bash
.venv/Scripts/python.exe scripts/evaluate.py --out out --ablation
```

### 4. Generate the forensic report

```bash
.venv/Scripts/python.exe scripts/report.py --out out --top 25
```

Writes `out/report.md` — totals by tampering type, ranked suspicious records
with the evidence behind each flag, affected owners and ports, inferred
deletions, the suspected attack timeline, and the data-quality findings that
were deliberately **not** treated as attacks.

### 5. Replay the live feed

```bash
.venv/Scripts/python.exe scripts/stream_sim.py --out out --events 900
```

### 6. Run the interface

Two processes. API first:

```bash
.venv/Scripts/python.exe -m backend.main
```

Then the UI:

```bash
npm --prefix frontend run dev
```

Open **http://localhost:5173**. The Vite dev server proxies `/api` to port
8000, so no CORS configuration is needed.

### Everything at once

```bash
.venv/Scripts/python.exe scripts/demo.py
```

Runs generate → analyse → evaluate → report → stream in sequence and prints
the figures above.

---

## Environment Variables

**None are required.** The system runs fully with nothing set, including the
LLM layer, which is disabled by default. The one that visibly changes the demo
is `VITE_CARTO_API_KEY`: without it the geo map renders all of its own
geometry but has no basemap tiles underneath.

| variable | default | purpose |
|---|---|---|
| `MAKAR_DATA_DIR` | `out` | Dataset directory the API serves. |
| `MAKAR_MANIFEST` | `manifest_suspect.csv` | Manifest file to analyse. |
| `MAKAR_API_HOST` | `127.0.0.1` | API bind host. |
| `MAKAR_API_PORT` | `8000` | API bind port. |
| `MAKAR_LLM_PROVIDER` | `disabled` | `disabled` · `openai` · `anthropic` · `local` |
| `MAKAR_LLM_MODEL` | *(provider default)* | Model id for the analyst. |
| `MAKAR_LLM_API_KEY` | — | Required only if a provider is enabled. Without it the provider falls back to `disabled`. |
| `MAKAR_LLM_BASE_URL` | — | For `local` / OpenAI-compatible endpoints. |
| `MAKAR__<path>` | — | Override any config value, `__` for nesting: `MAKAR__detection__geospatial__speed_ratio_hard=1.5` |
| `VITE_API_BASE` | *(empty)* | Frontend only. Point the UI at a non-proxied API origin. |
| `VITE_CARTO_API_KEY` | — | Frontend only, in `frontend/.env.local`. CARTO basemaps require a key. **Without it the map still draws every forensic layer** over a plain background and says so on screen. |

Copy `.env.example` to `.env` as a starting point. **The LLM is an explanation
interface only** — it cannot modify the manifest, the verdicts or the chain,
and every number in this README was produced with it disabled.

---

## What it produces

`scripts/generate.py` writes into `--out`:

| file | contents |
|---|---|
| `manifest_suspect.csv` / `.json` | **the system's input** |
| `manifest_clean.csv` / `.json` | reference only; never read by `core/` |
| `ground_truth.json` | **private answer key** — only `evaluation/` reads it |
| `world.json` | ports, vessels, routes, owners, shipments, containers |
| `route_manifests.json` | per-container route histories |
| `chain.json` / `node_chains.json` / `nodes.json` | provenance chain and the four nodes |
| `data/ports.geojson`, `data/routes.geojson` | map layers |

Then `evaluation.json`, `report.md` / `report.json` and
`stream_evaluation.json` from the three scripts above.

---

## The eight interfaces

| view | what it is for |
|---|---|
| **Command Center** | What the manifest *now is* — a disposition, not a score. |
| **Geo Forensic Map** | Layers, confidence floor, class filters, timeline slider; observed vs reconstructed paths. |
| **Bloodhound** | Follow evidence through the graph: Expand / Isolate / Conflict / Trace / Timeline, plus shortest evidence path. |
| **Attack Timeline** | Inferred windows as hypotheses with confidence, and the inferred deletions. |
| **Record Ledger** | The working queue, filterable by class, disposition, owner, port and probability. |
| **Record Investigation** | Observation → Evidence → Inference → Decision, with the arithmetic and the blame arbitration shown. |
| **Reconstruction** | Every candidate the engine generated, with per-criterion scores — not just the winner. |
| **Provenance Monitor** | Chain ledger, sealed coverage, and the node that diverges while passing its own integrity check. |
| **Live Feed** | Replay the stream: unseen attack patterns, live record revisions, the live reconstructed manifest, and operator load. |
| **Evaluation Console** | The scorecard, including the ablation and the calibration gap. |

---

## How it works

```
suspect manifest
  → normalise            typed records + FORMAT evidence (benign, negative weight)
  → provenance view      majority chain + cross-node consistency
  → 8 detectors          independent evidence layers, none allowed a verdict
  → arbitrate            decide who to blame in a contradiction
  → fuse                 calibrated probability with an auditable breakdown
  → classify             which kind of tampering, by decision table
  → reconstruct          candidate original states, scored and selected
  → attack timeline      group anomalies into windows
```

Eight detectors, registered by name and enabled from YAML
(`detection.enabled`): `temporal`, `geospatial`, `route`, `cargo`,
`duplicate`, `statistical`, `graph`, `provenance`. Forty-nine evidence codes
across ten reasoning layers. **No detector may classify a record** — they
observe and emit evidence; only the confidence layer infers and only the
reconstruction layer decides.

Three ideas carry most of the result:

**Baselines are learned from the manifest with robust statistics.** There is
no labelled ground truth, so "normal" is estimated from the data — which is
the same data that was tampered with. Everything uses median/MAD, whose 50%
breakdown point survives contamination far beyond any plausible attack rate.

**Messiness is exculpatory.** `FORMAT` evidence carries a *negative* fusion
weight, so a record with a blank cell and a day-first date is scored as *less*
likely to have been deliberately edited. This is why the noise false-alarm rate
is zero.

**Symmetric evidence, asymmetric blame.** When two records contradict each
other, both carry the finding — but only one is usually the lie. A separate
arbitration pass decides which, using corroboration from independent layers.
This was found by measurement: with temporal + geospatial detectors alone,
*every* clean-record false positive was the innocent half of a genuine
conflict pair. It took false positives from 198 to 2.

---

## Documentation

- **[docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md)** — the full platform
  walkthrough: demo script, every feature, every formula, every number, and the
  questions a reviewer is likely to ask.
- **[docs/TWIST_RESPONSE.md](docs/TWIST_RESPONSE.md)** — the Shifting Waters
  twist: what changed, what it cost, what was traded for speed.
- **[docs/APPROACH_DOSSIER.md](docs/APPROACH_DOSSIER.md)** — approach and
  reasoning, alternatives rejected, strengths and weaknesses, scalability, and
  how the solution changed for the live feed.
- **[docs/DESIGN_DECISIONS.md](docs/DESIGN_DECISIONS.md)** — every design
  decision with the measurement behind it, including the ones that failed and
  were reverted.
- **[docs/DATA_DICTIONARY.md](docs/DATA_DICTIONARY.md)** — every manifest
  field, every evidence code, every attack class.

---

## Repository layout

```
core/            detection, confidence, reconstruction, graph, normalisation
  alerting.py    folds findings into open alerts, so operators see problems
  streaming.py   incremental analysis, live revisions, live manifest
  detection/     the eight engines + shared context and segmentation
  confidence/    arbitration, fusion, classifier
  reconstruction/candidate generation and scoring
  graph/         cargo intelligence graph and its forensic queries
blockchain/      block, chain, node, consensus, network
generator/       world, manifest, corruption, stream + the private log
evaluation/      metrics and ground-truth scoring (the only reader of the key)
reporting/       the suspicious activity report
backend/         FastAPI service
frontend/        React + TypeScript + Tailwind
configs/         every tunable threshold in the system
scripts/         generate · evaluate · report · stream_sim · demo
tests/           unit and property tests
```

Nothing under `core/` imports from `generator/` at analysis time. That is what
makes the reported numbers mean something.

---

## Images Gallery

---

### Command Dashboard

<img width="1280" height="674" alt="image" src="https://github.com/user-attachments/assets/9b981d59-d3d6-4b76-8f96-c5057c8f5c10" />



### Geo Forensic Map

<img width="1280" height="674" alt="image" src="https://github.com/user-attachments/assets/0fd672b6-2aac-491e-a725-9cf1956426a1" />



### Bloodhound

<img width="1280" height="674" alt="image" src="https://github.com/user-attachments/assets/280bc45a-7a88-4c17-bb4e-3043286c9083" />



### Timeline

<img width="1280" height="677" alt="image" src="https://github.com/user-attachments/assets/dad3dd1b-a47d-48b8-bc00-ed1f05e9d353" />



### Record Ledger

<img width="1280" height="671" alt="image" src="https://github.com/user-attachments/assets/7e32a4bf-bda4-47c9-8503-61977589fa67" />



### Investigate

<img width="1280" height="675" alt="image" src="https://github.com/user-attachments/assets/28766e1a-3e07-4b3a-b128-c45626afdb84" />



### Rebuild Log

<img width="1280" height="672" alt="image" src="https://github.com/user-attachments/assets/c4bd47ad-ba21-4a6f-b9a0-21bad5c037e0" />



### Provenance

<img width="1280" height="668" alt="image" src="https://github.com/user-attachments/assets/3ac5551e-8458-4aae-81ee-0eebdd022825" />



### Live Feed Demo

<img width="1280" height="672" alt="image" src="https://github.com/user-attachments/assets/f6cc1e15-f7b0-4d72-940e-4f1857a4b927" />



### Evaluation Metrics

<img width="1280" height="677" alt="image" src="https://github.com/user-attachments/assets/ab5c255b-151d-4129-ae94-2cf203ac57e7" />








