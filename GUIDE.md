# FaultSeeker++ Web Console: Complete Guide

This guide covers everything added around the original FaultSeeker research code: the web console, its API,
the tests, and deployment to Render. The original `README.md` and the `faultseeker` command-line tool are
unchanged in behaviour; see [What changed](#1-what-changed-and-what-did-not) for the exact list of touched files.

**Contents**
1. [What changed (and what did not)](#1-what-changed-and-what-did-not)
2. [Quick start (local)](#2-quick-start-local)
3. [Prerequisites in detail](#3-prerequisites-in-detail)
4. [Using the console](#4-using-the-console)
5. [Supported networks](#5-supported-networks)
6. [Configuration reference](#6-configuration-reference)
7. [Running the tests](#7-running-the-tests)
8. [Deploying to Render](#8-deploying-to-render)
9. [Running with Docker locally](#9-running-with-docker-locally)
10. [API reference](#10-api-reference)
11. [Security model](#11-security-model)
12. [Troubleshooting](#12-troubleshooting)
13. [Project layout](#13-project-layout)
14. [Known limitations](#14-known-limitations)
15. [Extending](#15-extending)

---

## 1. What changed (and what did not)

**New (nothing existing was replaced):**

| Path | Purpose |
|---|---|
| `web/` | The console: your `index.html` (unchanged) plus `assets/console.css` and `assets/console.js` |
| `faultseeker/server/` | FastAPI service: runs analyses in isolated subprocesses, streams progress, stores history |
| `faultseeker/chains.py` | One registry of networks (id, chain ID, explorer, support level) used by every module |
| `tests/` | Python test suite and a browser-level UI suite (`tests/ui/`) |
| `Dockerfile`, `docker-entrypoint.sh`, `.dockerignore`, `render.yaml` | Deployment |
| `GUIDE.md` | This file |

**Small edits to original files** (each one is covered by a test in `tests/test_pipeline_patches.py`):

| File | Change | Why |
|---|---|---|
| `faultseeker/data_collection/txn_replayer.py` | Reads `FAULTSEEKER_RPC_URL` if set; prints cast's error output; never prints the RPC URL | Per-run custom RPC without leaking its key; real error messages instead of silent empty output |
| `faultseeker/data_collection/txn_info_collector.py` | `curl` gets a browser user agent, a 45 s timeout, redirects and an optional proxy; prints a diagnostic when the explorer page is unusable; explorer links come from the registry | Explorers often reject bare `curl`; failures were silent |
| `faultseeker/data_collection/contract_downloader.py` | Uses `getCode --chainid <id>`; passes `ETHERSCAN_API_KEY` as `-k` when set | One naming scheme for every network; paid-tier networks need a key |
| `faultseeker/core/pipeline.py` | Handles a failed Stage 1 before unpacking its result | Original code crashed with `cannot unpack non-iterable NoneType` instead of reporting the failure |
| `foundry.toml` | Added RPC aliases: `linea scroll celo cronos moonbeam aurora` | Replay on the extra networks |
| `requirements.txt` | Added `fastapi`, `uvicorn` | The server |
| `README.md` | Appended a short "Web console" section | Pointer to this guide |

The CLI works exactly as before:

```bash
faultseeker -txn_hash 0x9f4ef3cc55b016ea6b867807a09f80d1b2e36f6cd6fccfaf0182f46060332c57 -chain bsc
```

---

## 2. Quick start (local)

Requires Python 3.10 or newer (3.11 recommended), `curl`, and Foundry's `cast` (see [section 3](#3-prerequisites-in-detail)).

```bash
cd FaultSeeker-main
python3 -m venv venv && source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .

uvicorn faultseeker.server.app:app --port 8000
```

Open <http://localhost:8000>. The badge at the top right should read **LOCAL · READY**. If it reads
**LOCAL · ATTENTION**, hover it: it lists the missing tool.

Then:
1. Click **BNB** under *Presets* and pick any entry (or paste a transaction hash).
2. Paste your OpenAI API key (or set `OPENAI_API_KEY` in the environment first and leave the field blank).
3. Click **Analyze transaction**.

A first run on a transaction that was never replayed needs an RPC that can replay it. See [RPC connection](#rpc-connection).

---

## 3. Prerequisites in detail

| Requirement | Why | Check | Install |
|---|---|---|---|
| Python 3.10+ | Runtime (the original badge says 3.8, but current dependency versions need 3.10) | `python3 --version` | python.org / your package manager |
| Foundry `cast` | Replays the transaction to get its call trace | `cast --version` | `curl -L https://foundry.paradigm.xyz \| bash` then `foundryup` |
| `curl` | Fetches explorer pages | `curl --version` | Preinstalled on macOS/Linux; Windows: use WSL |
| `getCode` | Downloads verified contract source | `getCode -v` | Installed by `pip install -r requirements.txt` |
| An LLM | Reads traces and source | | OpenAI key, or a local [Ollama](https://ollama.com) model |
| An RPC that can replay your transaction | See below | | Any archive provider with tracing |

**Windows:** the server starts workers with POSIX process groups, so run it in **WSL2** or Docker, not native Windows.

### RPC connection

`cast run` replays a transaction against the chain state of its block. For anything but very recent transactions
that needs an **archive node**. The built-in public endpoints in `foundry.toml` are non-archive and will fail on
older transactions. Expand **RPC connection** in the console and use one of:

* A complete endpoint: `https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY` (leave *RPC key* empty)
* A template: URL `https://eth-mainnet.g.alchemy.com/v2/{key}` and the key in *RPC key*

Rules: the URL must start with `http://`, `https://`, `ws://` or `wss://`; a key without `{key}` in the URL (or `{key}` without a key) is rejected;
endpoints that resolve to private or local addresses are blocked on the server (see `FAULTSEEKER_ALLOW_PRIVATE_RPC`).
The URL and key are held only by that run's worker process, are not saved in browser storage and are masked in logs.

To change the **server's default** endpoints, edit `[rpc_endpoints]` in `foundry.toml`.

---

## 4. Using the console

### Setup page
| Field | Notes |
|---|---|
| **Transaction hash** | `0x` plus 64 hex characters. The dropdown suggestion list holds recent runs and benchmark exploits. |
| **Presets** | Hover (or tap) **ETH** / **BNB** to pick from the benchmark's verified exploits (101 Ethereum, 13 BNB), newest first. Picking one fills the hash and network. |
| **Network** | See [Supported networks](#5-supported-networks). Beta and partial networks show a notice when selected. zkSync Era is disabled. |
| **Analysis model** | OpenAI models by default. Add Ollama models with `FAULTSEEKER_OLLAMA_MODELS`. |
| **Model API key** | Required unless the server has `OPENAI_API_KEY` (then optional; your key overrides it). Not needed for Ollama. Never stored. |
| **RPC connection** | Optional. See above. |
| **View saved capture** | Opens a recorded reference report. No model runs. |

### While a run is in progress
* The six-step tracker advances **only when the pipeline actually prints that it reached the step**. There are no timers or fake percentages.
* **Current task** and **Recent activity** describe the latest real events. **Technical logs** show the raw (redacted) pipeline output.
* **Cancel run** stops the worker and everything it started (`cast`, `getCode`).
* You can leave the page. The run continues on the server; reopen it from **Recent runs** or the URL (`#run/<id>`).
* Only **one analysis runs at a time** per server (configurable). A second submit shows a notice with a button to open the running one.

### Reading a report
* **Ranked suspicious functions**: the model's ranking, each with the evidence it gave. The first is tagged *Top suspect*.
* **UNRANKED**: shown when the model failed to produce a ranking; candidates are listed without an order and a warning explains why.
* A warning banner appears if model calls failed during the run. Treat such reports as incomplete.
* **Transaction understanding**: the model's narrative of what the transaction did.
* **Download JSON** gives the raw pipeline output.

### Recent runs
Lists stored runs (newest first, last 100 by default). Failed runs show their reason; opening one shows the failure and its logs.

### Saved capture
Shows `captures/capture.json` if you place one there (any report JSON in the normalized shape served by `GET /api/runs/<id>/result`).
Otherwise it shows a **reference built from the benchmark's ground truth**: the known vulnerable function for the BEGO exploit.
It is clearly labelled as not coming from a live run.

---

## 5. Supported networks

| Network | id | Chain ID | Support |
|---|---|---|---|
| Ethereum | `eth` | 1 | **Full** (benchmarked) |
| BNB Smart Chain | `bsc` | 56 | **Full** (benchmarked); source download needs `ETHERSCAN_API_KEY` |
| Polygon PoS | `polygon` | 137 | Beta |
| Arbitrum One | `arbitrum` | 42161 | Beta |
| Optimism | `optimism` | 10 | Beta; source download needs `ETHERSCAN_API_KEY` |
| Base | `base` | 8453 | Beta; source download needs `ETHERSCAN_API_KEY` |
| Avalanche C-Chain | `avalanche` | 43114 | Beta; source download needs `ETHERSCAN_API_KEY` |
| Linea | `linea` | 59144 | Beta |
| Scroll | `scroll` | 534352 | Beta |
| Gnosis (xDai) | `gnosis` | 100 | Beta |
| Celo | `celo` | 42220 | Beta |
| Moonbeam | `moonbeam` | 1284 | Beta |
| Fantom Opera | `fantom` | 250 | **Partial**: replay works, but source download is unavailable, so Stage 2 fails |
| Cronos | `cronos` | 25 | **Partial** (same limitation) |
| Aurora (NEAR EVM) | `aurora` | 1313161554 | **Partial** (same limitation) |
| zkSync Era | `zksync` | 324 | **Not supported**: `cast` cannot replay it and its explorer cannot be scraped |

* **Full**: the networks the paper evaluated.
* **Beta**: wired through replay, explorer lookup and source download, and unit-tested for configuration, but **never run on a real transaction**. Treat results with care.
* **Partial**: `getCode` (Etherscan's V2 API) does not cover the network. A test (`test_getcode_knows_the_chain_ids`) enforces this stays accurate.
* Explorer pages are read by scraping Etherscan-style HTML. Layout differences between explorers may break Stage 1 on beta networks.
* Replay needs an archive RPC **with call tracing** on every network.

---

## 6. Configuration reference

All optional. Set them in your shell, a `.env` file in the project root (loaded by both the server and the pipeline, never overriding real environment variables), or the Render dashboard.

| Variable | Default | Meaning |
|---|---|---|
| `OPENAI_API_KEY` | none | Server-wide key. If set, users need not supply one, **and anyone with the URL can spend it**. |
| `ETHERSCAN_API_KEY` | none | Passed to `getCode`; required for BSC, Base, Optimism, Avalanche source download (paid Etherscan tier). |
| `FAULTSEEKER_OPENAI_MODELS` | `gpt-4o-mini,gpt-4o,gpt-4.1-mini,gpt-4.1` | Models offered. The pipeline sends `temperature=0`, so choose models that accept it. |
| `FAULTSEEKER_DEFAULT_MODEL` | `gpt-4o-mini` | Preselected model. |
| `FAULTSEEKER_OLLAMA_MODELS` | none | Comma-separated Ollama model names to add (also set `OLLAMA_HOST` if not local). |
| `FAULTSEEKER_HTTP_PROXY` | none | Proxy for explorer page fetches (`curl -x`), if the explorer blocks the server. |
| `FAULTSEEKER_DATA_DIR` | `./data` | Where run history is stored. The pipeline's replay/contract cache is `./data/cache`. |
| `FAULTSEEKER_MAX_CONCURRENT` | `1` | Simultaneous analyses. Keep at 1 unless you have isolated the shared `./temp2` and `Implementation/` folders. |
| `FAULTSEEKER_RUN_TIMEOUT` | `3600` | Seconds before a run is stopped. |
| `FAULTSEEKER_MAX_STORED_RUNS` | `100` | Older runs are pruned. |
| `FAULTSEEKER_ALLOW_PRIVATE_RPC` | unset | Set to `1` to allow RPC URLs on private/local addresses (e.g. a local anvil). Never on a public deployment. |
| `FAULTSEEKER_CAPTURE_TX` | BEGO tx | Which benchmark transaction the built-in reference capture uses. |
| `FAULTSEEKER_MAX_LINE_BYTES` | 32 MB | Largest single line of worker output accepted. |
| `FAULTSEEKER_WORKER_MODULE` | `faultseeker.server.worker` | Test hook: lets the suite substitute a stand-in worker. Do not set in production. |
| `PORT` | 8000 (Render: 10000) | Used by the Docker command. |

---

## 7. Running the tests

Nothing needs the internet, a model key or a funded RPC.

### Python suite
```bash
pip install -r requirements-dev.txt   # inside the project's venv
python -m pytest tests -q
```

Current result: **101 passed** with the full requirements and Foundry installed. Without them, tests that need the
real pipeline modules or Foundry **skip** (73 pass, 2 skip) rather than fail.

| File | Covers |
|---|---|
| `test_api.py` | Every endpoint, validation errors, cursors, static files, security headers, "environment not ready" |
| `test_runs.py` | Secret redaction (including server-held keys), one-at-a-time limit, cancel **kills child processes**, timeout, crash, oversized output, failure classification, restart handling, history persistence, pruning |
| `test_security.py` | Hash/key/RPC validation, private-address blocking, redaction of URLs and key forms |
| `test_progress.py` | Progress parsing checked against **the pipeline's actual print statements read from source**, so rewording a print fails a test |
| `test_results.py` | Result normalization including the real failure shapes of the LLM layer |
| `test_chains_presets.py` | All 16 networks, `foundry.toml` aliases, `getCode` chain-ID coverage, presets, and the frontend contract (every id used by JS exists in HTML; no inline styles or unsafe HTML, which the CSP would block) |
| `test_pipeline_patches.py` | Each edit to original modules, plus the **real pipeline** failing cleanly at Stage 1 end to end |
| `test_worker.py` | Worker markers, atomic result file, error reporting |
| `test_cast_integration.py` | **Real Foundry**: starts `anvil`, runs a real transaction, replays it with `cast run`, and parses it with the project's parser (skips if Foundry is missing) |

Run one file or test: `python -m pytest tests/test_runs.py -k cancel -q`.

### Browser-level UI suite
Loads the real `index.html` and `console.js` in jsdom against a real server process (using the stand-in worker):

```bash
cd tests/ui
npm install
PYTHON=$(which python) npm test        # PYTHON must point at the venv's python
```

Current result: **113 checks pass.** It covers the setup form and key rules, presets, field errors, a full live run through
to the report and history, every failure type, unusable model output, the saved capture, reload and bookmarks, busy and
cancel handling, an unreachable server, and that untrusted text is never interpreted as HTML.

### Both at once
```bash
./scripts/run_all_tests.sh
```

### What the tests do **not** prove
No automated test can show that a real model produces a correct analysis, that a given explorer will serve its page to your
server, or that your RPC can replay a given transaction. The stages after replay (trace analysis through ranking) were exercised
only through the stand-in worker. Your first real run is the true end-to-end check. See [Known limitations](#14-known-limitations).

---

## 8. Deploying to Render

### Before you start
* A Render account and the project in a Git repository (GitHub/GitLab).
* Decide on keys: **OpenAI** (yours on the server, or each user's own), and an **Etherscan** key if you need BSC/Base/Optimism/Avalanche source.
* An archive RPC for the networks you will use (users can enter their own in the console).

### Steps
1. Push the project to your repository (the `data/`, `logs/` folders are already git-ignored).
2. In Render choose **New → Blueprint**, select the repository. Render reads `render.yaml` and creates the web service from the `Dockerfile`.
3. When prompted for the `sync: false` variables, set the ones you need:
   * `OPENAI_API_KEY`: optional (see the warning in the table above)
   * `ETHERSCAN_API_KEY`: needed for paid-tier networks
   * `FAULTSEEKER_HTTP_PROXY`: leave empty unless the explorer blocks the server
4. Wait for the first build (it installs the Python dependencies and downloads Foundry; several minutes).
5. Open the service URL. The badge should read **RENDER · READY**.

Manual setup instead of a Blueprint: **New → Web Service → Docker**, health check path `/api/health`, same environment variables.

### Sizing and persistence
* `render.yaml` uses the `standard` plan (2 GB RAM). The pipeline loads pandas/numpy and large traces; 512 MB plans may be killed for memory. This has **not been measured**; check Render's metrics after a real run and adjust.
* **Run history lives in `/app/data`.** Without a disk it is lost on every deploy and restart. To keep it, uncomment the `disk:` block in `render.yaml` (paid plans). The entrypoint fixes the mount's ownership.
* Run **one instance**. Run state lives in the process, so do not scale horizontally.
* The container runs as a non-root user (`app`).

### First-run checklist on Render
1. Badge says **RENDER · READY** (otherwise hover it for the missing tool).
2. Open **View saved capture**: it should render without calling a model.
3. Analyze one **Ethereum or BNB** preset with an archive RPC and a valid key.
4. If it fails, open **Technical logs**; the error banner names the stage. See [Troubleshooting](#12-troubleshooting).
5. Check memory and CPU in Render's metrics during that run.

### Updating
Push to the tracked branch (`autoDeploy: true`). A restart marks any in-flight run as *interrupted*; users simply run it again.

---

## 9. Running with Docker locally

```bash
docker build -t faultseeker .
docker run --rm -p 8000:10000 \
  -e OPENAI_API_KEY=sk-... \
  -v faultseeker-data:/app/data \
  faultseeker
```
Open <http://localhost:8000>. Pin Foundry with `--build-arg FOUNDRY_VERSION=v1.x.y`.

---

## 10. API reference

All responses are JSON and `Cache-Control: no-store`. Errors look like `{"error": {"code", "message", "field"?}}`.

| Method & path | Purpose |
|---|---|
| `GET /api/health` | Liveness check (used by Render) |
| `GET /api/config` | Networks, models, presets, recent hashes, environment report, active run |
| `POST /api/runs` | Start a run. Body: `txn_hash`, `chain`, `mode` (model id), `model_key`, `rpc_url`, `rpc_key`. `201` with `{id, run}` |
| `GET /api/runs` | History, newest first |
| `GET /api/runs/{id}?e=&l=` | Run state, new events after cursor `e`, new log lines after cursor `l` |
| `POST /api/runs/{id}/cancel` | Cancel a running run |
| `GET /api/runs/{id}/result` | Normalized report. `?download=raw` for the pipeline's raw JSON as a file |
| `GET /api/capture` | The saved capture |

Error codes from `POST /api/runs`: `invalid_input` (400, with `field`), `model_key_rejected` (400), `busy` (409, with `active_run`),
`environment_not_ready` (503, with `issues`), `too_large` (413).
Run failure codes (in `run.error.code`): `rpc_failed`, `explorer_unavailable`, `no_forensics`, `model_key_rejected`, `model_quota`,
`timeout`, `interrupted`, `worker_crashed`, `pipeline_error`, `result_missing`.

Run states: `running`, `completed`, `failed`, `cancelled`, `interrupted`.

---

## 11. Security model

* **Keys**: model and RPC keys travel only in the POST body, are handed to the worker through its process environment (not arguments or disk),
  and are masked in every log line before storage. Server-held keys are masked too. Browser storage is never used.
* **Isolation**: each run is its own process group; cancel and timeout kill the whole group.
* **SSRF guard**: custom RPC hosts are resolved and rejected if private, loopback, link-local or reserved. (DNS can change between the check and use; run the service where internal addresses are not reachable if this matters.)
* **Rendering**: all dynamic text uses `textContent`; a strict Content-Security-Policy (`script-src 'self'; style-src 'self'`, no framing) is sent.
* **Input limits**: bodies over 16 KB are rejected; hashes, models, networks and keys are validated server side; run IDs are validated before any file access.
* **No authentication and no rate limiting.** Anyone with the URL can start analyses and see history (which contains public transaction hashes and reports, never keys).
  If you set a server `OPENAI_API_KEY`, put the service behind access control (for example Render's private networking, a reverse proxy with auth, or Cloudflare Access).

---

## 12. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Badge **ATTENTION** / "missing tools" | `cast`, `getCode`, `curl` or `foundry.toml` not found | Install the tool; check `PATH` |
| **Transaction replay failed** with DNS/connect errors | RPC unreachable | Check the URL/key; server needs outbound internet |
| Replay fails with "missing trie node", "state not available" or similar | Non-archive RPC | Use an archive RPC with tracing |
| **Explorer page did not report a successful transaction** | Explorer blocked the request, the hash is on another network, or the transaction reverted | Check the network selector; try `FAULTSEEKER_HTTP_PROXY`; open the explorer URL yourself |
| **The model provider rejected the API key** | Wrong key or wrong provider | Re-enter it (use *Show* to check). The run stops immediately |
| **no remaining quota** | OpenAI billing | Add credit or change key |
| Report shows **UNRANKED** or a warning about failed model requests | Rate limits or model errors during the run | Re-run; try another model; check logs for `openai.` lines |
| Function analysis fails on BSC/Base/Optimism/Avalanche | Paid-tier explorer API | Set `ETHERSCAN_API_KEY` |
| Function analysis fails on Fantom/Cronos/Aurora | `getCode` does not support them | Known limitation |
| "Another analysis is already running" | One-at-a-time limit | Open or cancel it from the notice |
| Run marked **interrupted** | Server restarted mid-run | Run again |
| **stopped unexpectedly (exit code N)** | Worker crashed (often out of memory) | Check **Technical logs**; raise the instance size |
| Page loads but is unstyled / blank | Static files not served | Confirm `/assets/console.css` returns 200; use the server, not `file://` |
| Windows: analysis fails to start | POSIX process groups | Use WSL2 or Docker |
| `getCode` writes `Implementation/` and `logs/` into the project | Original tool behaviour | Harmless; both are git-ignored or safe to delete |

For anything else, the quickest diagnostic is the **Technical logs** panel and `GET /api/runs/<id>`.

---

## 13. Project layout

```
FaultSeeker-main/
├── faultseeker/
│   ├── chains.py              network registry (ids, chain IDs, explorers, support level)
│   ├── core/ forensics/ data_collection/ function_analysis/ utils/   original pipeline
│   └── server/
│       ├── app.py             FastAPI routes, security headers, static files
│       ├── runs.py            run manager: worker subprocess, events, logs, persistence
│       ├── worker.py          subprocess entry point that runs the pipeline
│       ├── progress.py        pipeline output -> stage progress and failure signals
│       ├── results.py         raw output -> report shape; reference capture
│       ├── presets.py         benchmark exploit presets
│       ├── security.py        validation, SSRF guard, redaction
│       └── settings.py        environment configuration
├── web/                       index.html, assets/console.css, assets/console.js
├── tests/                     pytest suite; ui/ holds the browser-level suite
├── benchmark/                 original benchmark and ground truth
├── foundry.toml               RPC aliases used by `cast`
├── Dockerfile  docker-entrypoint.sh  render.yaml  .dockerignore
└── GUIDE.md
```

Runtime data (git-ignored): `data/runs/<id>/` holds `meta.json`, `events.jsonl`, `logs.txt`, `result.raw.json`, `result.json`; `data/cache/` is the pipeline's cache.

---

## 14. Known limitations

* **Stages after replay have not run on a real model here.** The suite proves the plumbing, parsing and failure handling; it cannot prove analysis quality.
* **Explorer scraping is fragile.** Stage 1 reads Etherscan-family HTML. If a host (including Render's network) is challenged or blocked, Stage 1 fails with a clear message. The durable fix is replacing the scraper with direct RPC reads (receipts and token transfer logs). That is a larger change and was not made.
* **Beta networks are unverified**, **partial** networks cannot complete Stage 2, and **zkSync Era** is not supported.
* **One run at a time**: the original code writes to shared relative folders (`temp2`, `Implementation`).
* **No authentication or rate limiting** (see [Security model](#11-security-model)).
* **Memory needs are unmeasured.** Check them on your first real run.
* **Visual layout** was verified structurally in a simulated browser, not by eye on real devices. Look at it on your phone and desktop.
* `Windows` is supported through WSL2 or Docker only.

---

## 15. Extending

* **Add a network**: add an entry to `faultseeker/chains.py` and an alias with the same id to `[rpc_endpoints]` in `foundry.toml`.
  `pytest` then checks the alias exists and whether `getCode` knows the chain ID.
* **Add models**: set `FAULTSEEKER_OPENAI_MODELS` / `FAULTSEEKER_OLLAMA_MODELS`. Names starting with `gpt` use OpenAI; others use Ollama (the pipeline's `build_agent` rule).
* **Change the look**: edit `web/assets/console.css` (colours are variables at the top). Keep styles in the stylesheet; inline styles are blocked by the CSP.
* **Change progress wording**: `faultseeker/server/progress.py`. If you reword a `print` in the pipeline, update the matching rule; `test_every_pipeline_milestone_is_mapped` fails until you do.
* **Ship a real saved capture**: save a completed run's `GET /api/runs/<id>/result` JSON as `captures/capture.json`.
