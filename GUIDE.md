# FaultSeeker++ Web Console: Complete Guide

This guide covers everything added around the original FaultSeeker research code: the web console and its API, the model
provider registry, access protection, reproducible Foundry trace handling, the tests, and deployment to Render's free plan.
The original engine and the `faultseeker` command keep their behaviour, with one deliberate exception listed in
[section 1](#1-what-changed-and-what-did-not).

**Honest status.** Everything here was tested **offline** with controlled test doubles and local tools. **No real paid API was
called, and no real Ethereum or BSC analysis has been run or verified.** See [section 11](#11-tests) for exactly what was and
was not exercised.

**Contents**
1. [What changed (and what did not)](#1-what-changed-and-what-did-not)
2. [Quick start (local)](#2-quick-start-local)
3. [Prerequisites](#3-prerequisites)
4. [Model providers](#4-model-providers)
5. [Access protection](#5-access-protection)
6. [Using the console](#6-using-the-console)
7. [Supported networks](#7-supported-networks)
8. [Foundry versions and trace handling](#8-foundry-versions-and-trace-handling)
9. [Configuration reference](#9-configuration-reference)
10. [API reference](#10-api-reference)
11. [Tests](#11-tests)
12. [Deploying to Render (free plan)](#12-deploying-to-render-free-plan)
13. [Running with Docker locally](#13-running-with-docker-locally)
14. [Security model](#14-security-model)
15. [Troubleshooting](#15-troubleshooting)
16. [Project layout](#16-project-layout)
17. [Known limitations](#17-known-limitations)
18. [Extending](#18-extending)

---

## 1. What changed (and what did not)

**New:**

| Path | Purpose |
|---|---|
| `web/` | The console (`index.html` unchanged, plus `assets/console.css`, `assets/console.js`) and the sign-in page `web/login/` |
| `faultseeker/server/` | FastAPI service: isolated analysis workers, progress, history, key validation (`keycheck.py`), access control (`auth.py`) |
| `faultseeker/providers.py`, `config/models.json` | The model provider registry |
| `faultseeker/chains.py` | One registry of networks (ids, chain IDs, explorers, support level) |
| `faultseeker/utils/selectors.py`, `known_selectors.json` | Function identity independent of how `cast` prints calls |
| `tests/`, `scripts/` | Python and browser test suites; fixture-capture and selector-generation scripts |
| `Dockerfile`, `docker-entrypoint.sh`, `.dockerignore`, `render.yaml`, `.env.example`, `.python-version` | Deployment |

**Edits to original files** (each covered by tests):

| File | Change |
|---|---|
| `utils/agent.py` | `GPTAgent` now talks to any OpenAI-compatible endpoint described by the registry (explicit base URL, key variable and parameters; automatic SDK retries off). `OllmaAgent` accepts an explicit host. |
| `utils/utils.py` | `build_agent` resolves the model through the registry. **It no longer guesses the provider from a `gpt` prefix.** `is_function_hash` is anchored to a bare 8-hex selector. |
| `data_collection/txn_replayer.py` | Runs `cast` in a minimal environment with an empty temporary `HOME`; prints the cast version; honours `FAULTSEEKER_RPC_URL`; never prints the RPC URL; prints cast's error output. |
| `data_collection/trace_parser.py` | Normalises each call to one identity (name + selector) whether cast printed a selector or a decoded name. Nodes gain a `selector` field (old cached traces still load). |
| `data_collection/txn_info_collector.py` | **Reads the transaction over RPC** (status, block, from/to, input, logs, token transfers) and no longer fetches any explorer page by default. The old page scrape is kept behind `FAULTSEEKER_EXPLORER_FALLBACK=1` ([section 3](#rpc-first-transaction-collection)). |
| `data_collection/rpc_client.py`, `rpc_collector.py` (new) | Standard-library JSON-RPC client (endpoint resolution, `ws`→`http`, retries, never prints the URL) and the record builder. |
| `data_collection/contract_downloader.py`, `source_fetcher.py` (new) | Source comes from **Sourcify (free, no key)**; `getCode --chainid` with the optional `ETHERSCAN_API_KEY` is the other source. Neither found → a clear message, no crash. |
| `core/pipeline.py` | A failed Stage 1 is reported instead of crashing with `cannot unpack NoneType`. |
| `foundry.toml`, `requirements.txt` | RPC aliases for the extra networks; `fastapi`, `uvicorn`. |

**The one deliberate CLI change.** `faultseeker -forensics_model llama3` used to be sent to Ollama because the name did not start
with `gpt`. That guess is gone. Use a registry id (`gpt-4o-mini`, `codex-proxy`, `mercury`, ...) or the explicit `ollama:<name>`
form. An unknown name now stops with a message listing the known models. All flags and defaults are otherwise unchanged
(`tests/test_cli.py`).

---

## 2. Quick start (local)

Needs Python 3.10+ (3.11 is what Render runs) and Foundry's `cast`. `curl` is needed only for the optional explorer fallback.

```bash
cd FaultSeeker-main
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt && pip install -e .     # editable: the registry, web files and benchmark are read from the repository
cp .env.example .env            # then fill in only what you need; never commit .env
uvicorn faultseeker.server.app:app --port 8000
```

Open <http://localhost:8000>. The badge reads **LOCAL · READY**; if it says **ATTENTION**, hover it for the missing tool.
For private local use the access code can stay empty. A first run needs an RPC that can replay your transaction
(see [RPC connection](#rpc-connection)).

---

## 3. Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Python 3.10+ (3.11 recommended) | Runtime | `python3 --version` |
| Foundry `cast` | Replays the transaction. **Tested: 1.4.4, 1.5.1, 1.9.0** (image pins 1.9.0; see [section 8](#8-foundry-versions-and-trace-handling)) | `cast --version` |
| `curl` | Optional: only the explorer fallback uses it | `curl --version` |
| `getCode` | Downloads verified source from the Etherscan API (installed by `requirements.txt`); Sourcify is tried too and needs no key | `getCode -v` |
| A model | OpenAI, an OpenAI-compatible proxy, or Ollama ([section 4](#4-model-providers)) | |
| An archive RPC with call tracing | Replaying anything but very recent transactions | |

Windows: run the server in **WSL2** or Docker (workers use POSIX process groups).

### RPC connection
Expand **RPC connection** in the console: paste a complete endpoint, or put `{key}` in the URL and the key in *RPC key*. Schemes
`http(s)`/`ws(s)` only; private/local addresses are blocked unless `FAULTSEEKER_ALLOW_PRIVATE_RPC=1`. The URL and key exist only in
that run's worker environment and are masked in logs. The server's default endpoints are in `foundry.toml` and are non-archive.

---

### RPC-first transaction collection
Stage 1 gets everything from the RPC endpoint of the run (`FAULTSEEKER_RPC_URL`, set by the console for a custom endpoint, otherwise the
`foundry.toml` alias for the network). `ws://` and `wss://` endpoints are used over HTTP(S) (an Infura-style `/ws/` path segment is dropped).
Calls: `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockByNumber`, `eth_blockNumber`, and `eth_call` for token
symbol/decimals. The record keeps the keys the explorer collector produced (`status`, `block_number`, `address_info`, `transaction_date`,
`token_transfer`) and adds `input_data`, `method_selector`, `value_wei`, `logs`, `gas_consumption`. The endpoint URL is never printed or put in an
error. Failures print `RPC collection failed (<kind>): …` and surface as `rpc_failed`, `tx_not_found` or `tx_not_successful`.
Set `FAULTSEEKER_EXPLORER_FALLBACK=1` to also try the explorer page after a transport/lookup failure (never after a revert).

## 4. Model providers

### One source of truth
`config/models.json` (or the file named by `FAULTSEEKER_MODELS_FILE`) declares **providers** and **models**. The server, the console
(through `/api/config`) and the pipeline agents all read it. It contains **no secrets and no invented endpoints**: base URLs, exact
model IDs and API keys are read from the environment variables the file names.

```json
"providers": {
  "codex_proxy": {"label": "Codex proxy", "type": "openai_compatible",
                  "base_url_env": "CODEX_PROXY_BASE_URL", "api_key_env": "CODEX_PROXY_API_KEY", "key_validation": "models_list"}
},
"models": [
  {"id": "codex-proxy", "label": "Codex proxy", "provider": "codex_proxy", "model_env": "CODEX_PROXY_MODEL",
   "params": {"temperature": {"env": "CODEX_PROXY_TEMPERATURE", "type": "float", "when_unset": "omit"}}}
]
```

* **Every model names its provider explicitly.** Nothing is inferred from a model-name prefix: a model called `gpt-something` is not
  OpenAI unless the registry says so, and a model that is not `gpt-*` is not Ollama.
* **Shipped entries:** direct OpenAI (`gpt-4o-mini`, `gpt-4o`, `gpt-4.1-mini`, `gpt-4.1`), `codex-proxy`, `mercury`, and Ollama.
* **A model is offered only when fully configured.** Missing `CODEX_PROXY_BASE_URL` or `CODEX_PROXY_MODEL` hides it from the console;
  authenticated admins can see why in `unavailable_models` from `/api/config` (variable *names* only, never values).
* **`FAULTSEEKER_ENABLED_MODELS`** (comma-separated ids) restricts what is offered; unknown ids stop the server from starting.
  **`FAULTSEEKER_DEFAULT_MODEL`** picks the preselected one.
* **Ollama:** set `FAULTSEEKER_OLLAMA_MODELS=name1,name2` (ids become `ollama:name1`) and `OLLAMA_HOST` if not local.
  The CLI and API also accept an ad-hoc `ollama:<name>`.
* Provider types: `openai_compatible` (any `/v1/chat/completions` endpoint) and `ollama`.

### Setting up your Codex proxy and Inception Mercury
Set these in `.env` or the Render dashboard. The values come from **your** accounts; this repository supplies none of them.

| Variable | Meaning |
|---|---|
| `CODEX_PROXY_BASE_URL` | Your proxy's OpenAI-compatible base URL (ending in `/v1`) |
| `CODEX_PROXY_MODEL` | The exact model ID your proxy expects (case preserved) |
| `CODEX_PROXY_API_KEY` | Optional server-held key (see [section 5](#5-access-protection) first) |
| `MERCURY_BASE_URL`, `MERCURY_MODEL`, `MERCURY_API_KEY` | The same three for Inception Mercury |

### Request parameters are explicit
Per model, `params` lists what is sent. Allowed names: `temperature`, `top_p`, `max_tokens`, `max_completion_tokens`,
`reasoning_effort`, `seed`; anything else is rejected when the registry loads.

* `temperature: "pass"` sends the value the pipeline asks for (0); `"omit"` never sends one; a number sends exactly that;
  `{"env": ..., "when_unset": "omit"}` reads it from the environment and sends nothing when unset.
* Other parameters are sent verbatim. **Nothing is silently dropped or changed**, and **a failed call is made once**: the
  OpenAI client's automatic retries are disabled (`max_retries` 0 per provider unless you raise it) and the agent never re-sends.
* If a provider rejects a parameter (for example a model that does not accept `temperature`), the run **stops with
  `provider_parameter_rejected`** and tells the operator to adjust `params`, rather than working around it.

### Keys and isolation
* A user may type a key for the selected model, or the server may hold one in the variable the registry names for that provider.
* A user's key replaces the server key for **that provider only**.
* Each analysis runs in its own process. Its environment contains **only the selected provider's key**; every other provider's key,
  the access code and the session secret are removed, and `.env` is not reloaded inside the worker.
* Keys, RPC URLs, the access code, private provider URLs and the Etherscan key are masked in logs, error messages, stored run
  metadata and every API response. The browser never receives endpoints or exact model IDs.

### Key validation
Before a run starts the key is checked **against the selected provider** (`GET <base_url>/models` with that provider's own key,
redirects not followed). Three outcomes, never conflated:

| Outcome | Meaning | Result |
|---|---|---|
| **valid** | HTTP 200 | Run starts (`key_check: "valid"`) |
| **invalid** | HTTP 401 | `400 model_key_rejected` under the key field. If the key was the server's: `503 server_key_rejected` ("tell the operator") |
| **unavailable** | timeout, connection error, 5xx, 429, 403, 404/405, redirect, anything unexpected | `503 key_validation_unavailable`. **Nothing starts: an outage never counts as a valid key.** |

A provider can opt out with `"key_validation": "none"` (for a proxy with no `/models`): the key is then used unchecked, the run is
labelled `key_check: "not_supported"`, and a wrong key fails fast on the first model call. If your proxy answers `/models` with 404,
the message tells you to set this.

---

## 5. Access protection

Set **`FAULTSEEKER_ACCESS_CODE`** (at least 12 characters, chosen by you, **no default exists anywhere**). When set:

* Everything requires a session **except** `/api/health`, `/login` (and its two assets), `/auth/login`, `/auth/logout`,
  `/auth/session` and `/favicon.ico`. Pages, run submission, status, results, downloads, the console's own code and every other API
  answer `401` (or redirect `/` to `/login`) without a session. A test enumerates every route to prove this.
* **Login** compares the code in constant time (SHA-256 digests through `hmac.compare_digest`). A session is a random 256-bit token,
  stored server-side only as a hash, in an `HttpOnly`, `SameSite=Strict` cookie (`Secure` over HTTPS and always in public mode),
  valid for `FAULTSEEKER_SESSION_HOURS` (default 12).
* **Rate limiting:** 5 failed attempts per client address per 15 minutes, plus a global ceiling (`429` with `Retry-After`);
  even the right code is refused while locked out.
* **Logout** (`Sign out` in the console) revokes the session server-side; a replayed cookie stops working.
* **Cross-site POSTs** are refused (`Origin` must match the host). The sign-in page uses only external scripts and styles and obeys the
  existing strict CSP (no inline scripts).
* Sessions live in memory: a restart signs everyone out.

**Startup safety.** The server refuses to start when:
* the access code is shorter than 12 characters, or
* a server-held model key is set (any provider's key variable) **and** there is no access code **and** the server is public
  (`RENDER` is set, or `FAULTSEEKER_PUBLIC=1`, which the Docker image sets). The message names the fix and never prints a key.
  `FAULTSEEKER_ALLOW_UNSAFE_PUBLIC=1` is the explicit override.

A public server with no server-held keys and no access code is allowed (users bring their own keys) but logs a warning; an unlisted
URL is not protection. For anything you share, set the code.

---

## 6. Using the console

* **Setup:** hash, presets (benchmark exploits), network, model, key (the hint names the selected provider), optional RPC.
* **Run view:** the tracker advances only on real pipeline output; logs are redacted; **Cancel** kills the worker and its children.
  One analysis runs at a time (a second submit offers to open the running one).
* **Failures** are explained with a code, message and hint: `rpc_failed`, `tx_not_found`, `tx_not_successful`, `explorer_unavailable`, `model_key_rejected`, `model_quota`,
  `provider_forbidden`, `model_not_found`, `provider_parameter_rejected`, `provider_unreachable` (3 connection errors; no retries),
  `provider_not_configured`, `timeout`, `interrupted`, `worker_crashed`, `no_forensics`, `pipeline_error`, `result_missing`.
* **Reports:** ranked suspicious functions with evidence; `UNRANKED` and warnings appear when the model's output was unusable.
* **Recent runs**, **Download JSON**, and a **saved capture** (`captures/capture.json`, or a labelled benchmark reference).
* **Sign out** appears only when access protection is on.

---

## 7. Supported networks

| Network | id | Chain ID | Support |
|---|---|---|---|
| Ethereum | `eth` | 1 | **Full** (benchmarked in the paper) |
| BNB Smart Chain | `bsc` | 56 | **Full**; source from Sourcify, or `ETHERSCAN_API_KEY` for contracts Sourcify lacks |
| Polygon PoS, Arbitrum One, Linea, Scroll, Gnosis, Celo, Moonbeam | `polygon` `arbitrum` `linea` `scroll` `gnosis` `celo` `moonbeam` | various | Beta |
| Optimism, Base, Avalanche C-Chain | `optimism` `base` `avalanche` | various | Beta; source from Sourcify, or `ETHERSCAN_API_KEY` |
| Fantom, Cronos, Aurora | `fantom` `cronos` `aurora` | 250 / 25 / 1313161554 | **Partial**: replay works; `getCode` cannot download source, so Stage 2 fails |
| zkSync Era | `zksync` | 324 | **Not supported** (`cast` cannot replay it) |

Beta means wired through every module and unit-tested for configuration, **never run on a real transaction**. Replay needs an archive
RPC with call tracing on every network.

---

## 8. Foundry versions and trace handling

### The problem (reproduced with real binaries)
`cast run` prints a call either with the raw selector (`2fbebd38(…)`) or decoded (`foo(7)`), depending on its signature cache and
version. Captured from real output (anvil, no network); the same call, "cold" = empty cache, "warm" = a cache that knows it:

| cast | cold cache | warm cache | warm cache + `FOUNDRY_OFFLINE=true` |
|---|---|---|---|
| 1.4.4, 1.5.1 | `a9059cbb(…)`, `2fbebd38(…)` | `transfer(…)`, `foo(7)` | still decoded |
| 1.9.0 | **`transfer(…)` decoded even when cold**, `2fbebd38(…)` | decoded | still decoded |

This matters because the analyzer's rules key off names (`flashLoan`, `uniswapV2Call`, ...) and treat a bare selector as an "unresolved
function". So the same transaction used to classify differently depending on cache, version and network.

**Pinning a version alone does not fix this** (1.9.0 itself decodes some selectors on its own, and `FOUNDRY_OFFLINE` does not stop
decoding from a local cache). The fix has two parts:

1. **Isolation (`txn_replayer.py`).** `cast` runs with an empty temporary `HOME` (no signature cache), no `ETHERSCAN_*`, no `FOUNDRY_*`,
   no provider keys, and `FOUNDRY_OFFLINE=true` (set `FAULTSEEKER_CAST_OFFLINE=0` to allow online lookups). The output is then a
   function of the version only, and the version is written to the run log (`cast version: 1.9.0`).
2. **Identity (`utils/selectors.py`).** The parser maps both formats onto one identity using a bundled table of well-known signatures
   (40 entries: ERC-20/721, ERC-3156, Aave, Balancer, Uniswap, DODO, dYdX, Morpho; every selector re-derived by keccak and `cast sig` in
   tests). A raw `5cffe9de` and a decoded `flashLoan(…)` both become function `flashLoan`, selector `5cffe9de`.

### What is and is not equivalent
* **Equivalent** (tested across 1.4.4, 1.5.1, 1.9.0 × cold/warm, including a nested two-level call tree): every function in the table,
  including identical `flashloan` / `callback` / `name_in_hash` buckets from the analyzer.
* **Not equivalent, by nature:** a function in neither the bundled table nor cast's own database cannot be named from `2fbebd38`
  alone, so it remains a "hashed name" (the original meaning of that bucket). Add its signature with
  `FAULTSEEKER_SELECTOR_TABLE=/path/extra.json` (`{"2fbebd38": "foo(uint256)"}`) and it becomes equivalent too. A test documents both cases.
* The "hashed name" bucket now means *unknown to cast's built-in set and to the bundled table*, which is stable across network
  conditions, rather than *unknown to whatever online lookup happened to succeed*.
* Online signature lookups could not be tested here (no network). `FOUNDRY_OFFLINE=true` is applied on the expectation that it
  disables them; if a real run on your network ever shows decoded names for unknown selectors, the identity layer still keeps known ones
  consistent. Please check your first real trace's log line.

### The pin
The Docker image installs **Foundry v1.9.0**, verified against a SHA-256 checksum at build time (a wrong checksum fails the build).
To change it, override **both** build args and rerun the tests against the new version:
```bash
docker build --build-arg FOUNDRY_VERSION=v1.x.y --build-arg FOUNDRY_SHA256=<sha256 of foundry_v1.x.y_linux_amd64.tar.gz> .
FAULTSEEKER_TEST_FOUNDRY_DIRS=/path/foundry-1.x.y python -m pytest tests/test_cast_integration.py
python scripts/capture_cast_fixtures.py /path/foundry-1.4.4 /path/foundry-1.x.y   # refresh tests/fixtures/cast_traces.json
```
`/api/config` reports the running `cast` version and a note when it is not one of the tested versions.

---

## 9. Configuration reference

All optional unless stated; `.env.example` lists them with placeholders only. A `.env` file is read by the server and by CLI runs and
never overrides real environment variables.

| Variable | Default | Meaning |
|---|---|---|
| `FAULTSEEKER_ACCESS_CODE` | none | **Set before hosting publicly** (12+ chars; no default) |
| `FAULTSEEKER_SESSION_HOURS` | 12 | Session lifetime |
| `FAULTSEEKER_LOGIN_MAX_FAILURES` / `_WINDOW_SECONDS` / `FAULTSEEKER_LOGIN_MAX_FAILURES_GLOBAL` | 5 / 900 / 50 | Login rate limits |
| `FAULTSEEKER_PUBLIC` | unset (Render and Docker set it) | Treat the server as publicly reachable |
| `FAULTSEEKER_ALLOW_UNSAFE_PUBLIC` | unset | Explicitly accept a public server with a server-held key and no access code |
| `FAULTSEEKER_MODELS_FILE` | `config/models.json` | Provider/model registry |
| `FAULTSEEKER_ENABLED_MODELS`, `FAULTSEEKER_DEFAULT_MODEL` | all configured, first | Offered models and default |
| `OPENAI_API_KEY`, `CODEX_PROXY_*`, `MERCURY_*` | none | See [section 4](#4-model-providers) |
| `FAULTSEEKER_OLLAMA_MODELS`, `OLLAMA_HOST` | none | Ollama models and address |
| `ETHERSCAN_API_KEY` | none | Optional. Widens source coverage beyond Sourcify (tried first when set) |
| `FAULTSEEKER_EXPLORER_FALLBACK` | off | `1` lets Stage 1 try the explorer page when RPC reading fails (never when the transaction reverted) |
| `FAULTSEEKER_HTTP_PROXY` | none | Proxy for the explorer fallback only |
| `FAULTSEEKER_SOURCIFY_URL` | `https://sourcify.dev/server` | Sourcify server (self-hosted mirror, tests) |
| `FAULTSEEKER_RPC_RETRIES` | 2 | Retries after the first RPC attempt (0 = single attempt) |
| `FAULTSEEKER_CAST_OFFLINE` | 1 | `0` lets cast do online signature lookups |
| `FAULTSEEKER_SELECTOR_TABLE` | none | Extra `{"selector": "signature"}` JSON |
| `FAULTSEEKER_DATA_DIR` | `./data` | Run history (the pipeline cache is `./data/cache`) |
| `FAULTSEEKER_RUN_TIMEOUT`, `FAULTSEEKER_MAX_STORED_RUNS`, `FAULTSEEKER_MAX_LINE_BYTES` | 3600, 100, 32 MB | Limits |
| `FAULTSEEKER_ALLOW_PRIVATE_RPC` | unset | Allow local/private RPC URLs (development only) |
| `FAULTSEEKER_CAPTURE_TX` | BEGO tx | Benchmark transaction used by the reference capture |
| `FAULTSEEKER_WORKER_MODULE`, `FAULTSEEKER_ISOLATED_RUN`, `FAULTSEEKER_TEST_FOUNDRY_DIRS` | | Test/worker internals; do not set in production |

Concurrency is fixed at **one analysis at a time** (the pipeline writes to shared `temp2/` and `Implementation/`).

---

## 10. API reference

JSON, `Cache-Control: no-store`; errors are `{"error": {"code", "message", "field"?}}`. With access protection on, everything except the
public paths listed in [section 5](#5-access-protection) needs a session.

| Method & path | Purpose |
|---|---|
| `GET /api/health` | Liveness (public) |
| `GET /auth/session`, `POST /auth/login`, `POST /auth/logout`, `GET /login` | Access control (public) |
| `GET /api/config` | Networks, models (no endpoints or IDs), presets, environment report, auth state |
| `POST /api/runs` | Start: `txn_hash`, `chain`, `mode` (model id), `model_key`, `rpc_url`, `rpc_key` |
| `GET /api/runs`, `GET /api/runs/{id}?e=&l=` | History; run state with event and log cursors |
| `POST /api/runs/{id}/cancel` | Cancel |
| `GET /api/runs/{id}/result[?download=raw]` | Report |
| `GET /api/capture` | Saved capture |

`POST /api/runs` errors: `invalid_input` 400 (with `field`), `model_key_rejected` 400, `key_validation_unavailable` 503,
`server_key_rejected` 503, `busy` 409, `environment_not_ready` 503, `bad_origin` 403, `auth_required` 401, `too_large` 413.

---

## 11. Tests

Nothing needs the internet, a real key or a funded RPC. **No real paid API is contacted by any test.**

### How to run
```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests -q                                   # Python suite
FAULTSEEKER_TEST_FOUNDRY_DIRS=/f/1.4.4:/f/1.5.1:/f/1.9.0 python -m pytest tests -q   # run the real-Foundry tests on several versions
./scripts/run_all_tests.sh                                  # Python suite, then the browser suite (cd tests/ui && npm install first run)
```

### Results of the final verification (fresh unzip of the delivered build)

| Run | Conditions | Result |
|---|---|---|
| 1 | Python 3.12.3, full requirements (incl. `getSourceCode`), real Foundry **1.4.4 + 1.5.1 + 1.9.0** (1.9.0 tarball checksum matches the Dockerfile pin) | **261 passed, 0 failed, 0 skipped** |
| 2 | Python 3.12.3, full requirements, **no Foundry on PATH** | 248 passed, 0 failed, 5 skipped (4 Foundry integration + 1 `cast sig` oracle) |
| 3 | Python 3.12.3, **minimal packages** (fastapi, uvicorn, httpx, pytest), no Foundry | 154 passed, 0 failed, 12 skipped (each names its missing dependency), 1 third-party deprecation warning |
| 4 | Browser suite: Node v22, jsdom 31, server on Python 3.12.3, local fake providers | **148 checks passed, 0 failed** |

**Not re-run for this revision:** Python 3.11 (Render's version) was not available in the build environment, so the earlier Python 3.11
runs were not repeated; the code uses only the standard library plus packages already required, but that is not a test result.
New in this revision: `test_rpc_collection.py` (14 tests) and a local fake JSON-RPC node/Sourcify (`tests/fake_rpc.py`).
The key proof is `test_collection_works_with_explorers_blocked_and_never_touches_them`: a `curl` stand-in that answers like Cloudflare and
records every call is on PATH, collection succeeds for `eth` and `bsc` from the fake node, and the `curl` log stays empty.
`test_real_worker_collects_over_rpc_when_explorers_are_blocked` shows the same through the real worker and pipeline.

Key package versions are whatever pip resolved on the build date; they were not pinned for this run.

### What kind of test each is
* **Real tools, local only:** `test_cast_integration.py` starts a local `anvil` chain and runs real `cast` (1.4.4, 1.5.1, 1.9.0) on real
  transactions including a hand-assembled nested proxy contract; `test_pipeline_patches.py` runs the real worker and real pipeline
  modules against failing stand-in `cast`/`curl`.
* **Recorded real output, offline fixtures:** `tests/fixtures/cast_traces.json` is genuine `cast run` output (7 calls × cold/warm × 3
  versions) used by `test_trace_formats.py` and `test_selectors.py`.
* **Mocked / test doubles:** key validation uses `httpx.MockTransport` (no sockets) or `tests/fake_provider.py`, an OpenAI-compatible
  server on `127.0.0.1`; runs use `tests/fake_worker.py`, a stand-in for the pipeline that prints the pipeline's real progress lines and
  reports which secrets reached it; `cast`, `curl` and `getCode` are stand-in shell scripts where noted.

### Coverage by file
| File | Covers |
|---|---|
| `test_providers.py` | Registry validation; **no prefix guessing**; per-provider routing and key isolation through the real agent against local fake servers; parameter policies; **one call per query, no retries, no silent changes** |
| `test_keycheck.py` | valid / invalid / **unavailable (never valid)**; redirects not followed; each provider's key only to its own URL; server-held vs user key; `none` validation; unconfigured models hidden; endpoints not sent to the browser |
| `test_secret_isolation.py` | The worker receives only the selected provider's key (SHA-256 report), no access code, no other provider key; **no secret appears in any stored file or API response**, including failure messages |
| `test_access.py` | Constant-time compare; sessions, expiry, revocation; rate limiting; **every route enumerated** (only the allowlist is public); cookie flags; CSRF; CSP; **startup refusal** and its overrides; no default password in any shipped file |
| `test_selectors.py`, `test_trace_formats.py` | Every selector re-derived by keccak and `cast sig`; identical identity and analyzer classification across 3 versions × cold/warm (incl. nested); a sensitivity test showing the formats diverge without the identity layer; the documented residual for unknown functions |
| `test_cast_integration.py` | Real Foundry: isolated replay ignores a polluted `HOME`, direct cast does not; deterministic output; version logged; 1.9.0 decodes `transfer` while 1.4.4/1.5.1 do not, and the parsed identity is the same |
| `test_rpc_collection.py` | Collection over RPC with explorers blocked, token-transfer shape and fund-flow arithmetic, ws→http, retries, reverted / pending / unknown hash, no URL in errors, the flagged explorer fallback, Sourcify and `getCode` source paths, real worker end to end |
| `test_pipeline_patches.py` | Replayer environment isolation (no keys, empty HOME, offline flag), explorer/`getCode` changes, Stage 1 failure, real worker with registry models |
| `test_runs.py`, `test_api.py`, `test_security.py`, `test_progress.py`, `test_results.py`, `test_chains_presets.py`, `test_worker.py`, `test_cli.py` | Run lifecycle, failure classification (including every provider failure), API behaviour, validation and redaction, progress parsing against the pipeline's printed lines, result normalization, networks and frontend contract, worker protocol, the original CLI |
| `tests/ui/ui.test.mjs` | Console behaviour in jsdom: setup, networks, presets, provider-aware key hints, invalid / **unreachable** / outage key checks, full run to report, every failure type, capture, routing, busy/cancel, **access protection with a cookie jar** (sign-in, wrong code, sign-out, expired session, rate-limit message), unreachable server, untrusted text never interpreted as HTML |

### What the tests do **not** prove
* **No real Ethereum or BSC analysis was run or verified.** No test calls a real model, a real RPC node, Sourcify, Etherscan or any explorer. The RPC and Sourcify paths were exercised against local fakes written from the JSON-RPC and Sourcify v2 documentation; real providers may differ (response quirks, rate limits, pruned history).
* Stages after replay (trace analysis through ranking) were exercised only through the stand-in worker; analysis quality is untested.
* The Docker image could not be built here (no Docker). Its Foundry download, checksum and extraction were executed as written, and the
  entrypoint was syntax-checked; the full build, Render's behaviour and the free plan's memory use are untested.
* Online signature lookups in cast were not testable offline ([section 8](#8-foundry-versions-and-trace-handling)).
* The browser suite runs in jsdom, not a real browser: layout, real cookie handling and navigation were not seen by eye.

---

## 12. Deploying to Render (free plan)

`render.yaml` is set up for: **plan `free`**, **Docker** (the image is Python 3.11), **branch `main2`**, one worker process,
**one analysis at a time**, no disk and no paid add-ons. Do not add any.

**Branches.** Deploy from `main2` only. Leave `main` and `main1` untouched: create `main2` from this build, point Render at it
(the Blueprint already says `branch: main2`), and never merge into `main` or `main1` for deployment. This ZIP contains no git
metadata and changes no branch.

### Steps
1. Create `main2` from this build and push it.
2. In Render: **New → Blueprint**, pick the repository and the `main2` branch. Render reads `render.yaml`.
3. When prompted for the `sync: false` values, set:
   * **`FAULTSEEKER_ACCESS_CODE`**: required before you share the URL (12+ characters, your own).
   * The models you want: `CODEX_PROXY_BASE_URL`, `CODEX_PROXY_MODEL`, `MERCURY_BASE_URL`, `MERCURY_MODEL`, and optionally
     `OPENAI_API_KEY`, `CODEX_PROXY_API_KEY`, `MERCURY_API_KEY`. **If you set any key, the access code is mandatory**: the server will
     not start publicly without it. Leave keys unset to make each user bring their own.
   * `FAULTSEEKER_ENABLED_MODELS` (optional), `ETHERSCAN_API_KEY` (BSC source), `FAULTSEEKER_EXPLORER_FALLBACK` / `FAULTSEEKER_HTTP_PROXY` (leave unset: Stage 1 no longer needs explorers).
4. Wait for the build (installs Python 3.11 dependencies and the checksum-verified Foundry 1.9.0).
5. Open the URL: you should land on the sign-in page; after signing in the badge reads **RENDER · READY**.

### Free-plan realities (not workarounds)
* **Memory is 512 MB and has not been measured** for this pipeline. A run killed for memory shows `worker_crashed`.
* The service **spins down when idle** and cold-starts on the next request; a run in progress at restart becomes `interrupted`.
* **Storage is ephemeral:** run history, the replay cache and sessions vanish on restart or redeploy.
* Replay **and** transaction collection depend on your RPC. No explorer is contacted by default, so Etherscan/BscScan blocking Render's network no longer matters ([section 17](#17-known-limitations)).

### First-run checklist
1. `GET /api/health` returns `{"status":"ok"}`; `/` redirects to `/login`; the wrong code is refused; the right one signs in.
2. Badge **RENDER · READY**; hover shows the `cast` version (expect 1.9.0).
3. **View saved capture** renders without calling a model.
4. Run one Ethereum or BNB preset with an archive RPC and a valid key. Read the run log's `cast version:` line and **Technical logs** on any failure.

---

## 13. Running with Docker locally
```bash
docker build -t faultseeker .
docker run --rm -p 8000:10000 -e FAULTSEEKER_ACCESS_CODE='choose-your-own-code' faultseeker
```
The image sets `FAULTSEEKER_PUBLIC=1`, so adding a server-held key (`-e OPENAI_API_KEY=...`) without an access code is refused at startup.

---

## 14. Security model
* Keys travel only in request bodies, reach one worker process through its environment (only the selected provider's), and are masked
  everywhere they could be stored or served; the browser never stores them.
* Each provider's key is only ever sent to that provider's base URL; key checks do not follow redirects.
* Access protection ([section 5](#5-access-protection)); strict CSP (`script-src 'self'; style-src 'self'`, no framing); text rendered with
  `textContent` only; input and body-size limits; run IDs validated before any file access; SSRF guard on custom RPC hosts
  (DNS can change between check and use).
* Not provided: user accounts, per-user quotas, audit logs. The access code is a single shared secret.

---

## 15. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server exits at startup naming `FAULTSEEKER_ACCESS_CODE` | A server-held key without protection on a public server | Set the code (12+ chars), or remove the key |
| `Model registry: ... not configured: set CODEX_PROXY_MODEL` | A model is enabled but not fully configured | Set the named variables or remove it from `FAULTSEEKER_ENABLED_MODELS` |
| `key_validation_unavailable` | The provider could not be reached/verified (not a wrong key) | Check the base URL and status; for a proxy without `/models` set `key_validation` to `none` |
| `model_key_rejected` | The provider returned 401 | Re-enter the key for **that** provider |
| `provider_parameter_rejected` | The model refuses a configured parameter | Edit the model's `params` in `config/models.json` (e.g. temperature `omit`) |
| `model_not_found` | Wrong exact model ID or base URL | Fix `*_MODEL` / `*_BASE_URL` |
| `provider_unreachable` | 3 connection errors; no retries are made | Check the endpoint, then run again |
| Function names look raw (`2fbebd38`) in a trace | Unknown to cast and to the bundled table | Add the signature via `FAULTSEEKER_SELECTOR_TABLE` |
| Different classification between machines | Different `cast` version | Compare the `cast version:` log line; use the pinned 1.9.0 |
| Replay fails ("missing trie node", etc.) | Non-archive RPC | Use an archive RPC with tracing |
| `RPC collection failed (not_found)` | The endpoint does not know the hash: wrong network, or a pruned node | Match the network and RPC chain; use an archive RPC |
| `RPC collection failed (not_successful)` | The transaction reverted or is not mined | Only successful transactions are analyzed |
| `RPC collection failed (rejected / unreachable)` | Bad key, rate limit, provider down | Check the RPC URL and key; use another endpoint |
| `Contract source unavailable for 0x…` | Not verified on Sourcify and no Etherscan-API result | Set `ETHERSCAN_API_KEY`; the run continues without that contract's source |
| `Explorer page did not report a successful transaction` | Only with `FAULTSEEKER_EXPLORER_FALLBACK=1`: blocked page | Leave the fallback off |
| `worker_crashed` | Often out of memory on the free plan | See Technical logs; try smaller transactions |
| Locked out of sign-in | Rate limit (429) | Wait for `Retry-After` |

---

## 16. Project layout
```
FaultSeeker-main/
├── config/models.json          provider and model registry (no secrets)
├── faultseeker/
│   ├── chains.py  providers.py
│   ├── core/ forensics/ data_collection/ function_analysis/ utils/   original pipeline (utils/selectors.py, data_collection/rpc_client.py, rpc_collector.py, source_fetcher.py are new)
│   └── server/  app.py auth.py keycheck.py runs.py worker.py progress.py results.py presets.py security.py settings.py
├── web/            index.html, assets/ (console), login/ (sign-in page)
├── tests/          pytest suite, fixtures/, fake_worker.py, fake_provider.py, ui/ (browser suite)
├── scripts/        run_all_tests.sh, capture_cast_fixtures.py, generate_selectors.py
├── Dockerfile  docker-entrypoint.sh  render.yaml  .env.example  .python-version
└── GUIDE.md
```

---

## 17. Known limitations
* **No real Ethereum or BSC run has been verified**, and no real provider was called. Treat the first real runs as the actual acceptance test.
* **Explorer scraping is no longer on the default path.** Stage 1 reads the transaction over RPC. The scrape remains only behind
  `FAULTSEEKER_EXPLORER_FALLBACK=1`, and is as fragile as before (Cloudflare returns 403 to datacenter IPs).
* **RPC collection limits.** Token transfers come from `Transfer` events in the receipt (ERC-20, ERC-721, ERC-1155 single and batch); symbols and
  decimals are read with `eth_call` at `latest` (a token that implements neither is shown as `ERC20` with its raw amount). Native-coin and
  internal transfers are not part of the record, as before. The fund-flow graph is now a multigraph, so two transfers between the same pair
  of addresses are both kept (the page scrape collapsed them). Reverted transactions are rejected, as before.
* **Source download.** Sourcify only has contracts someone verified there; for others, set `ETHERSCAN_API_KEY`. Without either, Stage 2 has no
  source for that contract and says so. Sourcify results were not tested against the live service (see section 11).
* Beta and partial networks are unverified; zkSync is unsupported.
* One analysis at a time; free-plan memory, spin-down and ephemeral storage ([section 12](#12-deploying-to-render-free-plan)).
* A shared access code, in-memory sessions, and rate limiting that trusts the proxy's forwarded address.
* Unknown function selectors stay "hashed" ([section 8](#8-foundry-versions-and-trace-handling)).
* Layout was verified structurally in jsdom, not by eye on real devices. Windows needs WSL2 or Docker.

---

## 18. Extending
* **Add a provider or model:** add entries to `config/models.json` naming the environment variables for the base URL, exact model ID and key;
  `tests/test_providers.py` shows the shape. Set `key_validation` to `models_list` or `none`.
* **Add a network:** an entry in `faultseeker/chains.py` and a same-named alias in `foundry.toml`.
* **Add known signatures:** edit `scripts/generate_selectors.py`, run it, and run `pytest tests/test_selectors.py`.
* **Change the look:** edit `web/assets/console.css` (and `web/login/login.css`); keep styles in stylesheets (the CSP blocks inline styles).
