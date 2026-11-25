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

### Input budgets

Every request to a model is checked against that model's input budget before it is sent. There is no universal character cap any more
(the old 10,000-character cap was an application limit, not a provider limit, and it ended the BEGO `swap` analysis with a 10,237-character request).

**Units.** Estimated tokens, never characters. No tokenizer dependency is added, so the estimate is a conservative upper bound:
`tokens = ceil(UTF-8 bytes / bytes_per_token)` with `bytes_per_token = 1.0` by default (a byte-level BPE token covers at least one byte, so this
over-counts rather than under-counts; it cannot guarantee that a *different* tokenizer is bounded, which is why a larger ratio is an explicit
operator calibration). A request fits when the estimated tokens of **every message sent** (system message, retained history, tool messages and
the new user message, each plus 16 tokens of framing) + the reserved output + a safety margin (the larger of 256 tokens and 2% of the context)
do not exceed the context window. History is the system message plus the last exchange, for every provider (Ollama now sends the same,
and states `num_ctx` explicitly because Ollama otherwise silently drops the front of an oversized prompt).

**Where limits come from, highest precedence first.**

| # | Source | Notes |
|---|---|---|
| 1 | `FAULTSEEKER_CONTEXT_TOKENS_<MODEL>`, `FAULTSEEKER_OUTPUT_RESERVE_TOKENS_<MODEL>`, `FAULTSEEKER_BYTES_PER_TOKEN_<MODEL>` | `<MODEL>` is the registry id upper-cased with every non-alphanumeric character replaced by `_` (`gpt-4o-mini` → `GPT_4O_MINI`, `ollama:llama3` → `OLLAMA_LLAMA3`, `mercury` → `MERCURY`). Context 1,024–10,000,000; ratio 1.0–8.0. Trusted as set |
| 2 | `limits` block of the model in `config/models.json` | Documented values only, each with its source page and check date (below) |
| 3 | `FAULTSEEKER_DEFAULT_CONTEXT_TOKENS` | Only for models without a `limits` block |
| 4 | Built-in conservative fallback | `openai_compatible` 8,192 tokens (2,048 reserved for output), `ollama` 4,096 (1,024). An assumption about an **unknown** model, not a claim about any model |

The output reserve is, highest first: the override; the `max_tokens`/`max_completion_tokens` the request actually sends; the model's documented
maximum output; the fallback. Invalid values (non-numeric, out of range, a reserve below the `max_tokens` sent, a context that leaves under 512
usable tokens) are rejected when the model is resolved, with the setting named; nothing is silently clamped.

**Verified limits in `config/models.json`** (OpenAI model pages, checked 2026-11-18; context window / max output tokens):

| Model | Context | Max output | Source |
|---|---|---|---|
| gpt-4o-mini | 128,000 | 16,384 | https://developers.openai.com/api/docs/models/gpt-4o-mini |
| gpt-4o | 128,000 | 16,384 | https://developers.openai.com/api/docs/models/gpt-4o (the page marks the model deprecated) |
| gpt-4.1-mini | 1,047,576 | 32,768 | https://developers.openai.com/api/docs/models/gpt-4.1-mini |
| gpt-4.1 | 1,047,576 | 32,768 | https://developers.openai.com/api/docs/models/gpt-4.1 |

`codex-proxy` and `mercury` have **no** `limits`: their model id comes from your environment, and the only Mercury figures found were secondary
sources that disagree with each other. They use the fallback until you set `FAULTSEEKER_CONTEXT_TOKENS_CODEX_PROXY` / `..._MERCURY` (and, if
needed, `FAULTSEEKER_OUTPUT_RESERVE_TOKENS_<MODEL>`) from your own provider's documentation. Ollama's documented default context is chosen by VRAM
(4k / 32k / 256k tokens); the 4,096 fallback is the lowest of those tiers. Set the real figure with `FAULTSEEKER_CONTEXT_TOKENS_OLLAMA_<NAME>`.

**What happens when a request does not fit (Stage 2, per candidate).** Prompt text is split into *required* parts (instructions, candidate identity,
the task description, the closing contract) and *reducible evidence*, reduced **in this order**: (1) history (earlier understanding, task tree),
(2) context (balances, relations, children calls, the latest task result), (3) source code, (4) the candidate's own trace/analysis evidence. Within a
tier every part keeps the same fraction; a reduced part keeps its head and tail around a visible `[… N bytes omitted …]` marker, and a part that cannot keep
anything becomes the marker alone. Every reduction is recorded per candidate (step, section, tier, original and kept bytes) and reaches the report. If the
**required** parts alone do not fit, the request is **not sent**: `InputLimitExceeded` (a terminal `ProviderFailure`, no retry) fails the candidate, Stage 2 ends as
`analysis_incomplete`, and the hint names the budget instead of blaming the provider. Narrowing and ranking requests (optional, whole-candidate-list prompts) and the
Stage 1 forensics prompts are budget-checked but not reduced: over budget, narrowing is ignored, ranking falls back to unranked, and a Stage 1 prompt stops the run as `input_too_large`.

**Execution versus evidence.** The report keeps two axes apart. *Execution* (`coverage.status`, `limited`): was every candidate analyzed.
*Evidence* (`coverage.evidence_limited`, per-function `evidence`): did the model see adequate evidence: `complete`, `reduced` (cut to fit the budget),
`source_missing`, `reduced_source_missing`, `not_analyzed`. A completed execution with limited evidence is never reported as a clean negative.

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

### Results

**Fresh results for this revision (main2 audit-fix build; run offline from the working tree; nothing here is a live ETH/BSC result):**

| Run | Conditions | Result |
|---|---|---|
| Python suite | Python **3.11.15** (uv-managed), full `requirements.txt` + `requirements-dev.txt`, **no Foundry** on PATH. `python -m pytest tests -q -p no:cacheprovider -rs` | **954 passed, 0 failed, 5 skipped**. Skips: 4 in `test_cast_integration.py` (Foundry `cast` + `anvil` not installed) and 1 in `test_selectors.py:34` (`cast` not installed) |
| Browser suite | Node v22.23.4, jsdom 31, server on Python 3.11.15 with the fake worker and local fake providers. `cd tests/ui && npm install && npm test` | **275 checks passed, 0 failed** |
| Real browser | Headless Chromium 153 (npm `@sparticuz/chromium`) against the real server and fake worker: a cancelled run (new `cancelled` stage state), desktop 1280x900 and mobile 390x844 | Rendered and inspected by eye; no horizontal overflow. The key-routing fix (F01) and the other audit fixes have no visual change and are covered by jsdom and Python tests |

The immediately previous revision (budgeting build) recorded 820 passed / 5 skipped (Python 3.11.15) and 258 browser checks.

The Foundry integration tests (`test_cast_integration.py`) were **not run** here: Foundry is unavailable, so real-`cast` behaviour was not re-verified in this revision.

**Baseline for comparison (the November 15 ZIP, re-run here on Python 3.11.15):** 528 passed, 5 skipped (same five skips), 221 jsdom checks.
The new regressions were written first and run against that baseline: the six new files collected 213 tests, **150 failed and 63 passed** (the passing ones are guards, e.g. valid keys still accepted). That revision's 10,000-character cap no longer exists; see Input budgets.

**Historical claims (not re-verified in this revision; kept only as history).** An earlier revision recorded: Python 3.12.3 with real Foundry 1.4.4 + 1.5.1 + 1.9.0 =
261 passed / 0 skipped; Python 3.12.3 without Foundry = 248 passed / 5 skipped; minimal packages = 154 passed / 12 skipped; browser suite = 148 checks.
Those counts describe an older tree and are superseded by the table above. The RPC-only revision added `test_rpc_collection.py` and a fake JSON-RPC node/Sourcify
(`tests/fake_rpc.py`); its key proof, `test_collection_works_with_explorers_blocked_and_never_touches_them`, still exists and still passes.

**Old assertions that were changed (not weakened silently).** Requirement 1 reverses three behaviours that older tests had encoded, so those assertions were rewritten to the new rule:
function names were matched case-insensitively when ranking (`test_ranking_contract.py`, `test_results.py`); a ranked full key that was not a finding was shown with empty evidence
(`test_results.py`, `test_ranking_contract.py`); a model finding with a key that is not `<function>_<address>` was promoted as an unranked candidate (`test_results.py`).
Two other tests only changed their *setup* because the old setup gave the model a key that is not a candidate of its context (`test_evidence_to_verdict.py`, `test_model_response_validation.py`); their assertions are unchanged.
Changed again in the budgeting revision, because the behaviour they pinned is the defect that revision fixes: `test_input_limit.py` was rewritten (it pinned the universal 10,000-character cap);
the verdict-input warning now says "model input budget" instead of "model input limit" (`test_evidence_report_contract.py`); and a pipeline test that expected the plain "No potentially vulnerable functions were identified"
line for candidates with no contract source now expects "not a clean result" (`test_selection_completion.py`), because missing source is limited evidence.

Changed again in the audit-fix revision, each because the behaviour it pinned is a finding that revision fixes: the exact-equality check of a balance amount now compares exact decimals instead of `pytest.approx` of a float (`test_rpc_collection.py`, F10);
an empty zero-exit explorer lookup is `no_files`, no longer "unverified" (`test_source_lookup_cause.py`, F08);
with an unreachable endpoint the chain check now stops the replay before `cast` runs, so two end-to-end tests no longer expect a `cast exited` line (`test_pipeline_patches.py`, F05);
the replay-cache tests now supply a complete cast footer and a chain id (`test_pipeline_patches.py`, F03/F04); the model-registry contract tests now include the DeepSeek route and assert model ids instead of a count (`test_api.py`, `test_providers.py`, `ui.test.mjs`, F11);
the fake node answers `eth_chainId`, so the RPC tests state which chain their node serves (setup only).

Key package versions are whatever pip resolved on the build date; they were not pinned for this run.

### Audit fixes (main2 audit, findings F01-F11 and R01-R02)

Each finding was reproduced by a failing test before it was fixed (`tests/test_audit_*.py` and the F01 section of `tests/ui/ui.test.mjs`).

| Finding | Fix |
|---|---|
| F01 key bound to provider | `console.js` keeps the owner of the typed key; a provider change clears and re-hides it, a submit re-checks |
| F02 body cap on streamed bodies | `read_json_body` counts received bytes; bad `Content-Length` is refused |
| F03 failed replay cached | success requires exit 0 and the cast completion footer; otherwise nothing is returned or cached |
| F04 cache keyed by hash only | key = chain id + hash + schema; SHA-256 and metadata sidecar; atomic publish; legacy entries ignored |
| F05 no chain check | `eth_chainId` must equal the registry id before replay or collection (`wrong_chain`, `bad_response`, `unknown_chain`) |
| F06 non-string fields | every field is type-checked; all validation precedes any external key check |
| F07 terminal paths | one `_settle` step; stage statuses `cancelled` / `interrupted` added to the UI |
| F08 zero-exit getCode | output is read, scrubbed and classified; empty zero exit is `no_files`, not "unverified" |
| F09 unknown decimals | historical block metadata, labelled `latest` fallback, unknown decimals shown as raw units |
| F10 float arithmetic | exact `Decimal` balances, string amounts with a `unit` flag |
| F11 stale tests | registry contract updated for the DeepSeek route; assertions are on model ids, not counts |
| R01 redirects / rebinding | redirects refused; connect-time public-address check with pinning in the Python RPC client |
| R02 latest-only source | `source_provenance` reported as a warning when any source was used |

**Reconciliation note.** This build was rebased onto main2 3048f70, which holds the real DeepSeek route. The real `config/models.json` entry (model id `deepseek-v4.1-flash-free`, `temperature: pass`, limits source `https://100milionseek.top/v1/models`) was kept; the audit-fix tests were changed to that id. The reconstructed `milionseek` model id is not used.

**Limitations that remain.** The `cast` subprocess resolves and connects by itself, so the connect-time address check and the redirect refusal do not cover it. The replay cache records chain, hash, digest and schema, not the block hash.
Token decimals and symbols come from the contract's current ABI answers at the transaction block when the endpoint keeps that state, otherwise from `latest` (labelled). R03-R06 (failed-run diagnostics artifact, readiness, parameter verification, 503 backoff) were not changed.

### Touched state machines and invariants

These flows were implicit (flags, list lengths, substring tests). They are now explicit; each invariant has a test.

| Machine | States and transitions | Invariants |
|---|---|---|
| **Candidate selection** (`_review_function_calls`) | universe → selected → {analyzed, failed}; universe − selected = omitted. A narrowing reply is applied only if, after validation, it is non-empty and smaller | Selection names must resolve to a candidate (function name exact, address case-insensitive); unknown names and repeats are rejected and counted; the model's order is kept; an unusable or fully invalid reply is ignored (nothing is dropped); an omitted candidate is never in `examined_function_memo` |
| **Coverage** (`coverage_report`, raw `coverage`, report `coverage`) | `no_candidates` / `complete` / `limited` (omitted or failed candidates) | Genuinely empty input reads differently from a limited analysis; an empty report with `limited` coverage is **not** a clean result in the API warnings and in the UI |
| **Candidate loop and completion** (`_function_analysis_init`) | init → steps → adequacy check → complete \| iteration limit \| provider failure (terminal) | Only an explicit response completes a candidate: exactly `Yes` (any case, optional final `.`/`!`) or `{"adequate": true}`. "not yet, yes later", a quoted yes, malformed text and an empty reply never complete it; the attempt bound (31 iterations, a check every third) and rollback are unchanged |
| **Verdict acceptance** (`_update_potentially_vulnerable_function`) | per entry: resolve identity → validate evidence → validate confidence → accepted \| rejected(reason); per step: some accepted \| nothing named \| everything rejected (error, retried by the candidate loop) | A key must resolve **uniquely** to a candidate of this analysis or to a trace-backed function the analysis context shows (child call present in the transaction's call memo); abbreviations and decorated spellings use the same rule; evidence must normalize to readable text; confidence must be finite and in (0, 1]; the same function twice in one reply counts once; rejections are counted per reason and roll back with a failed attempt |
| **Model input** (`budget.py`, `AbstractAgent._enforce_budget` / `fit`) | request → measured against the model's budget → sent whole \| fitted (reductions recorded) \| refused as `InputLimitExceeded` | Every request path (OpenAI-compatible, Ollama, legacy `query`) is checked against system + retained history + new message + reserved output + margin; reducible evidence goes in the order history, context, source, trace; required text is never cut; nothing required is dropped silently; routing, parameters and retry budgets are unchanged |
| **Evidence adequacy** (`function_results`, `coverage.evidence_limited`) | per candidate: execution completed \| failed \| omitted; evidence complete \| reduced \| source_missing \| reduced_source_missing \| not_analyzed | Execution completion never implies adequate evidence; reduced or source-missing evidence with no finding is reported as "not a clean result"; reductions roll back with a failed attempt |
| **RPC receipt state** (`rpc_collector.collect`) | transaction lookup → receipt lookup: found \| missing with a block number (`history_unavailable`) \| missing without a block number (genuinely unmined) | Only a transaction the node itself places in no block is "not mined"; a missing receipt for a mined transaction, or a pruned-history error, is `history_unavailable` with an archive-RPC hint; rate limits and other errors keep their own classes |
| **Request body** (`app.read_json_body`, gate middleware) | headers → bytes received → parsed \| 400 invalid \| 413 too large | The cap counts the bytes actually received, in chunks, before the body is buffered whole; a missing, understated or malformed `Content-Length` cannot bypass it; the same cap covers `/auth/login` and `/api/runs`; every field is validated (type and format) **before** any external key-validation call |
| **Provider key ownership** (`console.js`: `state.keyProvider`, `lastProvider`) | typed for provider P → still P (kept) \| provider changed (cleared, re-hidden) \| keyless (cleared, disabled) | A key is held only for the provider it was entered for; switching to another provider clears it and it is never restored; a submit re-checks and never pairs one provider's key with another model |
| **Chain verification** (`rpc_collector.verify_chain`, `TransactionReplayer.verified_chain_id`) | endpoint → `eth_chainId` → verified \| `wrong_chain` \| `bad_response` \| `unknown_chain` | Nothing is replayed, collected or cached for an endpoint that has not matched the selected network's registry chain id; the same endpoint resolution is used for replay and collection |
| **Replay cache** (`TransactionReplayer`) | cast run → exit 0 AND complete trace (completion footer) → published atomically \| discarded | Failed, empty, truncated or non-zero replays publish nothing; entries are keyed by chain id + hash + schema version, carry a SHA-256 and metadata, and a mismatching, corrupted or legacy (hash-only) entry is a miss; an interrupted write leaves no entry |
| **Token amounts** (`rpc_collector._TokenInfo`, `FundFlowAnalyzer`) | decimals read at the transaction block \| read at `latest` (labelled) \| unknown | Unknown decimals are never zero: the label says `N raw units, decimals unknown` and the record keeps the raw integer; balances are exact `Decimal` strings with a `unit` flag (no float anywhere), and an unreadable amount is an error, never zero |
| **Source lookup** (`ContractDownloader.lookup_outcomes`) | Sourcify → explorer API → found \| unverified \| credentials \| rate-limited \| unreachable \| no_files \| unknown | A zero exit with no files is classified by what the tool printed; an empty zero exit is `no_files` (absence not established), not "unverified"; keys are scrubbed everywhere; found source is reported as latest, not block-pinned |
| **Run terminal state** (`RunManager._decide` → `_settle`) | running → completed \| failed \| cancelled \| interrupted | Exactly one settle step: no stage stays `active` (it becomes `failed` / `cancelled` / `interrupted`), completed stages stay `done`, the headline no longer says "Starting the pipeline", and a terminal event is recorded; precedence is shutdown > cancel > timeout > fatal > result |
| **RPC redirects and addresses** (`rpc_client._opener`) | request → connect to a validated public address → response \| 3xx refused | Redirects are never followed; when the server enforces public endpoints (the default) every DNS answer must be public and the connection is pinned to the validated address; the foundry `cast` subprocess is not covered by this check (see limitations) |
| **Stage 1 model replies** (`forensics/contracts.py`) | reply → typed value \| `ProviderFailure` \| `ForensicsModelError` | No `eval` anywhere (a test scans the package); an explicit `[]` of victims is valid, a provider failure or unusable reply is never "no victims" or a clean classification; `unknown`/`vulnerable` match in any letter case; one `query_json` per operation, no loop around it |
| **Ranking** (`normalize`) | raw ranked entries → resolved to an accepted finding \| dropped (reason); ranking usable \| unranked fallback | A ranked key must resolve uniquely to an accepted finding (never invents one); optional ranking failure keeps valid findings (shown unranked) |
| **Report** (`normalize`) | raw finding → accepted (valid identity + readable evidence) \| rejected | Raw objects, confidence fields, provider error sentinels and malformed values are never shown; junk is never promoted; rejected verdict entries, unusable evidence, limited coverage and shortened verdict input are surfaced as warnings |
| **Worker error publication** (`runs.py`) | worker error → classified code | Generic worker errors publish a fixed sentence plus a sanitized exception type; the raw text goes only to the redacted technical log |

Other implicit machines exist (run lifecycle, key validation, sessions, progress stages, capture/replay) and were **not** audited in this revision.

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
| `test_identity_membership.py` | Verdict and ranking keys resolve uniquely to a candidate / accepted finding: unknown full keys, empty context, address case, function-name case, ambiguous abbreviations, decorated forms, duplicates, trace-backed functions |
| `test_selection_completion.py` | Narrowing validation, prioritization, selected/analyzed/omitted/failed bookkeeping, coverage in the pipeline result, explicit completion responses and look-alikes |
| `test_forensics_safe_parsing.py` | No `eval`/`exec`; hostile model text never executes; actual victim and role caller paths with local fake agents; provider and unusable replies fail closed within the existing retry budget |
| `test_evidence_report_contract.py` | Readable evidence, junk never promoted, rejection and coverage warnings, confidence finiteness and range, evidence-type validation |
| `test_input_limit.py` | Budget configuration and precedence, invalid overrides, the 10,237-character request under a restrictive and a sufficient budget, enforcement on every request path (system/history/tool messages, output reserve, multibyte text, Ollama), the defined reduction order, fail-closed required content, per-function and coverage propagation |
| `test_audit_requests.py`, `test_audit_replay.py`, `test_audit_amounts.py`, `test_audit_terminal_state.py`, `test_audit_ssrf_provenance.py` | Audit findings F01-F10, R01, R02: streamed body cap and typed fields, replay acceptance / cache provenance / chain verification, unknown decimals and exact arithmetic, terminal run state, redirects and connect-time address checks, source provenance |
| `test_rpc_history.py` | Pruned-history versus genuinely unmined versus unrelated RPC errors, retry behaviour, run classification |
| `test_source_lookup_cause.py` | Source lookup causes (credentials, unreachable, unverified, unknown), no key leak, evidence gap kept separate from execution failure |
| `test_worker_error_publication.py` | Generic worker errors are sanitized in the API; detail only in the technical log |
| `tests/ui/ui.test.mjs` | Console behaviour in jsdom: setup, networks, presets, provider-aware key hints, invalid / **unreachable** / outage key checks, full run to report, every failure type, capture, routing, busy/cancel, **access protection with a cookie jar** (sign-in, wrong code, sign-out, expired session, rate-limit message), unreachable server, untrusted text never interpreted as HTML |

### What the tests do **not** prove
* **No real Ethereum or BSC analysis was run or verified.** No test calls a real model, a real RPC node, Sourcify, Etherscan or any explorer. The RPC and Sourcify paths were exercised against local fakes written from the JSON-RPC and Sourcify v2 documentation; real providers may differ (response quirks, rate limits, pruned history).
* Stages after replay (trace analysis through ranking) were exercised only through the stand-in worker; analysis quality is untested.
* The Docker image could not be built here (no Docker). Its Foundry download, checksum and extraction were executed as written, and the
  entrypoint was syntax-checked; the full build, Render's behaviour and the free plan's memory use are untested.
* Online signature lookups in cast were not testable offline ([section 8](#8-foundry-versions-and-trace-handling)).
* The browser suite runs in jsdom, not a real browser: only the one scenario in the Results table was inspected in a real browser; other layouts, real cookie handling and navigation were not seen by eye.
* **Fake-model tests do not show exploit detection.** They prove how the pipeline treats replies, not that a real model finds a known exploit; no live ETH/BSC run was made.
* The input budget is an estimate (UTF-8 bytes, a conservative upper bound), not a tokenizer count; the documented limits are the providers' published context sizes, not a guarantee that a given account or endpoint accepts them. Models without a documented limit use a conservative fallback until an override is set.

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
| `Contract source unavailable for 0x…` | The line states what each lookup reported and the likely cause (missing/invalid explorer key, rate limit, unreachable service, unverified contract) or says the cause is not established | Follow the stated cause. A key may widen coverage but does not guarantee the source exists; the run continues and the report marks the function's evidence as source-missing |
| `RPC collection failed (history_unavailable)` | The endpoint knows the transaction (it returned a block number) but has no receipt, or answered with a pruned-history error (`missing trie node`, `historical state … not available`, …) | Use an archive-capable RPC under “RPC connection”. A hash the node has never mined still reports `not mined yet` |
| `analysis_incomplete` with `InputLimitExceeded` | A request did not fit the model's input budget (application limit, not a provider outage) | Use a model with a larger documented context or set `FAULTSEEKER_CONTEXT_TOKENS_<MODEL>` (see Input budgets) |
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
