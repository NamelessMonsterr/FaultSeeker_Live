# FaultSeeker + Forensic Console

FaultSeeker (LLM-empowered blockchain transaction forensics, ASE 2025) together with a live web console.
This is one repository: the pipeline at the root, the console under `console/`.

```
faultseeker/        pipeline package (original FaultSeeker + audit-hardened modules)
console/            web console: FastAPI server (app/), UI (app/web), saved capture (api/), console tests
tests/              pipeline tests            benchmark/   datasets, ground truth, evaluation scripts
data/models/        pre-trained calibrator    full_paper/  the original paper (unchanged)
docs/               pipeline docs; docs/original/ keeps both original READMEs
```

## Run the console

Needs Python 3.11+. For live traces you also need an **archive/trace RPC** (`debug_traceTransaction`,
e.g. dRPC or BlockPI) and an API key for the model you select. Free public RPCs cannot trace.

```bash
cp .env.example .env     # fill ETH_RPC_URL and your model key (optional: keys can also go in the UI's Settings)
./run.sh                 # Windows: run.bat
```

Open http://127.0.0.1:8420. The server refuses all requests until an access code exists: it uses
`DEMO_GATE_PASSWORD` from the environment or `.env`; if neither is set, `run.sh`/`run.bat` print a one-off code.

Modes in the UI: **Saved capture** (no keys, no network), **Analyze (no-LLM)** (deterministic Stage 1),
**Analyze (model)** (full Stage 1-3, spends your key).

## Run the pipeline without the UI

```bash
pip install -r requirements.txt
python -m faultseeker -txn_hash 0x... -chain eth
```

## Tests (written for this layout; not yet executed)

```bash
python -m pytest                          # pipeline tests (tests/)
python console/tests/run_offline.py       # console tests, network blocked
node console/tests/run_frontend_offline.cjs
python console/tools/sync_static.py --check
```

New in this layout: `tests/test_txn_info_registry_fallback.py`, `tests/test_console_contract.py`,
`console/tests/test_env_loader.py`, `console/tests/test_trace_identity_message.py`, rewritten
`console/tests/test_packaging.py`. The old "pinned fork" suite is retired (skips with a message);
`test_candidate_pipeline_transport.py` and `test_three_pillar_regressions.py` now run against this repo.

## Docker

```bash
docker build -t faultseeker .
docker run -p 8420:8420 -e DEMO_GATE_PASSWORD=... -e ETH_RPC_URL=... faultseeker
```

## Changes versus the two source projects

- Transaction info falls back to your configured `<CHAIN>_RPC_URL` before hardcoded public nodes
  (previously every run stopped at "Failed to collect transaction block info").
- A missing trace now says so ("No execution trace was obtained...") instead of "cache has a different transaction or chain".
- The server reads `<repo>/.env` (real environment wins) and defaults the pipeline to this repo; no clone step.
- Docs in `console/docs/` and `docs/pipeline/` are historical and may mention the old two-repo setup.

License: see `LICENSE`. Console front-end skin: nerv-ui (MIT), see `console/NOTICE`.
