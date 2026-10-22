# FaultSeeker // Live Forensic Console

The live console includes a responsive transaction setup screen, real event-driven analysis progress, cancellation, reconnect/recovery, recent runs, and resilient evidence reports. Failed live analyses remain failed or inconclusive; they are never silently replaced with a saved capture.

The editable frontend is `app/web/index.html` and `app/web/assets/console.{js,css}`. Root `index.html` and `assets/console.{js,css}` mirror it for static hosting. The original compiled bundles are retained but are no longer the entry point. Static hosting supports explicitly selected saved captures only.

Production verification and deployment notes: [docs/production-verification.md](docs/production-verification.md).

Live site: **https://namelessmonsterr.github.io/faultseeker-demo-console/**

A nerv-ui styled forensic console for FaultSeeker. This repo contains ONLY
the website: the compiled front end, the small local console server, and a
saved Stage-1 capture it replays. No FaultSeeker pipeline code is bundled.

The console drives **your own FaultSeeker fork**
([NamelessMonsterr/FaultSeeker-](https://github.com/NamelessMonsterr/FaultSeeker-))
for live runs - `run.bat` / `run.sh` clone it next to this repo automatically
(and use its `console-demo-compat` branch until that PR is merged).

## Contents

- `index.html`, `assets/console.*` - editable, dependency-free console frontend
- `app/server.py` - local FastAPI console server (serves the UI, runs Stage 1-3 through your fork, streams progress)
- `api/capture` - saved Stage-1 capture (Zunami UZD exploit, ETH) used for the hosted replay and as the offline fallback
- `api/config` - chain/model metadata for the Settings panel
- `run.bat` / `run.sh` - one-command local run
- `404.html`, `.nojekyll` - GitHub Pages plumbing (`gh-pages` branch)

## Hosted site (GitHub Pages)

Saved-capture viewing only: the user explicitly opens the Zunami UZD capture.
There is no backend on static hosting, so live analysis is disabled. A recorded
Stage-1 rule verdict is labeled as Stage 1 only, with its original limitations.

## Local run (live analysis with your keys)

1. Python 3.11 on PATH. For live traces: Foundry `cast` (`foundryup`) and an
   archive RPC key (dRPC) - free public RPCs cannot `debug_traceTransaction`.
2. Windows: `run.bat`. Linux/Mac: `./run.sh`
   (first run clones your fork and installs dependencies).
3. Open **http://127.0.0.1:8420**. Keys go in the UI's ⚙ Settings
   (chain, model, dRPC/BlockPI RPC, LLM key) - sent per-request to your local
   server only. Credentials are never placed in browser storage or run history.
   Supply the complete RPC URL and leave RPC key blank, or include `{key}` in
   the URL and supply its value separately; the server URL-encodes that value.

### Modes

- **SAVED CAPTURE** - replays `api/capture` (Zunami UZD). No keys, no network.
- **ANALYZE (no-LLM)** - deterministic Stage 1 via your fork's
  `main(txn_hash, chain, no_llm=True)`. Needs an archive RPC key for real
  transactions; without one it reports a visible error or inconclusive result.
- **ANALYZE (model selected)** - full pipeline Stage 1-3 with the chosen
  model and its API key, cost tracking on. Real spend on your key.

No API keys are stored anywhere in this repository. Do not commit any.

## Hosted live deploy (Render)

Live URL: **https://faultseeker-demo-console.onrender.com**

The same console, hosted as a Docker web service (Render free tier, Oregon).
Unlike the GitHub Pages replay, this one runs the real pipeline through your
fork - ANALYZE works here.

- Access is gated: the site asks for the demo access code first
  (`DEMO_GATE_PASSWORD` env var on Render; rotate it there anytime). Rate
  limits: 10 runs/hour, 40/day per network, one run at a time.
- Keys: server-side env vars on Render power out-of-the-box live runs
  (`ETH_RPC_URL` = dRPC endpoint, `GOOGLE_API_KEY` = Gemini, optional
  `BSC_RPC_URL` = BlockPI). The page's ⚙ Settings fields override them
  per-request; request-sent keys are held in memory for that run only and
  server env values are restored after every run. Keys never enter the repo.
- Free tier notes: 512 MB RAM, sleeps after 15 min idle (first load after
  sleep takes ~30-60s). 750 free instance-hours/month.
- Redeploy: Render auto-deploys on push to `main`. Manual: Render dashboard
  -> faultseeker-demo-console -> Manual Deploy.
- `Dockerfile` pins the pipeline to your fork's `console-demo-compat` branch;
  after PR #1 merges, change `FAULTSEEKER_REF` to `main` in the Dockerfile.

Health check: `/healthz` (used by the keep-alive ping).
