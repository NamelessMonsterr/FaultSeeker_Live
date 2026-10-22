# FaultSeeker // Forensic Console (hosted website build)

Live site: **https://namelessmonsterr.github.io/faultseeker-demo-console/**

A static, nerv-ui-styled forensic console for FaultSeeker, served with
GitHub Pages from this repository (`gh-pages` branch).

This repo contains ONLY the website build:

- `index.html`, `assets/` - the compiled front end (React + Tailwind, nerv-ui skin)
- `api/capture` - a saved Stage-1 capture (Zunami UZD exploit, ETH) the site replays
- `api/config` - chain/model metadata for the Settings panel
- `404.html`, `.nojekyll` - Pages plumbing

The hosted site is a **saved-capture replay**: it has no backend, so ANALYZE
cannot run live there (it falls back to the saved capture, by design). Live
pipeline runs with your own dRPC/BlockPI/LLM keys happen in the separate local
console, not in this repo. No API keys are stored anywhere in this repository.
