"""Run lifecycle: start a worker subprocess, stream its output into progress state, persist results."""
import asyncio
import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from . import progress, results, settings
from .security import RUN_ID_RE, Redactor
from .worker import MARKER

FINAL_STATES = {"completed", "failed", "cancelled", "interrupted"}


class BusyError(Exception):
    def __init__(self, active_id: str, started_at: float):
        super().__init__("busy")
        self.active_id, self.started_at = active_id, started_at


class Run:
    def __init__(self, txn_hash: str, chain: str, model: str, rpc_mode: str, key_source: str):
        self.id = uuid.uuid4().hex[:16]
        self.txn_hash, self.chain, self.model = txn_hash, chain, model
        self.rpc_mode, self.key_source = rpc_mode, key_source
        self.provider = ""
        self.key_check = ""
        self.connection_errors = 0
        self.state = "running"
        self.created_at = time.time()
        self.finished_at: Optional[float] = None
        self.error: Optional[dict] = None
        self.stages = [dict(s, status="pending") for s in progress.STAGES]
        self.current = {"title": "Starting the pipeline",
                        "description": "Waiting for the first confirmed progress event."}
        self.last_activity_at = self.created_at
        self.events: List[dict] = []
        self.logs: List[str] = []
        self.log_offset = 0           # number of lines dropped from the front of the ring buffer
        self.summary: Optional[dict] = None
        # supervisor-only state
        self.proc: Optional[asyncio.subprocess.Process] = None
        self.redactor = Redactor()
        self.shutting_down = False
        self.cancel_requested = False
        self.fatal: Optional[dict] = None
        self.cast_error = ""
        self.explorer_error = ""
        self.model_errors = 0
        self.worker_error: Optional[dict] = None
        self.result_ready = False
        self.log_bytes = 0

    # -- serialisation -----------------------------------------------------------------------------
    def meta(self) -> dict:
        return {
            "id": self.id, "txn_hash": self.txn_hash, "chain": self.chain, "model": self.model,
            "provider": self.provider, "key_check": self.key_check,
            "rpc_mode": self.rpc_mode, "key_source": self.key_source, "state": self.state,
            "created_at": self.created_at, "finished_at": self.finished_at,
            "last_activity_at": self.last_activity_at, "error": self.error,
            "stages": self.stages, "current": self.current, "summary": self.summary,
        }


class RunManager:
    def __init__(self):
        self.runs: Dict[str, Run] = {}
        self.active: Dict[str, Run] = {}
        settings.RUNS_DIR.mkdir(parents=True, exist_ok=True)
        self._mark_interrupted()

    # -- storage helpers ---------------------------------------------------------------------------
    def _dir(self, run_id: str) -> Path:
        return settings.RUNS_DIR / run_id

    def _write_meta(self, run: Run):
        d = self._dir(run.id)
        d.mkdir(parents=True, exist_ok=True)
        tmp = d / "meta.json.tmp"
        tmp.write_text(json.dumps(run.meta()), encoding="utf-8")
        os.replace(tmp, d / "meta.json")

    def _mark_interrupted(self):
        for d in settings.RUNS_DIR.glob("*/meta.json"):
            try:
                meta = json.loads(d.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if meta.get("state") == "running":
                meta["state"] = "interrupted"
                meta["finished_at"] = meta.get("finished_at") or time.time()
                meta["error"] = {"code": "interrupted", "message": "The server restarted while this run was in progress.",
                                 "hint": "Start the analysis again. Cached replays and contracts are reused."}
                d.write_text(json.dumps(meta), encoding="utf-8")

    def _prune(self):
        dirs = sorted((p for p in settings.RUNS_DIR.iterdir() if p.is_dir()), key=lambda p: p.stat().st_mtime)
        excess = len(dirs) - settings.MAX_STORED_RUNS
        for p in dirs:
            if excess <= 0:
                break
            if p.name in self.active:
                continue
            for f in p.glob("*"):
                f.unlink(missing_ok=True)
            p.rmdir()
            self.runs.pop(p.name, None)
            excess -= 1

    # -- public API --------------------------------------------------------------------------------
    def start(self, *, txn_hash: str, chain: str, model: str, model_key: str, rpc_url: str,
              key_check: str = "") -> Run:
        if len(self.active) >= settings.MAX_CONCURRENT_RUNS:
            current = next(iter(self.active.values()))
            raise BusyError(current.id, current.created_at)
        reg = settings.registry()
        resolved = reg.resolve(model)                       # explicit provider from the registry, never guessed
        provider = resolved.provider
        key_env = provider.api_key_env
        server_key = os.environ.get(key_env, "").strip() if key_env else ""
        effective_key = model_key or server_key
        run = Run(txn_hash, chain, resolved.id, "custom" if rpc_url else "server",
                  "user" if model_key else ("server" if server_key else "none"))
        run.provider = provider.id
        run.key_check = key_check
        run.redactor = Redactor(*self._secrets(reg, model_key, effective_key, rpc_url, resolved))
        self.runs[run.id] = run
        self.active[run.id] = run
        self._prune()
        self._write_meta(run)
        self._event(run, "Run accepted", "info")
        asyncio.get_running_loop().create_task(self._supervise(run, self._worker_env(reg, provider, effective_key, rpc_url)))
        return run

    @staticmethod
    def _secrets(reg, model_key, effective_key, rpc_url, resolved):
        """Everything that must never appear in logs, errors, stored metadata or API responses."""
        out = [model_key, effective_key, rpc_url, os.environ.get("ETHERSCAN_API_KEY", "").strip(), settings.ACCESS_CODE]
        out += [os.environ.get(n, "").strip() for n in reg.all_key_envs()]      # server-held keys of every provider
        for provider in reg.providers.values():                                   # private endpoints are sensitive too
            if provider.type == "openai_compatible" and not provider.public_endpoint:
                out.append((provider.base_url or os.environ.get(provider.base_url_env or "", "")).strip().rstrip("/"))
        out.append(resolved.host or "")
        return out

    @staticmethod
    def _worker_env(reg, provider, effective_key, rpc_url):
        """The worker gets only what this run needs: one provider key, no access code, no other providers' keys."""
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONPATH=str(settings.ROOT), FAULTSEEKER_ISOLATED_RUN="1")
        for name in reg.all_key_envs() + ["FAULTSEEKER_ACCESS_CODE", "FAULTSEEKER_SESSION_SECRET"]:
            env.pop(name, None)
        if provider.api_key_env and effective_key:
            env[provider.api_key_env] = effective_key
        if rpc_url:
            env["FAULTSEEKER_RPC_URL"] = rpc_url
        else:
            env.pop("FAULTSEEKER_RPC_URL", None)
        return env

    def get(self, run_id: str) -> Optional[Run]:
        if not RUN_ID_RE.match(run_id or ""):
            return None
        if run_id in self.runs:
            return self.runs[run_id]
        return self._load(run_id)

    def _load(self, run_id: str) -> Optional[Run]:
        d = self._dir(run_id)
        try:
            meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        run = Run(meta["txn_hash"], meta["chain"], meta["model"], meta.get("rpc_mode", "server"),
                  meta.get("key_source", "none"))
        run.id = run_id
        for key in ("state", "created_at", "finished_at", "last_activity_at", "error", "stages", "current", "summary", "provider", "key_check"):
            if key in meta:
                setattr(run, key, meta[key])
        try:
            run.events = [json.loads(x) for x in (d / "events.jsonl").read_text(encoding="utf-8").splitlines() if x]
        except (OSError, ValueError):
            run.events = []
        try:
            run.logs = (d / "logs.txt").read_text(encoding="utf-8").splitlines()[-settings.MAX_LOG_LINES_MEMORY:]
        except OSError:
            run.logs = []
        self.runs[run_id] = run
        return run

    def result(self, run_id: str, raw: bool = False) -> Optional[dict]:
        if not RUN_ID_RE.match(run_id or ""):
            return None
        path = self._dir(run_id) / ("result.raw.json" if raw else "result.json")
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def history(self, limit: int = 50) -> List[dict]:
        items = []
        for d in settings.RUNS_DIR.glob("*/meta.json"):
            try:
                meta = json.loads(d.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            live = self.runs.get(meta.get("id"))
            if live:
                meta = live.meta()
            items.append({k: meta.get(k) for k in ("id", "txn_hash", "chain", "model", "state", "created_at",
                                                    "finished_at", "summary", "error")})
        items.sort(key=lambda m: m.get("created_at") or 0, reverse=True)
        return items[:limit]

    def known_hashes(self) -> List[dict]:
        seen, out = set(), []
        for item in self.history(200):
            if item["txn_hash"] not in seen:
                seen.add(item["txn_hash"])
                out.append({"hash": item["txn_hash"], "chain": item["chain"]})
        replay = settings.ROOT / "data" / "cache" / "replay"
        if replay.exists():
            for f in sorted(replay.glob("0x*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)[:50]:
                h = f.stem.lower()
                if h not in seen:
                    seen.add(h)
                    out.append({"hash": h, "chain": ""})
        return out

    async def cancel(self, run: Run) -> bool:
        if run.state != "running":
            return False
        run.cancel_requested = True
        self._event(run, "Cancellation requested", "warn")
        await self._kill(run)
        return True

    async def shutdown(self):
        for run in list(self.active.values()):
            run.shutting_down = True
            await self._kill(run)

    # -- supervision -------------------------------------------------------------------------------
    async def _kill(self, run: Run):
        proc = run.proc
        if not proc or proc.returncode is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            return
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def _event(self, run: Run, message: str, level: str = "info"):
        now = time.time()
        run.last_activity_at = now
        run.events.append({"seq": len(run.events) + 1, "ts": now, "level": level, "message": message})

    def _log(self, run: Run, line: str):
        line = run.redactor.clean(line.rstrip("\r\n"))[:settings.MAX_LOG_LINE_CHARS]
        run.logs.append(line)
        if len(run.logs) > settings.MAX_LOG_LINES_MEMORY:
            drop = len(run.logs) - settings.MAX_LOG_LINES_MEMORY
            del run.logs[:drop]
            run.log_offset += drop
        if run.log_bytes < settings.MAX_LOG_FILE_BYTES:
            run.log_bytes += len(line) + 1
            with open(self._dir(run.id) / "logs.txt", "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def _set_stage(self, run: Run, stage_id: str, status: str):
        idx = progress.STAGE_INDEX[stage_id]
        for i, stage in enumerate(run.stages):
            if i < idx and stage["status"] != "done":
                stage["status"] = "done"
        run.stages[idx]["status"] = status

    def _apply(self, run: Run, update: progress.Update):
        if update.complete_stage:
            self._set_stage(run, update.complete_stage, "done")
        else:
            self._set_stage(run, update.stage, "active")
        run.current = {"title": update.title, "description": update.description}
        if update.activity:
            self._event(run, update.activity, "info")
        else:
            run.last_activity_at = time.time()

    def _handle_line(self, run: Run, line: str):
        line = run.redactor.clean(line)
        if line.startswith(MARKER):
            try:
                payload = json.loads(line[len(MARKER):].strip())
            except ValueError:
                return
            event = payload.get("event")
            if event == "start":
                self._set_stage(run, "collect", "active")
                run.current = {"title": "Pipeline started", "description": "Preparing to fetch the transaction."}
                self._event(run, "Pipeline started", "info")
            elif event == "result":
                run.result_ready = True
            elif event == "error":
                run.worker_error = payload
            return
        self._log(run, line)
        stripped = line.strip()
        update = progress.parse_line(stripped)
        if update:
            self._apply(run, update)
        m = progress.CAST_ERROR.match(stripped)
        if m:
            run.cast_error = m.group(2)[:400]
            self._event(run, "Transaction replay reported an error", "error")
        if progress.EXPLORER_ERROR.match(stripped):
            run.explorer_error = stripped[:300]
            self._event(run, "Explorer lookup failed", "error")
        if progress.CONNECTION_ERROR.match(stripped):
            run.connection_errors += 1
            if run.connection_errors >= progress.CONNECTION_ERROR_LIMIT and not run.fatal:
                run.fatal = dict(progress.PROVIDER_UNREACHABLE)
                self._event(run, run.fatal["message"], "error")
                asyncio.get_running_loop().create_task(self._kill(run))
        if progress.MODEL_ERROR.match(stripped):
            run.model_errors += 1
            if run.model_errors == 1:
                self._event(run, "A model request failed", "warn")
        for pattern, code, message, hint in progress.FATAL_PATTERNS:
            # Only provider exception lines count; the same words inside logged source code must not.
            if progress.MODEL_ERROR.match(stripped) and pattern.search(stripped) and not run.fatal:
                run.fatal = {"code": code, "message": message, "hint": hint}
                self._event(run, message, "error")
                asyncio.get_running_loop().create_task(self._kill(run))

    async def _supervise(self, run: Run, env: dict):
        out_path = self._dir(run.id) / "result.raw.json"
        cmd = [sys.executable, "-u", "-m", settings.WORKER_MODULE, "--hash", run.txn_hash,
               "--chain", run.chain, "--model", run.model, "--out", str(out_path)]
        timed_out = False
        try:
            run.proc = await asyncio.create_subprocess_exec(
                *cmd, cwd=str(settings.ROOT), env=env, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, start_new_session=True, limit=settings.MAX_LINE_BYTES)

            async def pump():
                async for raw in run.proc.stdout:
                    self._handle_line(run, raw.decode("utf-8", errors="replace"))
                await run.proc.wait()

            try:
                await asyncio.wait_for(pump(), timeout=settings.RUN_TIMEOUT_SECONDS)
            except asyncio.TimeoutError:
                timed_out = True
                await self._kill(run)
        except Exception as exc:  # noqa: BLE001
            started = run.proc is not None
            run.worker_error = {"type": type(exc).__name__,
                                "message": (f"Lost the worker's output stream: {exc}" if started
                                            else f"Could not start the analysis worker: {exc}")}
            await self._kill(run)   # never leave a worker running once the run is finished
        finally:
            await self._drain(run)
            self._finish(run, timed_out)

    @staticmethod
    async def _drain(run: Run):
        """After a kill the output pipe may still hold unread data; reading it to EOF lets asyncio close the transport."""
        if run.proc is None or run.proc.stdout is None:
            return
        try:
            await asyncio.wait_for(run.proc.stdout.read(), timeout=2)
        except Exception:    # noqa: BLE001 - best effort; the process is already dead
            pass

    def _finish(self, run: Run, timed_out: bool):
        rc = run.proc.returncode if run.proc else None
        run.finished_at = time.time()
        if run.shutting_down:
            run.state = "interrupted"
            run.error = {"code": "interrupted", "message": "The server restarted while this run was in progress.",
                         "hint": "Start the analysis again. Cached replays and contracts are reused."}
            run.current = {"title": "Run interrupted", "description": run.error["message"]}
        elif run.cancel_requested:
            run.state = "cancelled"
            run.current = {"title": "Run cancelled", "description": "The analysis was stopped before it finished."}
            self._event(run, "Run cancelled", "warn")
        elif timed_out:
            run.state = "failed"
            run.error = {"code": "timeout", "message": "The analysis exceeded the time limit and was stopped.",
                         "hint": "Try a smaller transaction or raise FAULTSEEKER_RUN_TIMEOUT."}
        elif run.fatal:
            run.state, run.error = "failed", run.fatal
        elif rc == 0 and run.result_ready:
            raw = self.result(run.id, raw=True)
            if raw is None:
                run.state = "failed"
                run.error = {"code": "result_missing", "message": "The analysis finished but its result could not be read.",
                             "hint": "Check the technical logs and run again."}
            else:
                normalized = results.normalize(raw, model_errors=run.model_errors)
                (self._dir(run.id) / "result.json").write_text(json.dumps(normalized), encoding="utf-8")
                run.state = "completed"
                for stage in run.stages:
                    stage["status"] = "done"
                top = normalized["ranking"][0]["function"] if normalized["ranking"] else None
                run.summary = {"findings": len(normalized["ranking"]), "top_function": top,
                               "warnings": len(normalized["warnings"]), "duration": normalized.get("duration")}
                run.current = {"title": "Report ready", "description": "The analysis finished."}
                self._event(run, "Report ready", "success")
        else:
            run.state, run.error = "failed", self._classify_failure(run, rc)
            active = next((s for s in run.stages if s["status"] == "active"), None)
            if active:
                active["status"] = "failed"
            run.current = {"title": "Analysis failed", "description": run.error["message"]}
            self._event(run, run.error["message"], "error")
        self.active.pop(run.id, None)
        self._write_meta(run)
        ev = self._dir(run.id) / "events.jsonl"
        ev.write_text("\n".join(json.dumps(e) for e in run.events), encoding="utf-8")

    def _classify_failure(self, run: Run, rc) -> dict:
        err = run.worker_error or {}
        message = err.get("message", "")
        if err.get("type") == "ProviderConfigError":
            return {"code": "provider_not_configured", "message": message,
                    "hint": "The operator needs to set the environment variables named above, then run again."}
        if run.cast_error and ("Stage 1" in message or not message or "Forensics" in message):
            detail = run.cast_error
            hint = ("Replaying older transactions needs an archive-capable RPC. Provide one under "
                    "“RPC connection”, then run again.")
            return {"code": "rpc_failed", "message": f"Transaction replay failed: {detail}", "hint": hint}
        if run.explorer_error and "Stage 1" in message:
            return {"code": "explorer_unavailable", "message": run.explorer_error,
                    "hint": "The explorer page could not be read. Confirm the hash is on the selected network and that "
                            "it succeeded; if the server is being blocked, set FAULTSEEKER_HTTP_PROXY."}
        if "Stage 1" in message:
            return {"code": "no_forensics", "message": "Transaction data could not be collected.",
                    "hint": "Check the network selection and RPC connection, and that the transaction succeeded."}
        if message:
            return {"code": "pipeline_error", "message": message, "hint": "See the technical logs for the full trace."}
        return {"code": "worker_crashed",
                "message": f"The analysis worker stopped unexpectedly (exit code {rc}).",
                "hint": "See the technical logs, then run again."}

    # -- views -------------------------------------------------------------------------------------
    def view(self, run: Run, after_event: int = 0, after_log: int = 0) -> dict:
        events = [e for e in run.events if e["seq"] > after_event]
        start = max(after_log - run.log_offset, 0)
        logs = run.logs[start:]
        return {"run": run.meta(), "server_time": time.time(), "events": events,
                "event_cursor": run.events[-1]["seq"] if run.events else 0,
                "logs": logs, "log_cursor": run.log_offset + len(run.logs)}
