"""F1 (finalization / admission) and F2 (cancel before spawn) for server/runs.py. OFFLINE: the stand-in worker only.

Each test drives a RunManager directly on its own event loop, so it can interleave start / cancel / shutdown exactly.
Cancellation policy (documented in runs.py): the LAST decision wins. A cancel accepted while the run is still "running"
- including after the worker exited successfully but before finalization ran - makes the run "cancelled".
Terminal precedence: shutting_down > cancel_requested > timeout > fatal > result.
"""
import asyncio
import json
import pathlib

import pytest

from tests.conftest import HASH, USER_KEY

HANG = "0x" + "4a49" + "0" * 60


def make_manager(make_client, **env):
    make_client(**env)                         # applies env, reloads server modules; its own app manager stays idle
    from faultseeker.server import runs
    return runs, runs.RunManager()


def begin(mgr, txn=HASH):
    return mgr.start(txn_hash=txn, chain="bsc", model="gpt-4o-mini", model_key=USER_KEY, rpc_url="")


async def until(predicate, timeout=10.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return False


async def until_final(run, timeout=10.0):
    return await until(lambda: run.state != "running", timeout)


def spawn_counter(monkeypatch, on_spawn=None):
    calls = []
    original = asyncio.create_subprocess_exec

    async def counting(*args, **kwargs):
        calls.append(args)
        if on_spawn:
            on_spawn()
        return await original(*args, **kwargs)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", counting)
    return calls


def dead(pid):
    try:
        text = pathlib.Path(f"/proc/{pid}/status").read_text()
    except OSError:
        return True
    return "Z" in text.split("State:")[1].split()[0]


def messages(run):
    return [e["message"] for e in run.events]


# ---------------------------------------------------------------------------------------------- F1

def test_normalize_failure_ends_failed_and_frees_admission(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)

    def boom(raw, **kw):
        raise ValueError("unexpected result shape")
    monkeypatch.setattr(runs.results, "normalize", boom)

    async def scenario():
        run = begin(mgr)
        assert await until_final(run, 8), "run stranded in 'running' after a finalization error"
        assert run.state == "failed" and run.error["code"] == "result_processing_failed"
        assert run.finished_at is not None and run.state != "running"
        assert mgr.active == {}, "admission must be released"
        on_disk = json.loads((runs.settings.RUNS_DIR / run.id / "meta.json").read_text())
        assert on_disk["state"] == "failed"
        assert mgr.result(run.id) is None
        second = begin(mgr)                                     # not BusyError
        assert await until_final(second, 8)
    asyncio.run(scenario())


def test_result_write_failure_ends_failed_and_frees_admission(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)
    real = pathlib.Path.write_text

    def flaky(self, *a, **k):
        if self.name.startswith("result.json"):
            raise OSError(28, "No space left on device")
        return real(self, *a, **k)
    monkeypatch.setattr(pathlib.Path, "write_text", flaky)

    async def scenario():
        run = begin(mgr)
        assert await until_final(run, 8)
        assert run.state == "failed" and run.error["code"] == "result_processing_failed"
        assert "No space" in run.error["message"] or "result" in run.error["message"].lower()
        assert mgr.active == {}
        assert not (runs.settings.RUNS_DIR / run.id / "result.json").exists(), "no half-written result is left behind"
    asyncio.run(scenario())


def test_start_storage_failure_does_not_strand_admission(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)
    real = runs.RunManager._write_meta
    state = {"fail": True}

    def flaky(self, run):
        if state["fail"]:
            state["fail"] = False
            raise OSError(28, "No space left on device")
        return real(self, run)
    monkeypatch.setattr(runs.RunManager, "_write_meta", flaky)

    async def scenario():
        with pytest.raises(OSError):
            begin(mgr)
        assert mgr.active == {} and mgr.runs == {}, "a start() that failed must leave no admission or registry entry"
        run = begin(mgr)                                        # would raise BusyError if admission leaked
        assert await until_final(run, 8) and run.state == "completed"
    asyncio.run(scenario())


def test_start_task_creation_failure_does_not_strand_admission(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)

    async def scenario():
        loop = asyncio.get_running_loop()
        real = loop.create_task
        state = {"fail": True}

        def failing(coro, **kw):
            if state["fail"]:
                state["fail"] = False
                coro.close()
                raise RuntimeError("cannot schedule")
            return real(coro, **kw)
        monkeypatch.setattr(loop, "create_task", failing)
        with pytest.raises(RuntimeError):
            begin(mgr)
        assert mgr.active == {}
        run = begin(mgr)
        assert await until_final(run, 8) and run.state == "completed"
    asyncio.run(scenario())


@pytest.mark.parametrize("how,expected", [("cancel", "cancelled"), ("shutdown", "interrupted")])
def test_terminal_precedence_beats_a_failing_result(make_client, monkeypatch, how, expected):
    """cancel_requested / shutting_down outrank the result branch, so a broken normalize() must not turn them into 'failed'."""
    runs, mgr = make_manager(make_client)
    monkeypatch.setattr(runs.results, "normalize", lambda *a, **k: 1 / 0)

    async def scenario():
        run = begin(mgr, HANG)
        assert await until(lambda: run.proc is not None)
        if how == "cancel":
            await mgr.cancel(run)
        else:
            await mgr.shutdown()
        assert await until_final(run, 8)
        assert run.state == expected and mgr.active == {}
    asyncio.run(scenario())


def test_shutdown_awaits_supervisors_and_leaves_nothing_running(make_client):
    runs, mgr = make_manager(make_client)

    async def scenario():
        run = begin(mgr, HANG)
        assert await until(lambda: run.proc is not None)
        pid = run.proc.pid
        await asyncio.wait_for(mgr.shutdown(), 15)
        assert run.state == "interrupted", "shutdown() must return only after the run is finalized"
        assert mgr.active == {} and dead(pid)
    asyncio.run(scenario())


# ---------------------------------------------------------------------------------------------- F2

def test_cancel_before_spawn_never_spawns_the_worker(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)
    spawned = spawn_counter(monkeypatch)

    async def scenario():
        run = begin(mgr)
        assert await mgr.cancel(run) is True                    # accepted before any subprocess exists
        assert await until_final(run, 8)
        await asyncio.sleep(0.3)
        assert spawned == [], "a run cancelled before spawn must not launch a worker"
        assert run.state == "cancelled" and run.proc is None and mgr.active == {}
        assert messages(run).count("Run cancelled") == 1
    asyncio.run(scenario())


def test_cancel_racing_the_spawn_terminates_the_worker_promptly(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)
    holder = {}

    def cancel_during_spawn():
        asyncio.get_running_loop().create_task(mgr.cancel(holder["run"]))      # lands while run.proc is still None
    spawned = spawn_counter(monkeypatch, cancel_during_spawn)

    async def scenario():
        holder["run"] = run = begin(mgr, HANG)
        assert await until_final(run, 10), "worker kept running after a cancel that raced the spawn"
        assert len(spawned) == 1 and run.state == "cancelled"
        assert run.proc is not None and run.proc.returncode is not None
        assert dead(run.proc.pid)
    asyncio.run(scenario())


def test_repeated_and_concurrent_cancel_is_idempotent(make_client):
    runs, mgr = make_manager(make_client)

    async def scenario():
        run = begin(mgr, HANG)
        assert await until(lambda: run.proc is not None)
        results = await asyncio.gather(mgr.cancel(run), mgr.cancel(run), mgr.cancel(run))
        assert results == [True, True, True]
        assert await until_final(run, 8)
        assert run.state == "cancelled"
        assert messages(run).count("Cancellation requested") == 1
        assert messages(run).count("Run cancelled") == 1
        assert await mgr.cancel(run) is False                   # finished: the API answers 409 as before
    asyncio.run(scenario())


def test_shutdown_before_spawn_never_spawns(make_client, monkeypatch):
    runs, mgr = make_manager(make_client)
    spawned = spawn_counter(monkeypatch)

    async def scenario():
        run = begin(mgr)
        await mgr.shutdown()           # awaited directly: wait_for() would wrap it in a task on 3.11 and let the supervisor run first
        assert spawned == [] and run.state == "interrupted" and mgr.active == {}
    asyncio.run(scenario())


def test_late_cancel_wins_over_a_finished_result(make_client, monkeypatch):
    """Documented policy: a cancel accepted before finalization runs wins, even if the worker had already succeeded."""
    runs, mgr = make_manager(make_client)
    original = runs.RunManager._drain

    async def drain_then_cancel(run):
        await original(run)
        await mgr.cancel(run)
    monkeypatch.setattr(runs.RunManager, "_drain", staticmethod(drain_then_cancel))

    async def scenario():
        run = begin(mgr)
        assert await until_final(run, 10)
        assert run.state == "cancelled" and run.error is None
        assert mgr.result(run.id) is None, "the discarded result is not published"
    asyncio.run(scenario())
