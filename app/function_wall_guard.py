"""Record how each FunctionAnalyzer function-analysis loop actually ended, without editing the fork.

The pinned fork stops a function's loop once 480s have passed and returns the partial
candidates with no truncation flag. A completion marker therefore does not prove the
function analysis finished. Rule here: an exit counts as "normal" ONLY when a positive
fork exit is observed:
  adequate          the adequacy check (fork prompt, matched by prefix) answered yes
  iteration_ceiling the number of fully completed cycles reached the fork's ceiling
Anything else is never inferred normal from elapsed time:
  likely_forced     not positively normal and wall time (time.time or monotonic) exceeded the cap
  unknown_exit      not positively normal, under the cap (empty-selection skips, exception breaks...)
  error             the analysis raised
Every non-normal outcome makes the run partial.
"""
import re
import threading
import time

FORK_FUNCTION_WALL_CAP_SECS = 480        # pinned by a test against the fork source
FORK_CLOUD_PREFIXES = ('gpt-', 'gemini-', 'grok-', 'qwen-', 'qwen/', 'claude-', 'o1-', 'o3-', 'o4-',
                       'agnes', 'jev', 'laguna', 'nemotron', 'minimax', 'llama-', 'openai/', 'allam-',
                       'z-ai/', 'deepseek-ai/', 'nvidia/', 'gla/')   # pinned by a test
_YES = re.compile(r"(?i)\s*yes[\s.!]*")


def fork_iteration_ceiling(model, kind):
    cloud = any(str(model).startswith(p) for p in FORK_CLOUD_PREFIXES)
    if kind == "function":
        return 3 if cloud else 8
    return 2 if cloud else 3


def classify(positive_exit, completed_cycles, ceiling, elapsed_wall, elapsed_mono, cap=FORK_FUNCTION_WALL_CAP_SECS):
    if positive_exit == "adequate":
        return "normal", "adequate"
    if completed_cycles >= ceiling:
        return "normal", "iteration_ceiling"
    if max(elapsed_wall, elapsed_mono) > cap:
        return "likely_forced", None
    return "unknown_exit", None


class WallCapLedger:
    def __init__(self, wall=None, mono=None):
        self._lock = threading.Lock()
        self.records = []
        self.active = {}          # id(analyzer) -> state
        self.wall = wall or (lambda: time.time())   # resolve at call time: same clock the fork reads
        self.mono = mono or (lambda: time.monotonic())

    def add(self, record):
        with self._lock:
            self.records.append(record)

    def summary(self):
        with self._lock:
            recs = list(self.records)
        count = lambda o: sum(r["outcome"] == o for r in recs)
        return {"cap_secs": FORK_FUNCTION_WALL_CAP_SECS, "functions": recs, "normal": count("normal"),
                "likely_forced": count("likely_forced"), "unknown_exit": count("unknown_exit"),
                "error": count("error")}

    def wrap_update(self, original):
        """Class-level patch: counts fully completed cycles only for registered analyzers."""
        ledger = self
        def wrapped(analyzer, *a, **k):
            r = original(analyzer, *a, **k)
            st = ledger.active.get(id(analyzer))
            if st is not None:
                st["completed"] += 1
            return r
        return wrapped

    def wrap(self, original, kind):
        ledger = self

        def wrapped(analyzer, *args, **kwargs):
            key = id(analyzer)
            model = getattr(analyzer, "txn_analyzer_model", "")
            st = {"completed": 0, "exit": None, "ceiling": fork_iteration_ceiling(model, kind)}
            prompts = getattr(analyzer, "function_prompts", None)
            prefix = getattr(prompts, "check_analysis_adequacy" if kind == "function" else "check_analysis_adequacy_alt", None)
            agent = getattr(analyzer, "organization_agent", None)
            hooked = False
            if isinstance(prefix, str) and agent is not None and "query" not in vars(agent) and hasattr(agent, "query"):
                query = agent.query
                def counted(prompt, *a, **k):
                    r = query(prompt, *a, **k)
                    try:
                        if str(prompt).startswith(prefix) and r and _YES.fullmatch(str(r)):
                            st["exit"] = "adequate"
                    except Exception:
                        pass
                    return r
                try:
                    agent.query = counted
                    hooked = True
                except Exception:
                    hooked = False
            with ledger._lock:
                ledger.active[key] = st
            info = getattr(analyzer, "function_call_info_summary", None) or {}
            label = f"{info.get('function', '?')}@{info.get('address', '?')}"
            w0, m0 = ledger.wall(), ledger.mono()
            try:
                result = original(analyzer, *args, **kwargs)
            except BaseException as exc:
                ledger.add({"kind": kind, "function": label, "outcome": "error", "detail": type(exc).__name__,
                            "elapsed_wall_secs": round(ledger.wall() - w0, 1), "elapsed_mono_secs": round(ledger.mono() - m0, 1),
                            "completed_cycles": st["completed"]})
                raise
            finally:
                with ledger._lock:
                    ledger.active.pop(key, None)
                if hooked:
                    try:
                        del agent.query
                    except Exception:
                        pass
            ew, em = ledger.wall() - w0, ledger.mono() - m0
            outcome, detail = classify(st["exit"], st["completed"], st["ceiling"], ew, em)
            ledger.add({"kind": kind, "function": label, "outcome": outcome, "detail": detail,
                        "elapsed_wall_secs": round(ew, 1), "elapsed_mono_secs": round(em, 1),
                        "completed_cycles": st["completed"], "ceiling": st["ceiling"]})
            return result
        return wrapped
