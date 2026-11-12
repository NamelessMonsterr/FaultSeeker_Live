"""Turns pipeline stdout into stage progress. Only real pipeline output moves the stepper."""
import re
from dataclasses import dataclass
from typing import Optional

STAGES = [
    {"id": "collect", "label": "Collect transaction"},
    {"id": "trace", "label": "Analyze trace"},
    {"id": "actors", "label": "Classify addresses"},
    {"id": "rank", "label": "Rank functions"},
    {"id": "analyze", "label": "Analyze functions"},
    {"id": "report", "label": "Compile report"},
]
STAGE_INDEX = {s["id"]: i for i, s in enumerate(STAGES)}


@dataclass
class Update:
    stage: str                 # stage that becomes active
    title: str
    description: str
    activity: Optional[str] = None
    complete_stage: Optional[str] = None   # stage that is finished by this line


_RULES = [
    (re.compile(r"Collecting transaction sequence"),
     Update("collect", "Replaying the transaction",
            "Replaying it with Foundry against the RPC endpoint to rebuild the call trace.",
            "Replaying transaction to rebuild its call trace")),
    (re.compile(r"Collecting transaction info"),
     Update("collect", "Reading the explorer record",
            "Fetching status, block and token transfers from the block explorer page.",
            "Reading transaction record from the block explorer")),
    (re.compile(r"Analyzing execution trace"),
     Update("trace", "Analyzing the execution trace",
            "The model is reading the call trace for flash loans, callbacks and repeated patterns.",
            "Execution trace collected; analyzing call patterns")),
    (re.compile(r"Classifying addresses"),
     Update("actors", "Classifying addresses and fund flow",
            "Separating attacker, victim and protocol addresses and measuring balance changes.",
            "Classifying addresses and tracing fund flow")),
    (re.compile(r"Identifying vulnerable functions"),
     Update("actors", "Selecting functions to inspect",
            "Choosing the calls that moved funds or changed state for deeper review.",
            "Selecting functions to inspect")),
    (re.compile(r"Forensics analysis completed"),
     Update("actors", "Forensics complete", "Stage 1 finished. Preparing the function ranking.",
            "Transaction-level forensics finished", complete_stage="actors")),
    (re.compile(r"Ranking suspicious functions"),
     Update("rank", "Ranking suspicious functions",
            "Filtering out read-only and standard functions to focus on custom logic.",
            "Ranking suspicious functions")),
    (re.compile(r"Ranking completed - (\d+) addresses"),
     Update("rank", "Ranking complete", "Queued addresses for source-level analysis.",
            None, complete_stage="rank")),
    (re.compile(r"Downloading contract source code"),
     Update("analyze", "Downloading contract source",
            "Fetching verified source for the addresses queued for analysis.",
            "Downloading verified contract source")),
    (re.compile(r"Reviewing function calls"),
     Update("analyze", "Reviewing function calls",
            "The model is narrowing the calls and reasoning about each candidate function.",
            "Reviewing function calls")),
    (re.compile(r"Function analysis completed"),
     Update("analyze", "Function analysis complete", "Compiling the ranked report.",
            "Function-level analysis finished", complete_stage="analyze")),
]
_PROGRESS = re.compile(r"\[(\d+)/(\d+)\]\s+Analyzing\s+(.+?)(?:\s*\(created contract param\))?\.\.\.")
_COUNT = re.compile(r"Ranking completed - (\d+) addresses")


def parse_line(line: str) -> Optional[Update]:
    text = line.strip()
    if not text:
        return None
    m = _PROGRESS.search(text)
    if m:
        i, n, name = m.group(1), m.group(2), m.group(3)
        return Update("analyze", f"Analyzing function {i} of {n}", f"Reading {name} against the collected evidence.",
                      f"Analyzing {name} ({i}/{n})")
    for pattern, update in _RULES:
        mm = pattern.search(text)
        if mm:
            if update.stage == "rank" and update.complete_stage == "rank":
                c = _COUNT.search(text)
                return Update(update.stage, update.title, update.description,
                              f"Ranking finished: {c.group(1)} address(es) queued" if c else None,
                              complete_stage="rank")
            return update
    return None


# ---- failure signals found in output -------------------------------------------------------------
_PARAM_WORDS = (r"(unsupported|unrecognized|unknown|not supported|invalid)[^\n]{0,60}(parameter|argument|value)"
                r"|temperature|max_tokens|max_completion_tokens|reasoning_effort|top_p")
FATAL_PATTERNS = [
    (re.compile(r"AuthenticationError|Incorrect API key|invalid_api_key", re.I), "model_key_rejected",
     "The model provider rejected the API key.",
     "Check that the key belongs to the selected provider and is active, then run again."),
    (re.compile(r"insufficient_quota|exceeded your current quota", re.I), "model_quota",
     "The model provider reports no remaining quota for this key.",
     "Add credit or use a different key, then run again."),
    (re.compile(r"PermissionDeniedError", re.I), "provider_forbidden",
     "The model provider refused access for this key or location.",
     "Check the key's permissions and the provider's access rules, then run again."),
    (re.compile(r"NotFoundError", re.I), "model_not_found",
     "The provider does not know the configured model ID or endpoint.",
     "The operator should check the model ID and base URL for this provider."),
    (re.compile(r"(BadRequestError|UnprocessableEntityError)[^\n]*(" + _PARAM_WORDS + ")", re.I), "provider_parameter_rejected",
     "The provider rejected a request parameter configured for this model.",
     "The run was stopped, not retried. The operator should adjust this model's params in config/models.json."),
]
PROVIDER_UNREACHABLE = {"code": "provider_unreachable", "message": "The model provider could not be reached.",
                        "hint": "Check the provider's base URL and status, then run again. Requests are not retried automatically."}
CONNECTION_ERROR = re.compile(r"^openai\.(APIConnectionError|APITimeoutError|InternalServerError)")
CONNECTION_ERROR_LIMIT = 3
MODEL_ERROR = re.compile(r"^(openai\.\w*(Error|Exception)|ollama\._types\.\w*Error|httpx\.\w+Error)")
CAST_ERROR = re.compile(r"^cast exited with code (\d+): ?(.*)$")
EXPLORER_ERROR = re.compile(r"^(Explorer request failed|Explorer page did not report)")
