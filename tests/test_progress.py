"""Progress parsing is checked against the pipeline's real print statements, read from its source."""
import re
from pathlib import Path

import pytest

from faultseeker.server import progress

PKG = Path(progress.__file__).resolve().parents[1]
SOURCES = ["core/pipeline.py", "forensics/orchestrator.py", "function_analysis/function_analyzer.py"]


def real_progress_lines():
    """Concrete example output for every f-string/str print() that carries a progress arrow or tick."""
    lines = []
    for rel in SOURCES:
        for m in re.finditer(r'print\(\s*f?(["\'])(.*?)\1\s*\)', (PKG / rel).read_text(encoding="utf-8")):
            text = m.group(2).encode().decode("unicode_escape", errors="ignore") if "\\n" in m.group(2) else m.group(2)
            text = text.replace("\\n", "")
            if any(sym in text for sym in ("→", "✓", "[Stage")) or "[{current}/" in text:
                text = re.sub(r"\{len\([^}]*\)\}", "3", text)
                text = re.sub(r"\{current\}", "1", text)
                text = re.sub(r"\{total_functions\}", "4", text)
                text = re.sub(r"\{(function|function_name)\}", "transfer", text)
                lines.append(text)
    return lines


def test_source_scan_finds_the_expected_lines():
    lines = real_progress_lines()
    assert len(lines) >= 16, lines
    assert any("Ranking completed - 3 addresses" in l for l in lines)
    assert any("[1/4] Analyzing transfer..." in l for l in lines)


def test_every_pipeline_milestone_is_mapped():
    """If someone rewords a pipeline print, the stepper would silently stall. This catches that."""
    expectations = {
        "Collecting transaction sequence": "collect", "Collecting transaction info": "collect",
        "Analyzing execution trace": "trace", "Classifying addresses": "actors",
        "Identifying vulnerable functions": "actors", "Forensics analysis completed": "actors",
        "Ranking suspicious functions": "rank", "Ranking completed": "rank",
        "Downloading contract source code": "analyze", "Reviewing function calls": "analyze",
        "Function analysis completed": "analyze",
    }
    lines = real_progress_lines()
    for phrase, stage in expectations.items():
        match = [l for l in lines if phrase in l]
        assert match, f"pipeline no longer prints '{phrase}'"
        update = progress.parse_line(match[0])
        assert update is not None and update.stage == stage, (phrase, update)


def test_function_progress_and_completion_flags():
    u = progress.parse_line("         [2/5] Analyzing withdraw (created contract param)...")
    assert (u.stage, u.title) == ("analyze", "Analyzing function 2 of 5") and "withdraw" in u.activity
    assert "(created" not in u.activity
    assert progress.parse_line("[1/1] Analyzing repeated pattern...").activity == "Analyzing repeated pattern (1/1)"
    done = progress.parse_line("   ✓ Ranking completed - 7 addresses to analyze")
    assert done.complete_stage == "rank" and "7 address" in done.activity
    assert progress.parse_line("   ✓ Forensics analysis completed").complete_stage == "actors"
    assert progress.parse_line("   ✓ Function analysis completed").complete_stage == "analyze"


@pytest.mark.parametrize("line", ["", "   ", "functions to be analyzed: {'a': 1}", "→ Analyzing vulnerable functions...",
                                  "Gas Usage Summary:", "Traceback (most recent call last):"])
def test_unrelated_lines_do_not_move_the_stepper(line):
    assert progress.parse_line(line) is None


def test_failure_signal_patterns():
    assert progress.MODEL_ERROR.match("openai.AuthenticationError: Error code: 401")
    assert progress.MODEL_ERROR.match("openai.RateLimitError: Error code: 429")
    assert not progress.MODEL_ERROR.match("  File \"x.py\", line 1, in openai.AuthenticationError")
    m = progress.CAST_ERROR.match("cast exited with code 1:  | Context: | - Error #0: dns")
    assert m and m.group(1) == "1" and "dns" in m.group(2)
    assert progress.EXPLORER_ERROR.match("Explorer request failed (curl exit 6): x")
    assert progress.EXPLORER_ERROR.match("Explorer page did not report a successful transaction (status: unknown).")
    codes = {code for _, code, _, _ in progress.FATAL_PATTERNS}
    assert codes == {"model_key_rejected", "model_quota"}


def test_stage_table_matches_what_the_frontend_expects():
    assert [s["id"] for s in progress.STAGES] == ["collect", "trace", "actors", "rank", "analyze", "report"]
    js = (PKG.parent / "web/assets/console.js").read_text()
    assert "repeat(6" in (PKG.parent / "web/assets/console.css").read_text()
    assert "stages" in js
