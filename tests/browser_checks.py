"""Real Chromium UI regressions with controlled provider/API boundary fixtures.

Run against a local server: python tests/browser_checks.py --url http://127.0.0.1:8421
Requires Playwright and an installed Chrome, or Playwright Chromium.
No live RPC/LLM calls or secrets are used by these browser fixtures.
"""
import argparse
import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

TX = "0x" + "a" * 64
CONFIG = {"chains": ["eth"], "models": [{"id": "no-llm", "label": "Deterministic Stage 1", "keyEnv": None}], "repo_present": True, "live_available": True, "capture_available": True}
REPORT = {"transaction_hash": TX, "chain": "eth", "analysis_status": "completed", "analysis_mode": "no-llm", "stage_completed": "stage-1", "scored_functions": [{"function": "<img src=x onerror=alert(1)>", "evidence": ["Observed function call"]}], "limitations": ["Controlled browser test fixture"]}


def event(number, kind, value):
    return f"id: {number}\nevent: {kind}\ndata: {json.dumps(value)}\n\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8421")
    parser.add_argument("--artifacts", default=os.path.join(os.environ.get("TEMP", "/tmp"), "faultseeker-browser-qa"))
    args = parser.parse_args()
    artifacts = Path(args.artifacts)
    artifacts.mkdir(parents=True, exist_ok=True)
    passed = []
    errors = []
    with sync_playwright() as p:
        chrome = Path("C:/Program Files/Google/Chrome/Application/chrome.exe")
        browser = p.chromium.launch(headless=True, **({"executable_path": str(chrome)} if chrome.exists() else {}))
        context = browser.new_context(viewport={"width": 1440, "height": 1000})
        page = context.new_page()
        page.on("pageerror", lambda error: errors.append(str(error)))
        state = {"complete": False, "cancelled": False, "submitted": 0, "model_wait": True, "partial": False}
        def fixture(route):
            path = route.request.url.split("/api/")[-1].split("?")[0]
            if path == "config":
                return route.fulfill(json=CONFIG)
            if path == "analyze":
                state["submitted"] += 1
                return route.fulfill(json={"run_id": "browserqa"})
            if path.startswith("stream/"):
                if state["cancelled"]:
                    body = event(8, "error", "Analysis cancelled by user") + event(9, "end", {})
                elif state["complete"]:
                    body = event(8, "end", {})
                elif state["model_wait"]:
                    body = event(1, "model_status", {"state": "waiting_on_model_endpoint", "phase": "preflight", "http_status": 502, "retry_in_seconds": 2})
                else:
                    body = "".join(event(i + 2, "stage", {"index": i}) for i in range(5)) + event(7, "log", "Long technical output " + "x" * 6000)
                return route.fulfill(content_type="text/event-stream", body=body)
            if path.startswith("result/"):
                if state["partial"]:
                    return route.fulfill(json={**REPORT, "analysis_mode": "live-pipeline", "analysis_status": "partial", "scored_functions": [], "classification": {"rule_verdict": "INCONCLUSIVE"},
                        "sections": {"deterministic_checks": "completed", "function_analysis": "failed", "scoring": "skipped"},
                        "model_endpoint": {"failure": {"kind": "upstream_http", "http_status": 502, "message": "Model endpoint returned an upstream HTTP error. HTTP 502."}}})
                return route.fulfill(json=REPORT)
            if path.startswith("status/"):
                return route.fulfill(json={"status": "cancelled" if state["cancelled"] else "completed" if state["complete"] else "running"})
            if path.startswith("cancel/"):
                state["cancelled"] = True
                return route.fulfill(json={"cancelled": True})
            if path == "runs":
                return route.fulfill(json={"runs": [{"run_id": "browserqa", "status": "completed", "model": "no-llm", "txn_hash": TX}]})
            return route.continue_()
        page.route("**/api/**", fixture)
        page.goto(args.url)
        expect(page.locator("#analyze")).to_be_enabled()
        page.screenshot(path=str(artifacts / "setup-desktop.png"), full_page=True)
        page.locator("#analyze").click()
        assert state["submitted"] == 0, "Invalid hash must never reach analyze"
        passed.append("setup and native form validation")
        page.locator("#transaction").fill(TX)
        page.locator(".rpc summary").click()
        page.locator("#rpc-url").fill("https://provider.example/DUMMY_REQUEST_SECRET")
        page.locator("#rpc-key").fill("DUMMY_REQUEST_SECRET")
        page.locator("#analyze").click()
        expect(page.locator("#running")).to_be_visible()
        expect(page.locator("#active-task")).to_have_text("Waiting on model endpoint")
        expect(page.locator("#active-description")).to_contain_text("Retrying in 2s")
        page.screenshot(path=str(artifacts / "model-wait-preview.png"), full_page=True)
        passed.append("explicit endpoint preflight/retry status with no false stage completion")
        state["model_wait"] = False
        page.reload()
        expect(page.locator("#active-task")).to_have_text("Function analysis")
        expect(page.locator("#stepper li").last).to_contain_text("Pending")
        page.locator(".technical summary").click()
        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
        page.screenshot(path=str(artifacts / "analysis-desktop.png"), full_page=True)
        assert "DUMMY_REQUEST_SECRET" not in page.evaluate("JSON.stringify({...sessionStorage,...localStorage})")
        passed.append("real EventSource progress, pending final stage, bounded long logs and credential storage")
        for width in [360, 768]:
            page.set_viewport_size({"width": width, "height": 900})
            assert not page.evaluate("document.documentElement.scrollWidth > innerWidth"), f"Overflow at {width}px"
            page.screenshot(path=str(artifacts / f"analysis-{width}.png"), full_page=True)
        passed.append("360px and 768px responsive layouts")
        state["complete"] = True
        page.reload()
        expect(page.locator("#results")).to_be_visible()
        expect(page.locator("#results h1")).to_have_text("Investigation report")
        assert page.locator("#results img").count() == 0
        assert "<img src=x onerror=alert(1)>" in page.locator("#results").inner_text()
        page.screenshot(path=str(artifacts / "report-mobile.png"), full_page=True)
        passed.append("reload recovery, raw-schema completion, XSS-safe evidence, no blank result screen")
        page.locator("#history-button").click()
        expect(page.locator("#history")).to_be_visible()
        page.get_by_role("button", name="View report", exact=True).click()
        expect(page.locator("#results")).to_be_visible()
        passed.append("history report recovery")
        state["partial"] = True
        page.locator("#history-button").click()
        page.get_by_role("button", name="View report", exact=True).click()
        expect(page.locator("#results")).to_contain_text("INCONCLUSIVE")
        expect(page.locator("#results")).to_contain_text("Analysis coverage")
        expect(page.locator("#results")).to_contain_text("Model endpoint failure")
        expect(page.locator("#results")).to_contain_text("502")
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.screenshot(path=str(artifacts / "partial-report-preview.png"), full_page=True)
        passed.append("partial report exposes failed/skipped sections and safe HTTP502 classification")
        state["partial"] = False
        page.get_by_role("button", name="New investigation", exact=True).click()
        state["complete"] = False
        page.locator("#transaction").fill(TX)
        page.locator("#analyze").click()
        expect(page.locator("#running")).to_be_visible()
        page.locator("#cancel").click()
        expect(page.locator("#cancel")).to_contain_text("Cancellation requested")
        expect(page.locator("#results")).to_be_visible(timeout=15000)
        expect(page.locator("#results")).to_contain_text("INCONCLUSIVE")
        assert "Investigation report" != page.locator("#results h1").inner_text()
        passed.append("cancelled pipeline cannot display a successful report")
        page.get_by_role("button", name="New investigation", exact=True).click()
        page.unroute("**/api/**", fixture)
        page.route("**/api/config", lambda route: route.fulfill(json=CONFIG))
        page.route("**/api/analyze", lambda route: route.fulfill(status=429, json={"error": "Rate limit reached"}))
        page.locator("#transaction").fill(TX)
        page.locator("#analyze").click()
        expect(page.locator("#notice")).to_contain_text("Rate limit reached")
        expect(page.locator("#setup")).to_be_visible()
        passed.append("API rate-limit failure remains recoverable")
        assert not errors, errors
        passed.append("zero uncaught browser exceptions")
        context.close()
        # Exercise the real server and its bundled capture, without fixture routes.
        actual = browser.new_page(viewport={"width": 1440, "height": 1000})
        actual.goto(args.url)
        actual.locator("#capture-button").click()
        expect(actual.locator("#results")).to_be_visible()
        expect(actual.locator("#results")).to_contain_text("SAVED CAPTURE")
        assert actual.locator(".finding").count() == 20
        actual.get_by_role("button", name="Show 20 more findings", exact=True).click()
        assert actual.locator(".finding").count() == 40
        passed.append("real server saved capture remains explicit and paginates 803 functions")
        browser.close()
    print(json.dumps({"passed": len(passed), "checks": passed, "artifacts": str(artifacts)}, indent=2))


if __name__ == "__main__":
    main()
