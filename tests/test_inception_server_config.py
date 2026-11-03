"""Offline server configuration contracts; no provider or runtime inference proof."""
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = "inception/mercury-3"


def server_tree():
    return ast.parse((ROOT / "app/server.py").read_text(encoding="utf-8"))


def configured_models():
    assignment = next(statement for statement in server_tree().body
                      if isinstance(statement, ast.Assign)
                      and any(isinstance(target, ast.Name) and target.id == "MODELS"
                              for target in statement.targets))
    return ast.literal_eval(assignment.value)


def test_inception_model_is_explicitly_listed_with_its_own_key():
    entries = [entry for entry in configured_models() if entry["id"] == MODEL]
    assert entries == [{"id": MODEL, "label": "Mercury 3 (Inception free allowance)",
                        "keyEnv": "INCEPTION_API_KEY"}]
    assert configured_models()[0]["id"] != MODEL  # Adding a route does not select it by default.


def test_static_config_contains_matching_inception_entry():
    generated = json.loads((ROOT / "api/config").read_text(encoding="utf-8"))
    assert [entry for entry in generated["models"] if entry["id"] == MODEL] == [
        entry for entry in configured_models() if entry["id"] == MODEL]
    assert any(entry["id"] == MODEL for entry in generated["models"])


def stage2_default(request):
    # Execute only the real worker's two side-effect-free policy assignments.
    # This is a policy contract, not an end-to-end worker/provider integration.
    worker = next(statement for statement in server_tree().body
                  if isinstance(statement, ast.FunctionDef) and statement.name == "worker")
    assignments = {target.id: statement for statement in ast.walk(worker)
                   if isinstance(statement, ast.Assign) for target in statement.targets
                   if isinstance(target, ast.Name) and target.id in ("_groqish", "s2w")}
    policy = ast.Module(body=[assignments["_groqish"], assignments["s2w"]], type_ignores=[])
    context = {"req": request}
    exec(compile(policy, str(ROOT / "app/server.py"), "exec"), context)
    return context["s2w"]


def test_inception_stage2_is_serial_by_default_and_keeps_explicit_override():
    assert stage2_default({"mode": MODEL}) == "1"
    assert stage2_default({"mode": MODEL, "stage2_workers": 3}) == "3"
    assert stage2_default({"mode": "gemini-3.8-flash"}) == ""
    assert stage2_default({"mode": "itera/qwen3.8-27b"}) == "1"
