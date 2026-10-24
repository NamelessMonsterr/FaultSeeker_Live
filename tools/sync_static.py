"""Generate the static Pages surface from the server UI without importing the server."""
import argparse
import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def outputs():
    source = ast.parse((ROOT / "app/server.py").read_text(encoding="utf-8"))
    constants = {}
    for statement in source.body:
        if isinstance(statement, ast.Assign):
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id in ("MODELS", "CHAINS", "PRESET_TXS", "BSC_PRESET_TXS"):
                    constants[target.id] = ast.literal_eval(statement.value)
    config = {"chains":constants["CHAINS"], "models":constants["MODELS"], "repo_present":False,
              "live_available":False, "capture_available":True,
              "preset_txs":[dict(p,chain=chain) for key,chain in [("PRESET_TXS","eth"),("BSC_PRESET_TXS","bsc")] for p in constants[key]]}
    result = {ROOT / "index.html": (ROOT / "app/web/index.html").read_bytes(),
              ROOT / "api/config": (json.dumps(config, indent=2)+"\n").encode()}
    for name in ("console.js", "console.css"):
        result[ROOT / "assets" / name] = (ROOT / "app/web/assets" / name).read_bytes()
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale = []
    for path, content in outputs().items():
        if args.check:
            if not path.exists() or path.read_bytes() != content:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_bytes(content)
    if stale:
        raise SystemExit("Static files out of date: " + ", ".join(stale))
