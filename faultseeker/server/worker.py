"""Subprocess entry point: runs one analysis and reports through stdout markers.

Each run executes in its own process so that it can be cancelled, so its secrets live only in
that process's environment, and so a crash cannot take the web server down.
"""
import argparse
import json
import os
import sys
import traceback

MARKER = "##FS##"


def emit(payload: dict):
    print(f"{MARKER} {json.dumps(payload)}", flush=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", required=True)
    parser.add_argument("--chain", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    emit({"event": "start"})
    try:
        from faultseeker.core.config import FaultSeekerConfig
        from faultseeker.core.pipeline import FaultSeekerPipeline

        pipeline = FaultSeekerPipeline(config=FaultSeekerConfig(
            forensics_model=args.model, function_analysis_model=args.model))
        result = pipeline.analyze_transaction(txn_hash=args.hash, chain=args.chain)
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        tmp = args.out + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, default=str)
        os.replace(tmp, args.out)
        emit({"event": "result"})
        return 0
    except Exception as exc:  # noqa: BLE001 - report every failure to the supervisor
        traceback.print_exc()
        emit({"event": "error", "type": type(exc).__name__, "message": str(exc)[:500]})
        return 1


if __name__ == "__main__":
    sys.exit(main())
