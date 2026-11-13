"""Worker stand-in for API tests: the REAL worker, pipeline, ranker and analyzer with a fake provider (tests/pipeline_fakes.py).
The scenario comes from the 4 hex digits after 0x in --hash."""
import sys

from tests import pipeline_fakes as fakes


def main():
    h = sys.argv[sys.argv.index("--hash") + 1]
    scenario = {v: k for k, v in fakes.HASH_PREFIX.items()}[h[2:6]]
    fakes.install(scenario, setattr)
    from faultseeker.server import worker
    return worker.main()


if __name__ == "__main__":
    sys.exit(main())
