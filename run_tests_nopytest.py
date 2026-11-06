"""Stdlib-only test runner: verifies how many tests actually pass without pytest."""
import importlib.util, os, sys, traceback, types

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

# Minimal pytest shim so modules that `import pytest` still work.
if "pytest" not in sys.modules:
    shim = types.ModuleType("pytest")

    class _Raises:
        def __init__(self, exc, match=None):
            self.exc = exc
        def __enter__(self):
            return self
        def __exit__(self, et, ev, tb):
            if et is None:
                raise AssertionError("DID NOT RAISE")
            return issubclass(et, self.exc)

    def raises(exc, *a, **k):
        return _Raises(exc)

    def skip(reason=""):
        raise _Skip(reason)

    class _Skip(Exception):
        pass

    def fixture(*a, **k):
        def deco(fn):
            return fn
        return deco if not (len(a) == 1 and callable(a[0])) else a[0]

    class _Mark:
        def __getattr__(self, name):
            def deco(*a, **k):
                if len(a) == 1 and callable(a[0]):
                    return a[0]
                return lambda fn: fn
            return deco

    shim.raises = raises
    shim.skip = skip
    shim.fixture = fixture
    shim.mark = _Mark()
    shim.Skip = _Skip
    class _Approx:
        def __init__(self, expected, rel=1e-6, abs=1e-12):
            self.expected = expected
            self.rel = rel if rel is not None else 1e-6
            self.abs = abs if abs is not None else 1e-12
        def __eq__(self, other):
            try:
                a = float(other); b = float(self.expected)
            except (TypeError, ValueError):
                return other == self.expected
            return abs(a - b) <= max(self.abs, self.rel * max(abs(a), abs(b)))
        def __repr__(self):
            return "approx(%r)" % (self.expected,)

    def approx(expected, rel=None, abs=None, **k):
        return _Approx(expected, rel=rel, abs=abs)

    shim.approx = approx
    sys.modules["pytest"] = shim

_Skip = sys.modules["pytest"].Skip

passed = failed = skipped = errors = 0
fail_detail = []

test_dir = os.path.join(ROOT, "tests")
for fname in sorted(os.listdir(test_dir)):
    if not (fname.startswith("test_") and fname.endswith(".py")):
        continue
    modname = "tests." + fname[:-3]
    try:
        spec = importlib.util.spec_from_file_location(modname, os.path.join(test_dir, fname))
        mod = importlib.util.module_from_spec(spec)
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)
    except Exception as e:
        errors += 1
        fail_detail.append((fname, "<module import>", repr(e)))
        continue

    for attr in sorted(dir(mod)):
        if not attr.startswith("test_"):
            continue
        fn = getattr(mod, attr)
        if not callable(fn):
            continue
        argcount = fn.__code__.co_argcount if hasattr(fn, "__code__") else 0
        if argcount > 0:
            skipped += 1
            continue
        try:
            fn()
            passed += 1
        except _Skip:
            skipped += 1
        except Exception as e:
            failed += 1
            fail_detail.append((fname, attr, repr(e)[:200]))

print(f"PASSED={passed}  FAILED={failed}  SKIPPED(fixtures)={skipped}  MODULE_ERRORS={errors}")
print(f"TOTAL COLLECTED={passed+failed+skipped}")
if fail_detail:
    print("\n--- failures ---")
    for f, t, e in fail_detail[:25]:
        print(f"{f}::{t}\n    {e}")
# Exit non-zero when any test failed or any module could not be imported.
# verify_paper_validity.py checks for FAILED=0 in stdout, but that check is
# insufficient: MODULE_ERRORS and SKIPPED counts are not validated there.
# Callers should inspect the full output line, not just FAILED=0.
if failed or errors:
    raise SystemExit(1)
