import hashlib
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone

from faultseeker.data_collection import rpc_client, rpc_collector
from faultseeker.data_collection.rpc_client import RpcClient, RpcError

CACHE_SCHEMA = 2
# `cast run` ends a COMPLETE successful replay with these two lines (cast 1.4.4, 1.5.1 and 1.9.0 outputs, tests/fixtures/cast_traces.json).
_COMPLETE_TRACE = re.compile(r"Transaction successfully executed\.\s*\n\s*Gas used: \d+\s*\Z")


def is_complete_trace(text) -> bool:
    """True only for a finished successful replay: cast prints its completion footer after the last trace line, so a truncated or
    interrupted output (which still contains trace-looking lines) does not pass."""
    return isinstance(text, str) and bool(_COMPLETE_TRACE.search(text.rstrip() + "\n"))


class TransactionReplayer:

    def __init__(self, cache_path='./data/cache/replay'):
        """Initialize TransactionReplayer with cache directory."""
        self.cache_path = cache_path
        os.makedirs(cache_path, exist_ok=True)

    # Variables cast may inherit. Everything else is dropped so that signature caches (HOME), Etherscan keys,
    # FOUNDRY_* config overrides and model-provider keys cannot change the trace format or leak into the process.
    _CAST_ENV_KEEP = ('PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TMPDIR', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE',
                      'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')

    @staticmethod
    def cast_environment(home):
        env = {k: v for k, v in os.environ.items() if k in TransactionReplayer._CAST_ENV_KEEP}
        env['HOME'] = home
        if os.environ.get('FAULTSEEKER_CAST_OFFLINE', '1') != '0':
            env['FOUNDRY_OFFLINE'] = 'true'    # no online signature lookups (does not stop decoding from a local cache)
        return env

    @staticmethod
    def transaction_replay(txn_hash, chain):
        """Execute transaction replay using cast command.

        The RPC endpoint is the foundry.toml alias for ``chain`` unless the FAULTSEEKER_RPC_URL environment variable is
        set (the web server sets it per run for custom endpoints). The URL is never printed because it may embed a
        provider key. cast runs with an empty temporary HOME and a minimal environment so its output does not depend on
        a warm signature cache; function identity is normalised in the trace parser either way (utils/selectors.py).
        """
        import shutil
        import tempfile
        custom_rpc = os.environ.get('FAULTSEEKER_RPC_URL', '').strip()
        rpc_target = custom_rpc or chain
        command = ["cast", "run", "--quick", txn_hash, '--rpc-url', rpc_target]

        home = tempfile.mkdtemp(prefix='faultseeker-cast-home-')
        try:
            env = TransactionReplayer.cast_environment(home)
            try:
                version = subprocess.run(["cast", "--version"], capture_output=True, text=True, timeout=30, env=env)
                import re
                found = re.search(r"(\d+\.\d+\.\d+)", version.stdout or "")
                print(f"cast version: {found.group(1) if found else 'unknown'}", flush=True)
            except Exception:
                pass
            print(f"cast run --quick {txn_hash} --rpc-url {'<custom endpoint>' if custom_rpc else chain}", flush=True)
            result = subprocess.run(command, capture_output=True, text=True, timeout=7200, env=env)
            if result.returncode != 0 or not result.stdout.strip():
                tail = (result.stderr or '').strip().splitlines()[-6:]
                print(f"cast exited with code {result.returncode}: {' | '.join(tail)}", flush=True)
                return None
            if not is_complete_trace(result.stdout):
                print("cast exited with code 0 but its output is not a complete trace (no completion footer): the replay is discarded.",
                      flush=True)
                return None
            return result.stdout
        except FileNotFoundError:
            print("cast exited with code 127: Foundry 'cast' is not installed or not on PATH", flush=True)
            return None
        except Exception:
            import traceback
            traceback.print_exc()
            return None
        finally:
            shutil.rmtree(home, ignore_errors=True)

    # ---- cache: only complete replays of a VERIFIED chain, keyed by chain id, written atomically, integrity-checked ----------------
    def _paths(self, txn_hash, chain_id):
        stem = os.path.join(self.cache_path, f"{int(chain_id)}-{txn_hash.lower()}.v{CACHE_SCHEMA}")
        return stem + '.txt', stem + '.json'

    def get_replay_cache(self, txn_hash, chain_id=None):
        """The cached trace for (chain id, hash), or None. Legacy entries (named by hash alone) are never read; an entry whose recorded
        digest, chain, hash or schema does not match its content is a miss, never trusted."""
        if chain_id is None:
            return None
        trace_path, meta_path = self._paths(txn_hash, chain_id)
        try:
            with open(meta_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)
            with open(trace_path, 'r', encoding='utf-8') as f:
                trace = f.read()
        except (OSError, ValueError):
            return None
        if (meta.get('schema') != CACHE_SCHEMA or meta.get('chain_id') != int(chain_id) or meta.get('txn_hash') != txn_hash.lower()
                or meta.get('sha256') != hashlib.sha256(trace.encode('utf-8')).hexdigest() or not is_complete_trace(trace)):
            return None
        return trace

    def cache_replay(self, txn_hash, invocation_flow, chain_id=None):
        """Publishes a COMPLETE replay atomically (temp file + rename), trace first and its metadata second; any failure leaves no entry."""
        if chain_id is None or not is_complete_trace(invocation_flow):
            return False
        trace_path, meta_path = self._paths(txn_hash, chain_id)
        meta = {'schema': CACHE_SCHEMA, 'chain_id': int(chain_id), 'txn_hash': txn_hash.lower(),
                'sha256': hashlib.sha256(invocation_flow.encode('utf-8')).hexdigest(), 'bytes': len(invocation_flow.encode('utf-8')),
                'created': datetime.now(timezone.utc).isoformat(timespec='seconds')}
        temps = []
        try:
            for path, payload in ((trace_path, invocation_flow), (meta_path, json.dumps(meta))):
                fd, tmp = tempfile.mkstemp(dir=self.cache_path, suffix='.tmp')
                temps.append(tmp)
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(payload)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, path)
            return True
        except OSError as exc:
            print(f"Could not cache the replay ({type(exc).__name__}); continuing without a cache entry.", flush=True)
            for tmp in temps:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            for path in (trace_path, meta_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
            return False

    @staticmethod
    def verified_chain_id(chain):
        """The chain id of the endpoint cast will use (the same resolution as the collector), verified against the selected network.
        Returns None, after printing the failure in the collection format, when it cannot be verified."""
        try:
            return rpc_collector.verify_chain(RpcClient(rpc_client.resolve_endpoint(chain)), chain)
        except RpcError as exc:
            print(f"RPC collection failed ({exc.kind}): {exc.message}", flush=True)
            return None

    def run(self, txn_hash: str, chain: str) -> str:
        """
        Run transaction replay for the given transaction hash and chain.

        The endpoint is verified (eth_chainId) against the selected network FIRST: a wrong endpoint never reaches cast and never
        reads or writes a cache entry. Only a successful (exit 0), complete replay is returned as a trace and cached; anything else
        returns None and leaves the cache untouched.

        Returns:
            Transaction replay trace text, or None
        """
        chain_id = self.verified_chain_id(chain)
        if chain_id is None:
            return None
        cached = self.get_replay_cache(txn_hash, chain_id)
        if cached:
            return cached
        invocation_flow = self.transaction_replay(txn_hash, chain)
        if invocation_flow:
            self.cache_replay(txn_hash, invocation_flow, chain_id)
        return invocation_flow
