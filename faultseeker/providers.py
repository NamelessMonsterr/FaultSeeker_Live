"""Model provider registry.

One JSON file (config/models.json, or FAULTSEEKER_MODELS_FILE) declares providers and models. Every model names its
provider explicitly; nothing is inferred from a model-name prefix. Endpoints, exact model IDs and API keys are read
from the environment variables the registry names, so no endpoint, model ID or secret lives in the repository.

Used by the pipeline agents (faultseeker.utils.agent / utils.build_agent), the web server and, through /api/config,
the console.
"""
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODELS_FILE = ROOT / "config" / "models.json"

PROVIDER_TYPES = {"openai_compatible", "ollama"}
KEY_VALIDATION_MODES = {"models_list", "none"}
# Parameters that may be configured per model. Anything else in "params" is rejected at load time rather than ignored.
ALLOWED_PARAMS = {"temperature", "top_p", "max_tokens", "max_completion_tokens", "reasoning_effort", "seed"}
_CASTERS = {"float": float, "int": int, "str": str}


class ProviderConfigError(Exception):
    """The registry file or the environment it points at is unusable. Messages never contain secret values."""


@dataclass(frozen=True)
class Provider:
    id: str
    label: str
    type: str
    base_url: Optional[str] = None
    base_url_env: Optional[str] = None
    api_key_env: Optional[str] = None
    host_env: Optional[str] = None
    key_validation: str = "none"
    timeout_seconds: float = 120.0
    max_retries: int = 0
    public_endpoint: bool = False


@dataclass(frozen=True)
class ModelSpec:
    id: str
    label: str
    provider_id: str
    model: Optional[str] = None
    model_env: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=lambda: {"temperature": "pass"})


@dataclass(frozen=True)
class ResolvedModel:
    """A model ready to call: everything resolved from the environment, still without the API key value."""
    id: str
    label: str
    provider: Provider
    model_id: str                      # exact ID sent to the provider (case preserved)
    base_url: Optional[str]            # openai_compatible
    host: Optional[str]                # ollama
    temperature_mode: str              # "pass" (use the caller's value) | "omit" | "fixed"
    temperature_value: Optional[float]
    extra_params: Dict[str, Any]       # sent verbatim, exactly as configured


def _read_env(environ: Mapping[str, str], name: Optional[str]) -> str:
    return (environ.get(name, "") if name else "").strip()


class Registry:
    def __init__(self, providers: Dict[str, Provider], models: List[ModelSpec]):
        self.providers = providers
        self.models = {m.id: m for m in models}

    # ---- loading -------------------------------------------------------------------------------------
    @classmethod
    def load(cls, path: Optional[Path] = None, environ: Optional[Mapping[str, str]] = None) -> "Registry":
        environ = os.environ if environ is None else environ
        path = Path(path or environ.get("FAULTSEEKER_MODELS_FILE") or DEFAULT_MODELS_FILE)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ProviderConfigError(f"Cannot read the model registry {path}: {exc.strerror or exc}")
        except ValueError as exc:
            raise ProviderConfigError(f"The model registry {path} is not valid JSON: {exc}")
        providers = {}
        for pid, raw in (data.get("providers") or {}).items():
            providers[pid] = cls._provider(pid, raw)
        models = []
        for raw in data.get("models") or []:
            models.append(cls._model(raw, providers))
        extra = cls._ollama_models(environ, providers)
        ids = [m.id for m in models + extra]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise ProviderConfigError(f"Duplicate model ids in the registry: {sorted(dupes)}")
        return cls(providers, models + extra)

    @staticmethod
    def _provider(pid: str, raw: dict) -> Provider:
        if not isinstance(raw, dict):
            raise ProviderConfigError(f"Provider '{pid}' must be an object.")
        ptype = raw.get("type")
        if ptype not in PROVIDER_TYPES:
            raise ProviderConfigError(f"Provider '{pid}': type must be one of {sorted(PROVIDER_TYPES)}.")
        if ptype == "openai_compatible" and not (raw.get("base_url") or raw.get("base_url_env")):
            raise ProviderConfigError(f"Provider '{pid}' needs base_url or base_url_env.")
        validation = raw.get("key_validation", "none")
        if validation not in KEY_VALIDATION_MODES:
            raise ProviderConfigError(f"Provider '{pid}': key_validation must be one of {sorted(KEY_VALIDATION_MODES)}.")
        return Provider(
            id=pid, label=raw.get("label", pid), type=ptype, base_url=raw.get("base_url"),
            base_url_env=raw.get("base_url_env"), api_key_env=raw.get("api_key_env"), host_env=raw.get("host_env"),
            key_validation=validation, timeout_seconds=float(raw.get("timeout_seconds", 120)),
            max_retries=int(raw.get("max_retries", 0)), public_endpoint=bool(raw.get("public_endpoint", False)))

    @staticmethod
    def _model(raw: dict, providers: Dict[str, Provider]) -> ModelSpec:
        mid = str(raw.get("id", "")).strip().lower()
        if not mid:
            raise ProviderConfigError("Every model needs an id.")
        if raw.get("provider") not in providers:
            raise ProviderConfigError(f"Model '{mid}' names an unknown provider '{raw.get('provider')}'.")
        if not (raw.get("model") or raw.get("model_env")):
            raise ProviderConfigError(f"Model '{mid}' needs model or model_env (the exact provider model ID).")
        params = raw.get("params", {"temperature": "pass"})
        unknown = set(params) - ALLOWED_PARAMS
        if unknown:
            raise ProviderConfigError(f"Model '{mid}': unsupported params {sorted(unknown)}; allowed: {sorted(ALLOWED_PARAMS)}.")
        return ModelSpec(id=mid, label=raw.get("label", mid), provider_id=raw["provider"], model=raw.get("model"),
                         model_env=raw.get("model_env"), params=params)

    @staticmethod
    def _ollama_models(environ: Mapping[str, str], providers: Dict[str, Provider]) -> List[ModelSpec]:
        names = [n.strip() for n in _read_env(environ, "FAULTSEEKER_OLLAMA_MODELS").split(",") if n.strip()]
        if names and "ollama" not in providers:
            raise ProviderConfigError("FAULTSEEKER_OLLAMA_MODELS is set but the registry has no 'ollama' provider.")
        return [ModelSpec(id=f"ollama:{n}".lower(), label=f"{n} (Ollama)", provider_id="ollama", model=n,
                          params={"temperature": "pass"}) for n in names]

    # ---- queries -------------------------------------------------------------------------------------
    def all_key_envs(self) -> List[str]:
        return sorted({p.api_key_env for p in self.providers.values() if p.api_key_env})

    def find(self, model_id: str) -> Optional[ModelSpec]:
        mid = (model_id or "").strip().lower()
        spec = self.models.get(mid)
        if spec is None and mid.startswith("ollama:") and "ollama" in self.providers and mid[7:]:
            # Explicit provider syntax for ad-hoc local models; the provider is stated, never guessed.
            raw = (model_id or "").strip()[7:]
            spec = ModelSpec(id=mid, label=f"{raw} (Ollama)", provider_id="ollama", model=raw)
        return spec

    def resolve(self, model_id: str, environ: Optional[Mapping[str, str]] = None) -> ResolvedModel:
        environ = os.environ if environ is None else environ
        spec = self.find(model_id)
        if spec is None:
            known = ", ".join(sorted(self.models)) or "none"
            raise ProviderConfigError(
                f"Model '{model_id}' is not in the provider registry. Known models: {known}. "
                "Use a registry id, or 'ollama:<name>' for a local Ollama model.")
        provider = self.providers[spec.provider_id]
        model_id_exact = spec.model or _read_env(environ, spec.model_env)
        if not model_id_exact:
            raise ProviderConfigError(f"Model '{spec.id}' is not configured: set {spec.model_env} to the exact model ID.")
        base_url = host = None
        if provider.type == "openai_compatible":
            base_url = (provider.base_url or _read_env(environ, provider.base_url_env)).rstrip("/")
            if not base_url:
                raise ProviderConfigError(f"Provider '{provider.id}' is not configured: set {provider.base_url_env} to its OpenAI-compatible base URL.")
            if not base_url.startswith(("http://", "https://")):
                raise ProviderConfigError(f"Provider '{provider.id}': the base URL must start with http:// or https://.")
        else:
            host = _read_env(environ, provider.host_env) or None
        mode, value, extra = self._params(spec, environ)
        return ResolvedModel(id=spec.id, label=spec.label, provider=provider, model_id=model_id_exact, base_url=base_url,
                             host=host, temperature_mode=mode, temperature_value=value, extra_params=extra)

    @staticmethod
    def _params(spec: ModelSpec, environ: Mapping[str, str]) -> Tuple[str, Optional[float], Dict[str, Any]]:
        mode, value, extra = "omit", None, {}
        for name, raw in spec.params.items():
            resolved, present = raw, True
            if isinstance(raw, dict):
                env_value = _read_env(environ, raw.get("env"))
                if not env_value:
                    if raw.get("when_unset", "omit") != "omit":
                        raise ProviderConfigError(f"Model '{spec.id}': parameter '{name}' has an unsupported when_unset value.")
                    present = False
                else:
                    try:
                        resolved = _CASTERS[raw.get("type", "str")](env_value)
                    except (KeyError, ValueError):
                        raise ProviderConfigError(f"Model '{spec.id}': {raw.get('env')} is not a valid {raw.get('type', 'str')}.")
            if name == "temperature":
                if resolved == "pass" and present:
                    mode = "pass"
                elif resolved == "omit" or not present or resolved is None:
                    mode = "omit"
                else:
                    mode, value = "fixed", float(resolved)
            elif present and resolved is not None:
                extra[name] = resolved
        return mode, value, extra

    def availability(self, environ: Optional[Mapping[str, str]] = None) -> List[Tuple[ModelSpec, Optional[str]]]:
        """Every model with None when it is usable, or the reason it is not (names env vars, never values)."""
        out = []
        for spec in self.models.values():
            try:
                self.resolve(spec.id, environ)
                out.append((spec, None))
            except ProviderConfigError as exc:
                out.append((spec, str(exc)))
        return out

    def enabled(self, environ: Optional[Mapping[str, str]] = None) -> List[ModelSpec]:
        """Models offered to users: FAULTSEEKER_ENABLED_MODELS (if set) intersected with the usable ones."""
        environ = os.environ if environ is None else environ
        wanted = [m.strip().lower() for m in _read_env(environ, "FAULTSEEKER_ENABLED_MODELS").split(",") if m.strip()]
        unknown = [w for w in wanted if w not in self.models]
        if unknown:
            raise ProviderConfigError(f"FAULTSEEKER_ENABLED_MODELS names unknown models: {unknown}.")
        usable = {s.id: s for s, reason in self.availability(environ) if reason is None}
        if wanted:
            return [usable[w] for w in wanted if w in usable]
        return list(usable.values())


def load_registry(environ: Optional[Mapping[str, str]] = None) -> Registry:
    return Registry.load(environ=environ)
