"""Real ablation switches for FaultSeeker++ components.

The legacy harness simulated ablations by subtracting a constant from the full
system score, so the ablation tables measured arithmetic rather than the effect
of disabling a component. This module provides a configuration object that the
orchestrator consults to actually bypass code paths.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

COMPONENTS = (
    "faegl",
    "tig",
    "calibration",
    "llm_routing",
    "adversarial_hardening",
)


@dataclass(frozen=True)
class AblationConfig:
    """Which components are disabled for this run."""

    disable_faegl: bool = False
    disable_tig: bool = False
    disable_calibration: bool = False
    disable_llm_routing: bool = False
    disable_adversarial_hardening: bool = False

    @property
    def is_full_system(self) -> bool:
        return not any(asdict(self).values())

    @property
    def disabled_components(self) -> List[str]:
        return [name for name in COMPONENTS if getattr(self, f"disable_{name}")]

    def enabled(self, component: str) -> bool:
        """True when the named component should run."""
        if component not in COMPONENTS:
            raise ValueError(
                f"Unknown component {component!r}; expected one of {COMPONENTS}"
            )
        return not getattr(self, f"disable_{component}")

    def variant_name(self) -> str:
        if self.is_full_system:
            return "full_system"
        return "minus_" + "_".join(self.disabled_components)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["variant"] = self.variant_name()
        payload["disabled_components"] = self.disabled_components
        return payload

    @classmethod
    def full_system(cls) -> "AblationConfig":
        return cls()

    @classmethod
    def disabling(cls, *components: str) -> "AblationConfig":
        kwargs = {}
        for component in components:
            if component not in COMPONENTS:
                raise ValueError(
                    f"Unknown component {component!r}; expected one of {COMPONENTS}"
                )
            kwargs[f"disable_{component}"] = True
        return cls(**kwargs)

    @classmethod
    def from_env(cls, environ: Optional[Dict[str, str]] = None) -> "AblationConfig":
        env = environ if environ is not None else os.environ
        kwargs = {}
        for component in COMPONENTS:
            key = f"FAULTSEEKER_DISABLE_{component.upper()}"
            raw = str(env.get(key, "")).strip().lower()
            kwargs[f"disable_{component}"] = raw in {"1", "true", "yes", "on"}
        return cls(**kwargs)

    @classmethod
    def from_args(cls, args: Any) -> "AblationConfig":
        kwargs = {}
        for component in COMPONENTS:
            attr = f"disable_{component}"
            kwargs[attr] = bool(getattr(args, attr, False))
        return cls(**kwargs)


def add_ablation_cli_args(parser: Any) -> Any:
    """Register --disable-<component> flags on an argparse parser."""
    group = parser.add_argument_group("ablation")
    for component in COMPONENTS:
        group.add_argument(
            f"--disable-{component.replace('_', '-')}",
            dest=f"disable_{component}",
            action="store_true",
            help=f"Bypass the {component} component for this run.",
        )
    return parser


def standard_ablation_suite() -> List[AblationConfig]:
    """Full system plus each single-component ablation (paper Table 5 layout)."""
    suite = [AblationConfig.full_system()]
    suite.extend(AblationConfig.disabling(component) for component in COMPONENTS)
    return suite
