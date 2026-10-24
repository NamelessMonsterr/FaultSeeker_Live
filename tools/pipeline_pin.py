"""Read the single Docker pipeline revision for local bootstrap scripts."""
from pathlib import Path
import re


def read_pin():
    dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile"
    matches = re.findall(r"^ARG FAULTSEEKER_SHA=([0-9a-f]{40})$", dockerfile.read_text(), re.MULTILINE)
    if len(matches) != 1:
        raise ValueError("Dockerfile must specify exactly one full pipeline commit SHA")
    return matches[0]


if __name__ == "__main__":
    print(read_pin())
