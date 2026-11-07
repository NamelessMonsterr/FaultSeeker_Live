import os
from setuptools import find_packages, setup

with open(os.path.join(os.path.dirname(__file__), "requirements.txt"), 'r', encoding='utf-8') as f:
    dependencies = f.read().strip().split("\n")

setup(
    name="FaultSeeker",
    author="Kairan Sun",
    description="An AI-powered tool for automated fault localization in malicious blockchain transactions.",
    packages=find_packages(include=["faultseeker", "faultseeker.*"]),
    install_requires=dependencies,
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "faultseeker=faultseeker.main:main_cli",
        ]
    },
)
