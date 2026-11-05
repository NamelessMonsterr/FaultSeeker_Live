"""
Prompt module for FaultSeeker.

This module contains all prompt classes organized according to the two-stage framework:
- Stage 1: Transaction-Level Forensics (forensics/)
- Stage 2: Task-Driven Function Analysis (function_analysis/)
"""

# Stage 1: Transaction-Level Forensics prompts
from faultseeker.prompts.forensics import (
    TraceAnalysisPrompts,
    FundFlowPrompts,
    AddressClassificationPrompts,
)

# Stage 2: Task-Driven Function Analysis prompts
from faultseeker.prompts.function_analysis import (
    OrchestrationSessionPrompts,
    TaskCoordinatorPrompts,
    WorkerPrompts,
    VulnerabilityAnalysisPrompts,
    LocalTaskPrompts,
)

__all__ = [
    # Stage 1: Forensics
    "TraceAnalysisPrompts",
    "FundFlowPrompts",
    "AddressClassificationPrompts",
    # Stage 2: Function Analysis
    "OrchestrationSessionPrompts",
    "TaskCoordinatorPrompts",
    "WorkerPrompts",
    "VulnerabilityAnalysisPrompts",
    "LocalTaskPrompts",
]
