"""
Forensics module for FaultSeeker - Stage 1: Transaction-Level Forensics

This module contains agents for analyzing blockchain transactions at the transaction level:
- Trace Analysis: Analyzes transaction execution traces
- Fund Flow Analysis: Analyzes token transfers and balance changes
- Address Classification: Identifies and classifies address roles
- Forensics Orchestration: Coordinates all Stage 1 analyses

These agents work together to identify suspicious functions for detailed analysis in Stage 2.
"""

# NOTE: Imports removed from __init__.py to avoid circular dependencies.
# Import directly from submodules instead:
#   from faultseeker.forensics.trace_analyzer import TraceAnalyzer
#   from faultseeker.forensics.orchestrator import ForensicsOrchestrator

__all__ = [
    "TraceAnalyzer",
    "FundFlowAnalyzer",
    "AddressClassifier",
    "ForensicsOrchestrator",
    "ForensicsResult",
]
