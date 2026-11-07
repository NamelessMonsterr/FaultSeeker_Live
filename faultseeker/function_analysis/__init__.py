"""
Agents module for FaultSeeker.

⚠️  DEPRECATION NOTICE:
This module structure is deprecated. Please use the new forensics module:
  - faultseeker.forensics.ForensicsOrchestrator
  - faultseeker.forensics.TraceAnalyzer
  - faultseeker.forensics.FundFlowAnalyzer
  - faultseeker.forensics.AddressClassifier

The agents in this module now import from forensics for backward compatibility.
"""

# NOTE: Imports removed from __init__.py to avoid circular dependencies.
# Import directly from submodules instead:
#   from faultseeker.agents.function_analyzer import FunctionAnalyzer
#   from faultseeker.agents.function_ranker import FunctionRanker

__all__ = [
    "FunctionAnalyzer",
    "FunctionRanker",
]
