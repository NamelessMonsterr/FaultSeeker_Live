"""
Forensics Stage Prompts (Stage 1: Transaction-Level Forensics)

This module contains prompts for the transaction-level forensics stage,
including trace analysis, fund flow analysis, and address classification.
"""

from faultseeker.prompts.forensics.trace_analysis_prompts import TraceAnalysisPrompts
from faultseeker.prompts.forensics.fund_flow_prompts import FundFlowPrompts
from faultseeker.prompts.forensics.address_classification_prompts import AddressClassificationPrompts

__all__ = [
    "TraceAnalysisPrompts",
    "FundFlowPrompts",
    "AddressClassificationPrompts",
]
