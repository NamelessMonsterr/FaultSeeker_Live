"""
Fund Flow Analysis Prompts

Prompts used by FundFlowAnalyzer for analyzing token transfers,
identifying victims and attackers, and understanding fund movements.
"""

from dataclasses import dataclass


@dataclass
class FundFlowPrompts:
    """Prompts for fund flow and balance change analysis"""

    identify_victims: str = """Review the observed token balance changes and identify addresses that merit further review for potential losses.
Outgoing transfers may be authorized. Do not assume this transaction is malicious or treat a balance decrease as proof of a victim.
Include only addresses present in the supplied balance summary. If the information is insufficient, use an empty victims list.
Balance change summary: {balance_change_summary}
Return ONLY a JSON object in this format, with no explanation or markdown:
{{"victims": ["<address>"]}}
"""
