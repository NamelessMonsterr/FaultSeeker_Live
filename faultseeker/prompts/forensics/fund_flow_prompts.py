"""
Fund Flow Analysis Prompts

Prompts used by FundFlowAnalyzer for analyzing token transfers,
identifying victims and attackers, and understanding fund movements.
"""

from dataclasses import dataclass


@dataclass
class FundFlowPrompts:
    """Prompts for fund flow and balance change analysis"""

    identify_victims: str = """You're an excellent smart contract security expert who excels at fault localization by investigating and understanding malicious transactions.
You need to help the security analyst in a fault localization training process, and your commitment is essential to the task. You have been provided with a balance change summary for a transaction. Your task is to identify potential victims based on the balance change summary. For instance, if an address has an abnormally high outflow of tokens, it may indicate that the address is a victim of a malicious transaction. You may return [] if you cannot identify any potential victims.
The balance change summary is as follows: {balance_change_summary}. Return the victim addresses in a list format. Do not include any further explaination."""
