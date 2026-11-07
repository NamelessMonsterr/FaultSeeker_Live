"""
Token Filter Prompts

Prompts used by TokenFilterAgent for filtering and classifying
addresses based on their role in transactions.
"""

from dataclasses import dataclass


@dataclass
class AddressClassificationPrompts:
    """Prompts for token filtering and address classification"""

    identify_role_of_address: str = """You're an excellent smart contract security expert who excels at fault localization by investigating and understanding malicious transactions.
You need to help the security analyst in a fault localization training process, and your commitment is essential to the task. You have been provided with an address and its functions called in the transaction. Your task is to identify possible role of the address in the transaction (e.g., flashloan, lending, stablecoin, unknown, etc.). In addition, descide if the address potentially contains vulnerable code to be examined further.
Return the possible roles in a list, and vulnerable in the list if it is potentially vulnerable. Do not include any further explaination."""
