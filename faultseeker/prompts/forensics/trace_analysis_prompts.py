"""
Transaction Analysis Prompts

Prompts used by TransactionTraceAnalyzer for analyzing transaction traces,
function calls, and attack vectors.
"""

from dataclasses import dataclass


@dataclass
class TraceAnalysisPrompts:
    """Prompts for transaction trace analysis"""

    analyze_basic_info_fund_flow: str = (
        'Given the following fund flow for an attack transaction, analyze and return the list potential attacker (potential_attacker) and victim (potential_victim) address with confidence level (confidence_score, 1-10, 10 be the most confident) and evidence (evidence). You should answer concisely with JSON format {"potential_attacker":{address:{confidence_score,evidence}},"potential_victim":{address:{confidence_score,evidence}}}.\n'
    )

    analyze_basic_info_address_relation: str = (
        'Given the following address call relations for an attack transaction, analyze and return the list potential attacker (potential_attacker) and victim (potential_victim) address with confidence level (confidence_score, 1-10, 10 be the most confident) and evidence (evidence). You should answer concisely with JSON format {"potential_attacker":{address:{confidence_score,evidence}},"potential_victim":{address:{confidence_score,evidence}}}.\n'
    )

    understand_function_call: str = '''You are an expert smart contract security analyst. I will present you with calls from a malicious transaction's execution flow one at a time, following a top-down, depth-first search order. Your task is to:

1. Analyze each call I present to you in detail
2. Identify any potential security vulnerabilities, exploits, or attack patterns in the call
3. Update our understanding of the attack vector based on this new information
4. Relate the current call to previously analyzed calls when relevant

Current attack vector understanding:
{attack_vector_record}

New call to analyze:
{new_call}

Provide your analysis in the following JSON format (DO NOT INCLUDE ANY OTHER TEXT):

TECHNICAL ANALYSIS:
str, Detailed breakdown of what the call is doing, including function interactions, value transfers, state changes, and any suspicious patterns

ATTACK VECTOR CONTRIBUTION:
str, How this call contributes to or relates to the overall attack vector(s) we've identified so far

UPDATED ATTACK VECTOR UNDERSTANDING:
[list, Description of first attack step, Description of second attack step, Description of third attack step,...]
'''

    update_attack_vector: str = (
        'Understand the provided incomplete attack vector, make it more concise. You may remove step not contributing to the key exploit logic (be cautious for the last few function calls since the attack vector maybe not complete yet) while keep it logic flows. Return the refined attack vector in JSON format {"refined_vector":[step1,step2,...]}. Do not include further explanations.\n'
    )

    evaluate_function_call_risk: str = (
        'Analyze the possibility of the function call to be vulnerable with likelihood_score (1-10, 10 be the most likely) and evidence (why it could be potentially vulnerable, you are expected to focus on smart contract related vulnerabilities). You should answer concisely with JSON format.'
    )

    understand_function_call_loops: str = '''You are an expert smart contract security analyst. I will present you with a function call from a malicious transaction's execution flow at one time, following a top-down, depth-first search order. Your task is to:
    1. Analyze the function calls in the loop I present to you in detail, each function call is presented in the format 'caller_address::function_name::params'
    2. Identify any potential security vulnerabilities, exploits, or attack patterns in the call
    3. Update our understanding of the attack vector based on this new information
    4. Relate the current call to previously analyzed calls when relevant
    However, this time, it is a loop, so you are expected to understand each function calls in the loop and then analyze the loop as a whole. You should consider the loop's impact on the overall attack vector.
    Current attack vector understanding:
    {attack_vector_record}
    New call to analyze:
    {new_call}
    Provide your analysis in the following JSON format (DO NOT INCLUDE ANY OTHER TEXT):
    TECHNICAL ANALYSIS:
    str, Detailed breakdown of what the call is doing, including function interactions, value transfers, state changes, and any suspicious patterns
    ATTACK VECTOR CONTRIBUTION:
    str, How this call contributes to or relates to the overall attack vector(s) we've identified so far
    UPDATED ATTACK VECTOR UNDERSTANDING:
    [list, Description of first attack step, Description of second attack step, Description of third attack step,...]
    '''

    understand_fund_flow: str = (
        'Given the following fund flow for an attack transaction, could you 1. summarize the fund flows, 2. identify potential attacker and victims with evidence and confidence_score (1-10, 10 be the most confident), 3. summarize the balance change for each account. Return with JSON format {summary:summary, potential_attack:{address:{confidence_score,evidence}}, potential_victim:{address:{confidence_score,evidence}}, balance_change:{address:{token_address:balance_change}}}. Do not include any further explaination.\n'
    )

    combine_analysis_results: str = (
        'Given the following analysis of different chunks for an attack transaction, understand and merge them into a single summary. Do not include further explainations.\n'
    )
