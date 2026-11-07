"""
Function Call Analysis Prompts

Prompts for analyzing function calls in the function validation workflow.
These prompts handle function call selection, processing, organization, and filtering.
"""

from dataclasses import dataclass


@dataclass
class WorkerPrompts:
    """Prompts for function call analysis workflow"""

    function_call_task_selection: str = """Given the task tree and the current analysis, select one sub-task that is favorable and most likely to lead to successful fault localization. Pay more attention to analyze function calls with unusual params or function calls with unusal high occurance (characteristics pointed to vulnerabilities like reentrancy, insufficient validations, and other contract related vulnerabilities), or risky function calls (functions related to price calculation) or customized business logic).Pay attention to function calls with high frequency as well. \nTask tree: {task_tree}\nFunction Call Information (FCI): {function_call_info_summary}\nCurrent understanding:{current_understanding}\nReturn your answer in the following JSON format with the following keys:\ntask_selected: the number of the selected sub-task only,\n task_description: provide the detailed steps to complete the selected sub-tasks,\n information: selected information from the FCI that is required to complete the subtask,\n additional_information: additional information required by the task but not in the FCI (could be empty if Function call information is enough to complete the task). You should not provide any comments or explanations."""

    function_call_task_generation: str = """Given the task tree and the current analysis, select one sub-task that is favorable and most likely to lead to successful fault localization.\nTask tree: {task_tree}\n
Function call information: {function_call_info_summary}\n
Return the detailed task description with the part of information to be further invesitgated.
    """

    function_call_info_processing: str = """Below is the task and the inforamtion to be analyzed. Keep the analysis result concise while keeping all the key point.\nTask and information provided: {selected_task}"""

    function_call_organization_function_call: str = """Given the function call information, please understand and summarize the current understanding to the transaction regarding fault localization. Keep the summary concise while keeping all the key point.\nFunction call information provided: {function_call_info_summary}"""

    function_call_organization_after_task_completion: str = """Given the current understanding and the new analysis result for the selected, please understand and update the understanding of the transaction. Keep the summary concise while keeping all the key point. \nCurrent understanding:{current_understanding}\nTask and information provided: {selected_task}"""

    function_call_children_call_filtering: str = """Given the function call information and its related children calls, please complete the task described at the start. Return the index of the function calls to be further investigated in a list or [] if no functions need to be further investigated. Do not include further explanations.\nParent function name: {function_name}\nChildren calls: {children_calls}"""

    retrieve_additional_info: str = '''Understand and translate the required additional information (for instance, when mentioning investigate function implementation, operations or logic, means retrieving source code, be smart for the translation)into the following JSON format with the following possible keys (only mention necessary keywords in your answer): function_call:((address, function) in list)\n,children_calls: (retrieving children calls of (address, function) in list)\nsource_code:((address, function) in list),\nbalance_change:(address in list).'''

    function_analysis_init_prompt: str = """The information of target function call is summarized as below. Please follow the instruction and update the task tree. The current task tree is as follows: {task_tree}\nCurrent understanding of the transaction:{current_understanding}\nInformation of the function call: {function_call_info_summary}"""

    check_analysis_adequacy: str = """Given the current understanding of the transaction, please decide if the analysis of the function call and its children calls is adequate for fault localization to move to the next functions to be investigated. Return Yes/No only. Do not include any other information."""

    check_analysis_adequacy_alt: str = """Given the current understanding of the transaction, please decide if the analysis of current function and its children calls is adequate to move to the next functions to be inspected. Return Yes/No only. Do not include any other information."""

    narrow_down_functions: str = '''You are a senior smart contract security expert and helping with a fault localization analysis for a malicious transaction. Given the information of the following function calls that have been selected to be potentially related to the fault (e.g., related to price manipulation, key transfer/stake/unstake/other token related operations, or key validations, same functions with multiple addresses), your task is to understand the provided information and narrow down the list of functions to be inspected by identifying and deciding which functions are most likely containing the fault implementation. Note that functions explicitly mentioned price related operations such as cache must be kept. The function call information is as follows (value for each is its appearance count): {function_call_to_be_inspected}\nReturn the key of the function call information (i.e., function_name_address) in a list format. Try to narrow down the list as much as possible. Do not include any other information.'''

    narrow_down_functions_with_created_contracts: str = '''You are a senior smart contract security expert and helping with a fault localization analysis for a malicious transaction. Given the information of the following function calls that have been selected to be potentially related to the fault, your task is to understand the provided information and narrow down the list of functions to be inspected by identifying and deciding which functions are most likely containing the fault implementation. The function call information is as follows: {function_call_to_be_inspected}\nReturn the key of the function call information (i.e., function_name_address) in a list format. Try to narrow down the list as much as possible. Do not include any other information.'''
