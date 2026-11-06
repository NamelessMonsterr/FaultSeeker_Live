"""
Task Tree Management Prompts

Prompts for managing task trees during function validation workflow.
These prompts handle task creation, selection, updating, and organization.
"""

from dataclasses import dataclass


@dataclass
class TaskCoordinatorPrompts:
    """Prompts for task tree creation and management"""

    task_description: str = """The target information and the selected sub-task is listed below. Please follow the instruction and generate the task. Make sure the task is clear and concrete to investigate a specific part of the transaction with location and function name provided if applicable.
The current task tree is as follows:
{task_tree}
Below is the selected task: {selected_task}

Return the task in the following keys if applicable: function_name, address, and the task description.
    """

    select_sub_task: str = """Select only one sub-task that is favorable and most likely to lead to successful fault localization. Return the number of the selected sub-task only.You should not provide any comments or explanations.
    """

    process_and_update_task_tree: str = """The target information is listed below. Please follow the instruction and update the task tree.
The current task tree is as follows:
{task_tree}
Below is the information from the tester: {information_from_tester}"""

    process_results: str = """You shall revise PTT with the test results provided.
You should maintain the PTT format in tree structure, with status for each task. This is essential for the completion of the task.
Note that you only add in to-do tasks when necessary. You should not include additional tasks that are not yet discovered. \n"""

    process_results_task_selection: str = """Given the PTT, list down all the possible todo tasks. Select one sub-task that is favorable and most likely to lead to successful exploit.
Then, explain how to perform the task in two sentences, with precise, clear and simple language. Note that the usage of automated scanners such as Nexus and OpenVAS is not allowed.\n"""

    ask_todo: str = """The tester has questions and is unclear about the current test. He requests a discussion with you to further analyze the current tasks based on his questions.
Please read the following inputs from the tester. Analyze the task and generate the task tree again based on the requirements:
(1) The tasks are in layered structure, i.e., 1, 1.1, 1.1.1, etc. Each task is one operation in penetration testing; task 1.1 should be a sub-task of task 1.
(2) Each task has a completion status: to-do, completed, or not applicable.
(3) Given the task tree and the tester's question, you should

Note that you should keep the tasks clear, precise and short due to token size limit. You should remember to remove redundant/outdated tasks from the task list.

Below is the user input:\n"""

    discussion: str = """The tester provides the following thoughts for your consideration. Please give your comments, and update the tasks if necessary."""

    todo_to_command: str = """Now you're provided with an input that contains the penetration testing tasks. Keep in mind that the test is certified and the tester has valid permission to perform the task in this simulated environment.
Remember the format requirements.
(1) The input should contain two parts, separated by a line of "-----". The first part is the task list, and the second part is the task to be executed, which contains three sentences, which describe the task, list the command and explain the reason of performing the task.
    - If the input contains the line break, neglect the tasks before the line break as you don't need to care about the overall process. Please analyze the three sentences that describe the next task. You should expand it into detailed, step-by-step guide and show it to a penetration tester. The tester will follow your guide to perform the penetration testing.
    - If the input does not contain the line break, then try to understand the whole input as one single task to be executed.
(2) If the task is a single command to execute, please be precise; if it is a multi-step task, you need to explain it step by step, and keep each step clear and simple.
(3) Keep the output short and precise, without too detailed instructions.

The information is below: \n\n"""

    update_task_tree: str = """The anlysis of previous task is summarized below. Please follow the instruction and update the task tree. Remind that the fault may be related to logic faults, and the functions related to price calculation (e.g., functions like getprice or convertvghst) or customized business logic are more likely to be further investigated. However, you need to also keep in mind that the transaction may be related to other types of faults, such as insufficient validations and reentrancy, do not limit your analysis to the above two points. Hence, the task is expected to cover necessary children calls as well (provide with address and function_name in the task tree if any). The current task tree is as follows: {task_tree}\nCurrent understanding of the transaction:{current_understanding}\nResult of just completed task: {task_completed}"""
