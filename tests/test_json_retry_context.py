import pytest
from faultseeker.utils.agent import AbstractAgent, JSON_RETRY_PROMPT


class DummyAgent(AbstractAgent):
    def __init__(self, responses):
        self.responses = list(responses)
        self.recorded_prompts = []
        super().__init__(task="dummy task", model_name="dummy_model")

    def _send_message(self, user_message: str, temperature=0) -> str:
        self.recorded_prompts.append(user_message)
        if self.responses:
            return self.responses.pop(0)
        return ""


def test_json_retry_preserves_task_across_all_repair_attempts():
    original_task = "Analyze function foo_0x1111111111111111111111111111111111111111 for reentrancy."
    # 2 invalid JSON responses, followed by 1 valid JSON response
    agent = DummyAgent([
        "Sorry, I cannot format this.",
        "Still not valid JSON: error.",
        '{"foo_0x1111111111111111111111111111111111111111": {"evidence": "reentrancy", "confidence_score": 0.9}}'
    ])

    result = agent.query(original_task, format="json")

    assert len(agent.recorded_prompts) == 3
    # Check that original task is present in all 3 attempts [yes, yes, yes]
    task_presence = [original_task in prompt for prompt in agent.recorded_prompts]
    assert task_presence == [True, True, True], f"Expected all True, got {task_presence}"
    assert "foo_0x1111111111111111111111111111111111111111" in result


def test_json_retry_respects_max_retries_and_returns_empty_on_exhaustion():
    original_task = "Find vulnerability"
    agent = DummyAgent([
        "invalid 1",
        "invalid 2",
        "invalid 3",
        "invalid 4",
    ])
    result = agent.query(original_task, format="json")
    assert result == {}
    assert len(agent.recorded_prompts) == 4  # 1 initial + 3 retries
    for p in agent.recorded_prompts:
        assert original_task in p
