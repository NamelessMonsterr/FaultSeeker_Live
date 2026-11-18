import abc
import ast
from contextvars import ContextVar
import json
from typing import Dict, List, Any, Union
import traceback
from ollama import Client as OllamaClient, chat
from openai import OpenAI
import os
from faultseeker.providers import ProviderConfigError, ResolvedModel, load_registry
from time import sleep
from datetime import datetime
from typing import NamedTuple



PROVIDER_ERROR_TEXT = "An error occurred."      # what _send_message returns when the provider call itself failed


class ModelResponseError(ValueError):
    """The model's reply is unusable under the JSON contract (provider failure, not JSON, or the wrong JSON shape).

    The message describes the problem and never quotes the reply, so nothing the model echoed can leak through it."""


class ProviderFailure(ModelResponseError):
    """The provider call failed, or answered without usable text (null, empty or non-text content). This is a provider
    failure, never a model answer: it can not be read as "yes", "not adequate" or any other reply.

    kind: call_failed | null_content | empty_content | non_text_content. The message never quotes the provider's reply."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class InputLimitExceeded(ProviderFailure):
    """The request was larger than the client's explicit input limit and was NOT sent (never silently cut).

    A ProviderFailure subclass on purpose: every caller already treats those as terminal and fail-closed (no retry of the same
    oversized request). kind is always 'input_limit'. The message gives sizes only and never quotes the prompt."""

    def __init__(self, message: str):
        super().__init__("input_limit", message)


class FittedPrompt(NamedTuple):
    text: str
    shortened: list          # labels of the sections that had to be shortened ([] when nothing was)
    omitted_chars: int


_OMITTED = "\n[… {n} characters omitted to fit the model input limit …]\n"


def _shorten(text: str, room: int) -> str:
    """Keeps the head and the tail of `text` in `room` characters, with an explicit marker in between."""
    marker = _OMITTED.format(n=len(text))
    keep = max(room - len(marker), 0)
    head = keep * 2 // 3
    return text[:head] + _OMITTED.format(n=len(text) - keep) + (text[len(text) - (keep - head):] if keep - head else "")


def fit_prompt(head: str, sections, tail: str, limit: int = None) -> FittedPrompt:
    """Builds `head + sections + tail` within `limit` characters under an explicit, reported policy.

    head and tail are REQUIRED text (instructions, candidate identifiers, the closing contract) and are never cut. `sections` is
    a list of (label, text) of compactable evidence: a section that does not fit is shortened to its head and its tail with a
    visible marker (the budget is shared fairly, small sections stay whole), and its label is reported in `shortened`. When
    the required parts alone do not fit, InputLimitExceeded is raised: nothing is silently dropped."""
    limit = GPTAgent.MAX_PROMPT_CHARS if limit is None else limit
    sections = [(label, str(text)) for label, text in sections]
    fixed = len(head) + len(tail)
    marker_cost = len(_OMITTED.format(n=10 ** 7))
    if fixed + sum(len(t) for _, t in sections) <= limit:
        return FittedPrompt(head + "".join(t for _, t in sections) + tail, [], 0)
    if fixed + marker_cost > limit:
        raise InputLimitExceeded(f"the required part of the request ({fixed} characters) does not fit the model input limit "
                                 f"of {limit} characters")
    budget = limit - fixed
    order = sorted(range(len(sections)), key=lambda i: len(sections[i][1]))
    room = {}
    left = budget
    for position, i in enumerate(order):
        fair = left // (len(order) - position)
        room[i] = min(len(sections[i][1]), fair)
        left -= room[i]
    parts, shortened, omitted = [], [], 0
    for i, (label, text) in enumerate(sections):
        if len(text) <= room[i]:
            parts.append(text)
        else:
            if room[i] < marker_cost + 40:
                raise InputLimitExceeded(f"section '{label}' cannot be fitted into the model input limit of {limit} characters")
            parts.append(_shorten(text, room[i]))
            shortened.append(label)
            omitted += len(text) - room[i]
    return FittedPrompt(head + "".join(parts) + tail, shortened, omitted)


# Pauses before each re-ask when the provider answered 200 but with unusable content (null / empty / non-text).
# Requests that raise are left to the client's own retry policy (max_retries in the provider registry).
CONTENT_RETRY_DELAYS = (1.0, 3.0)

# Scoped to the current execution context: a strict single-request operation
# must not trigger nested content retries in any real provider agent.
_STRICT_SINGLE_PROVIDER_REQUEST = ContextVar(
    "faultseeker_strict_single_provider_request",
    default=False,
)


class AbstractAgent(abc.ABC):
    
    def __init__(
        self, 
        task: str,
        model_name: str,
    ):
        self.model = model_name
        self.memory = []
        self._init_resources(task)

    def _init_resources(self, task):
        system_message = {
            "role": "system",
            "content": '\n'.join([
                task
            ])
        }
        self.memory.append(system_message)
    
    # to be implemented in the child class
    def _send_message(self, user_message: str, temperature = 0) -> str:
        pass

    @staticmethod
    def _require_text(content) -> str:
        """The provider's content as text, or ProviderFailure. Null, empty, non-text and the legacy error sentinel are
        failures, so None can never travel on as an answer (or into the conversation memory)."""
        if content is None:
            raise ProviderFailure("null_content", "the provider returned null content")
        if not isinstance(content, str):
            raise ProviderFailure("non_text_content", f"the provider returned non-text content ({type(content).__name__})")
        if not content.strip():
            raise ProviderFailure("empty_content", "the provider returned empty content")
        if content.strip() == PROVIDER_ERROR_TEXT:
            raise ProviderFailure("call_failed", "the provider call failed")
        return content

    def _send_message_strict(self, user_message: str, temperature = 0) -> str:
        """Provider call that either returns usable text or raises ProviderFailure. Subclasses with a real provider
        override it (validation plus bounded re-asks); the default validates whatever _send_message returned."""
        return self._require_text(self._send_message(user_message, temperature))

    def _chat_strict(self, user_message: str, call) -> str:
        """Shared strict provider call with bounded, optionally suppressed content retries.

        Ordinary calls retain the existing CONTENT_RETRY_DELAYS behavior.
        Structured single-request calls suppress nested retries without changing
        conversation-memory behavior or affecting concurrent execution contexts.
        """
        self.memory.append({"role": "user", "content": user_message})
        failure = None

        retry_count = (
            0
            if _STRICT_SINGLE_PROVIDER_REQUEST.get()
            else len(CONTENT_RETRY_DELAYS)
        )

        for attempt in range(retry_count + 1):
            if attempt:
                sleep(CONTENT_RETRY_DELAYS[attempt - 1])

            try:
                content = call()
            except Exception:
                traceback.print_exc()
                self.memory.append({"role": "assistant", "content": ''})
                raise ProviderFailure(
                    "call_failed",
                    "the provider call failed"
                ) from None

            try:
                text = self._require_text(content)
            except ProviderFailure as exc:
                failure = exc
                continue

            self.memory.append({"role": "assistant", "content": text})
            return text

        self.memory.append({"role": "assistant", "content": ''})
        raise failure

    def query_text(self, user_message: str, temperature = 0) -> str:
        """STRICT text contract: non-empty text, or ProviderFailure. Use it wherever the reply is read as text (it is
        searched, concatenated or stored); legacy query(format='str') can hand back the error sentinel instead."""
        return self._send_message_strict(user_message, temperature)
    
    @staticmethod
    def _literal(text: str):
        """json, then a Python literal. Never executes anything; raises ValueError when `text` is neither."""
        try:
            return json.loads(text)
        except ValueError:
            pass
        try:
            return ast.literal_eval(text)
        except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
            raise ValueError("not a data literal") from None

    def _process_json_response(self, response: str) -> Dict[str, Any]:
        """Legacy lenient parser (see query()): a data literal, else the old line-joining fallback, else the lines."""
        try:
            return self._literal(response)
        except ValueError:
            response = response.split("\n")
            if len(response) == 1:
                response = response[0].split('", "')
            output = []
            for res in response:
                temp = res.strip().strip('[').strip(']').strip('"').strip("'")
                if '```' in temp:
                    output.append(temp.replace('```', '').strip())
                    break
                if temp:
                    output.append(temp)
            try:
                return self._literal(''.join(output))
            except ValueError:
                return output

    def _process_dict_response(self, response: str) -> Dict[str, Any]:
        try:
            return self._literal(response)
        except ValueError:
            return [response]

    def _process_response(self, response: str, format: str) -> Union[List[str], Dict[str, Any]]:
        if '```json' in response:
            response = response.split('```json')[1]
            if '```' in response:
                response = response.split('```')[0]
        elif '```solidity' in response:
            response = response.split('```solidity')[1]
            if '```' in response:
                response = response.split('```')[0]
        elif '```python' in response:
            response = response.split('```python')[1]
            if '```' in response:
                response = response.split('```')[0]
        response = response.strip('```').strip('\n').strip()
        if format == 'json':
            return self._process_json_response(response)
        elif format == 'dict':
            return self._process_dict_response(response)


    @staticmethod
    def _unfence(text: str) -> str:
        for marker in ('```json', '```solidity', '```python'):
            if marker in text:
                text = text.split(marker)[1]
                if '```' in text:
                    text = text.split('```')[0]
                break
        return text.strip('```').strip('\n').strip()

    def query_json(self, user_message: str, temperature=0, expect=(dict, list)):
        """STRICT JSON contract: returns a parsed value whose type is in `expect`, or raises ModelResponseError.

        Never returns raw text, never guesses a structure out of plain lines, never uses eval(). A JSON document is
        parsed with json.loads, then (models often answer with Python literals such as single quotes or tuples) with
        ast.literal_eval. A provider failure, an empty reply, unparsable text, or a value of another type is an error.
        Callers decide whether to retry, skip the optional piece or fail the candidate; none can mistake text for data.
        """
        expect = tuple(expect) if isinstance(expect, (tuple, list)) else (expect,)
        wanted = " or ".join(t.__name__ for t in expect)

        failure_message = None
        for attempt in range(len(CONTENT_RETRY_DELAYS) + 1):
            if attempt:
                sleep(CONTENT_RETRY_DELAYS[attempt - 1])
                retry_message = (
                    user_message
                    + "\n\nYour previous reply did not satisfy the required JSON response "
                    + f"contract. Reply again with only valid JSON or a Python literal "
                    + f"whose top-level type is {wanted}. Do not include commentary "
                    + "or code fences. Preserve the requested task and do not invent "
                    + "missing information."
                )
            else:
                retry_message = user_message

            # Keep ProviderFailure behavior unchanged; only structured parsing/type
            # failures below are eligible for these re-asks.
            text = self._send_message_strict(retry_message, temperature)
            body = self._unfence(text)

            try:
                value = json.loads(body)
            except ValueError:
                try:
                    value = ast.literal_eval(body)
                except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
                    failure_message = (
                        f"the model reply is not valid JSON "
                        f"(expected {wanted}, {len(text)} characters)"
                    )
                    continue

            if not isinstance(value, expect):
                failure_message = (
                    f"the model reply has the wrong JSON type: expected {wanted}, "
                    f"got {type(value).__name__}"
                )
                continue

            return value

        raise ModelResponseError(
            "the model reply remained unusable after "
            f"{len(CONTENT_RETRY_DELAYS) + 1} attempts "
            f"(expected {wanted}; {failure_message or 'invalid structured reply'})"
        ) from None

    def query_json_once(self, user_message: str, temperature=0, expect=(dict, list)):
        """Perform exactly one provider request and strictly parse its structured reply.

        No content retries, parsing retries, or type retries are performed here.
        The caller owns the aggregate retry budget.
        """
        expect = tuple(expect) if isinstance(expect, (tuple, list)) else (expect,)
        wanted = " or ".join(t.__name__ for t in expect)

        token = _STRICT_SINGLE_PROVIDER_REQUEST.set(True)
        try:
            text = self._send_message_strict(user_message, temperature)
        finally:
            _STRICT_SINGLE_PROVIDER_REQUEST.reset(token)

        body = self._unfence(text)

        try:
            try:
                value = json.loads(body)
            except ValueError:
                value = ast.literal_eval(body)
        except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
            raise ModelResponseError(
                f"the model reply is not valid structured data "
                f"(expected {wanted}, {len(text)} characters)"
            ) from None

        if not isinstance(value, expect):
            raise ModelResponseError(
                f"the model reply has the wrong JSON type: expected {wanted}, "
                f"got {type(value).__name__}"
            )

        return value

    def query(self, user_message: str, temperature = 0, format='json') -> str:
        """Legacy, lenient: with format='json' the reply may come back as raw text or a list of lines when it cannot be
        parsed. Use query_json() wherever the result is consumed as a structure; keep this only for callers that
        check the type themselves."""
        result = self._send_message(user_message, temperature)
        if format == 'str':
            return result
        try:
            return self._process_response(result, format)
        except Exception:
            try:
                return self._process_response(result, format)
            except Exception:
                return result
    


class OllmaAgent(AbstractAgent):
    def __init__(self, task, model_name: str = "deepseek-r1:14b", host: str = None):
        super().__init__(task, model_name)
        self._client = OllamaClient(host=host) if host else None

    def _send_message_strict(self, user_message: str, temperature = 0.3) -> str:
        def call():
            send = self._client.chat if self._client else chat
            response = send(model=self.model, messages=self.memory, options={'temperature': temperature})
            return response['message']['content']
        return self._chat_strict(user_message, call)

    def _send_message(self, user_message: str, temperature = 0.3) -> str:
        try:
            return self._send_message_strict(user_message, temperature)
        except ProviderFailure:
            return PROVIDER_ERROR_TEXT
    


class GPTAgent(AbstractAgent):
    """Chat agent for any OpenAI-compatible endpoint described by the provider registry.

    The endpoint, the exact model ID, the API-key environment variable and the request parameters all come from the
    registry entry. Nothing is inferred from the model name. The OpenAI client's automatic retries are disabled
    unless the provider says otherwise, and parameters are sent exactly as configured (never silently dropped or
    changed after an error), so a provider that rejects a parameter fails visibly instead of being worked around.
    """

    # Explicit input-limit policy: a request longer than this many characters is never sent cut. It is either fitted by the caller
    # (fit_prompt, with the shortening reported) or refused as InputLimitExceeded before any request is made.
    MAX_PROMPT_CHARS = 10000

    def __init__(self, task, model):
        if not isinstance(model, ResolvedModel):
            model = load_registry().resolve(model)
        if model.provider.type != 'openai_compatible':
            raise ProviderConfigError(f"Provider '{model.provider.id}' is not OpenAI-compatible.")
        self.resolved = model
        key_env = model.provider.api_key_env
        api_key = os.environ.get(key_env, '').strip() if key_env else ''
        if key_env and not api_key:
            raise ProviderConfigError(f"No API key for provider '{model.provider.id}': set {key_env} in the environment or in .env.")
        self._client = OpenAI(api_key=api_key or 'no-key-required', base_url=model.base_url,
                              max_retries=model.provider.max_retries, timeout=model.provider.timeout_seconds)
        super().__init__(task, model_name=model.model_id)

    def _truncate_history(self, history, max_turns=1):
        system_prompt = history[0]
        message_pairs = history[1:]
        truncated = message_pairs[-(max_turns * 2):]
        return [system_prompt] + truncated

    def _request_params(self, temperature):
        params = dict(self.resolved.extra_params)
        if self.resolved.temperature_mode == 'pass':
            params['temperature'] = temperature
        elif self.resolved.temperature_mode == 'fixed':
            params['temperature'] = self.resolved.temperature_value
        return params

    def _send_message_strict(self, user_message, temperature=0):
        if len(user_message) > self.MAX_PROMPT_CHARS:
            raise InputLimitExceeded(f"the request has {len(user_message)} characters, over the model input limit of "
                                     f"{self.MAX_PROMPT_CHARS}; it was not sent")

        def call():
            completion = self._client.chat.completions.create(
                messages=self._truncate_history(self.memory),
                model=self.model,
                **self._request_params(temperature)
            )
            choices = getattr(completion, 'choices', None)
            return choices[0].message.content if choices else None       # no choices counts as no content
        return self._chat_strict(user_message, call)

    def _send_message(self, user_message, temperature=0):
        """Legacy contract (query() with format 'str'/'json'/'dict'): the error sentinel on any provider failure."""
        try:
            return self._send_message_strict(user_message, temperature)
        except ProviderFailure:
            return PROVIDER_ERROR_TEXT
