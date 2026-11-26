import abc
import ast
from contextlib import contextmanager
from contextvars import ContextVar
import json
from typing import Dict, List, Any, Union
import traceback
from ollama import Client as OllamaClient, chat
from openai import OpenAI
import os
from faultseeker.budget import BudgetExceeded, InputBudget, Part, fit_parts
from faultseeker.providers import ProviderConfigError, ResolvedModel, load_registry
from time import monotonic, sleep
from datetime import datetime



PROVIDER_ERROR_TEXT = "An error occurred."      # what _send_message returns when the provider call itself failed


class ModelResponseError(ValueError):
    """The model's reply is unusable under the JSON contract (provider failure, not JSON, or the wrong JSON shape).

    The message describes the problem and never quotes the reply, so nothing the model echoed can leak through it."""


class ProviderFailure(ModelResponseError):
    """The provider call failed, or answered without usable text (null, empty or non-text content). This is a provider
    failure, never a model answer: it can not be read as "yes", "not adequate" or any other reply.

    kind: call_failed | null_content | empty_content | non_text_content | deadline. The message never quotes the provider's reply."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


class InputLimitExceeded(ProviderFailure):
    """The request does not fit the model's input budget and was NOT sent (never silently cut).

    A ProviderFailure subclass on purpose: every caller already treats those as terminal and fail-closed (no retry of the same oversized
    request). kind is always 'input_limit'. The message gives sizes only and never quotes the prompt. `detail` carries the numbers
    (estimated tokens, limits, the budget's sources) for logs and reports; the cause is an application budget, not a provider outage."""

    def __init__(self, message: str, detail: dict = None):
        super().__init__("input_limit", message)
        self.detail = detail or {}


# Pauses before each re-ask when the provider answered 200 but with unusable content (null / empty / non-text).
CONTENT_RETRY_DELAYS = (1.0, 3.0, 8.0)
# Pauses before each re-send of a request that RAISED for a transient reason (timeout, connection error, HTTP 408/409/425/429/5xx).
# Permanent errors (400, 401, 403, 404, 422, ...) are never retried. Single-request operations (query_json_once) are never retried here.
TRANSIENT_RETRY_DELAYS = (2.0, 6.0, 15.0)

# Wall-clock budget of the current stage/candidate (a monotonic deadline). Once it has passed no further provider request is started
# and the failure is terminal, so a flaky provider cannot keep a run silent for tens of minutes.
_DEADLINE = ContextVar("faultseeker_deadline", default=None)


@contextmanager
def deadline(seconds):
    """Limits every provider request started inside the block to `seconds` of wall clock (nesting keeps the earlier deadline)."""
    when = monotonic() + float(seconds)
    current = _DEADLINE.get()
    token = _DEADLINE.set(when if current is None else min(current, when))
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def remaining_seconds():
    """Seconds left of the current deadline, or None when there is none."""
    when = _DEADLINE.get()
    return None if when is None else when - monotonic()


def describe_provider_exception(exc: BaseException):
    """(label, status, transient) of an exception raised by a provider call. The label is the class name and, for an HTTP error, the
    status code; it never contains the response body or any secret. transient says whether sending the same request again can help."""
    name = type(exc).__name__
    status = getattr(exc, "status_code", None)
    if not isinstance(status, int):
        response = getattr(exc, "response", None)
        status = getattr(response, "status_code", None)
        status = status if isinstance(status, int) else None
    label = f"{name} HTTP {status}" if status else name
    if status is not None:
        return label, status, status in (408, 409, 425, 429) or 500 <= status <= 599
    lowered = name.lower()
    transient = any(w in lowered for w in ("timeout", "connect", "connection", "remoteprotocol", "readerror", "writeerror", "pooltimeout",
                                           "incompleteread", "brokenpipe", "eof"))
    return label, None, transient or isinstance(exc, (TimeoutError, ConnectionError))


def _body_prefix(exc: BaseException, limit: int = 160) -> str:
    """The first characters of an HTTP error body, for the technical log only (the run's redactor scrubs known secrets)."""
    response = getattr(exc, "response", None)
    text = getattr(response, "text", None)
    if not isinstance(text, str):
        text = repr(getattr(exc, "body", "") or "")
    return " ".join(text.split())[:limit]

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

    # Input budget of the model behind this agent (faultseeker.budget.InputBudget); None means "not enforced" (test doubles only:
    # agents built from the registry always have one).
    budget = None

    def _truncate_history(self, history, max_turns=1):
        """The messages actually retained for a request: the system message and the last `max_turns` exchanges."""
        return [history[0]] + history[1:][-(max_turns * 2):]

    def _messages_for_request(self, user_message: str):
        """Exactly the messages a request with `user_message` would send (system + retained history + the new message)."""
        return self._truncate_history(self.memory + [{"role": "user", "content": user_message}])

    def input_room_bytes(self) -> int:
        """UTF-8 bytes still available for the NEXT user message, given the budget and what else is sent with it."""
        if self.budget is None:
            return 1 << 62
        sent = self._messages_for_request("")[:-1]
        tokens = self.budget.input_limit_tokens - self.budget.message_tokens(sent) - self.budget.per_message_tokens
        return self.budget.bytes_for_tokens(tokens)

    def _enforce_budget(self, user_message: str) -> None:
        """Refuses (InputLimitExceeded, nothing sent) a request that does not fit the budget. Counts every message that is sent: the
        system message, the retained history and the new user message, plus the reserved output and the safety margin."""
        if self.budget is None:
            return
        messages = self._messages_for_request(user_message)
        needed = self.budget.message_tokens(messages)
        limit = self.budget.input_limit_tokens
        if needed > limit:
            raise InputLimitExceeded(
                f"the request needs about {needed:,} estimated tokens across {len(messages)} messages, over this model's input budget of "
                f"{limit:,} ({self.budget.context_tokens:,} context - {self.budget.output_reserve_tokens:,} reserved output - "
                f"{self.budget.margin_tokens:,} margin); it was not sent",
                detail={"needed_tokens": needed, "input_limit_tokens": limit, "budget": self.budget.describe()})

    def fit(self, parts):
        """Joins prompt `parts` (faultseeker.budget.Part) within this model's budget. Returns (text, reductions); the reductions list is
        empty when nothing was cut. Required parts are never cut: when they alone do not fit, InputLimitExceeded is raised."""
        if self.budget is None:
            return "".join(p.text for p in parts), []
        try:
            fitted = fit_parts(parts, self.input_room_bytes())
        except BudgetExceeded as exc:
            d = exc.detail
            raise InputLimitExceeded(
                f"the required part of the request ({d['required_bytes']:,} bytes) does not fit this model's input budget "
                f"({d['room_bytes']:,} bytes available for this message even with all reducible evidence omitted)",
                detail=dict(d, budget=self.budget.describe())) from None
        return fitted.text, fitted.reductions

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
        self._enforce_budget(user_message)
        return self._require_text(self._send_message(user_message, temperature))

    def _chat_strict(self, user_message: str, call) -> str:
        """Shared strict provider call with bounded, optionally suppressed content retries.

        Ordinary calls retain the existing CONTENT_RETRY_DELAYS behavior.
        Structured single-request calls suppress nested retries without changing
        conversation-memory behavior or affecting concurrent execution contexts.
        """
        self.memory.append({"role": "user", "content": user_message})
        failure = None

        single = _STRICT_SINGLE_PROVIDER_REQUEST.get()
        content_retries = 0 if single else len(CONTENT_RETRY_DELAYS)
        transient_retries = 0 if single else len(TRANSIENT_RETRY_DELAYS)
        content_used = transient_used = 0

        def out_of_time(delay=0.0):
            left = remaining_seconds()
            return left is not None and left <= delay + 1.0

        while True:
            if out_of_time():
                self.memory.append({"role": "assistant", "content": ''})
                raise ProviderFailure("deadline", "the wall-clock budget for this stage ended before the provider answered")
            try:
                content = call()
            except Exception as exc:
                traceback.print_exc()
                label, status, transient = describe_provider_exception(exc)
                print(f"Provider call failed: {label}" + (f" body={_body_prefix(exc)!r}" if status else ""), flush=True)
                if transient and transient_used < transient_retries:
                    delay = TRANSIENT_RETRY_DELAYS[transient_used]
                    if not out_of_time(delay):
                        transient_used += 1
                        print(f"         retrying the provider request in {delay:g}s ({transient_used}/{transient_retries})", flush=True)
                        sleep(delay)
                        continue
                self.memory.append({"role": "assistant", "content": ''})
                raise ProviderFailure("call_failed", f"the provider call failed ({label})") from None

            try:
                text = self._require_text(content)
            except ProviderFailure as exc:
                failure = exc
                if content_used < content_retries:
                    delay = CONTENT_RETRY_DELAYS[content_used]
                    if not out_of_time(delay):
                        content_used += 1
                        sleep(delay)
                        continue
                break

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
    def __init__(self, task, model_name: str = "deepseek-r1:14b", host: str = None, budget: InputBudget = None):
        super().__init__(task, model_name)
        self._client = OllamaClient(host=host) if host else None
        self.budget = budget

    def _send_message_strict(self, user_message: str, temperature = 0.3) -> str:
        self._enforce_budget(user_message)

        def call():
            send = self._client.chat if self._client else chat
            options = {'temperature': temperature}
            messages = self.memory
            if self.budget is not None:
                # Ollama silently drops the front of a prompt that exceeds its context window, so the window is stated explicitly
                # (it is the one the budget was computed for) and only the retained history is sent, as for the other providers.
                options['num_ctx'] = self.budget.context_tokens
                messages = self._truncate_history(self.memory)
            response = send(model=self.model, messages=messages, options=options)
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

    def __init__(self, task, model):
        if not isinstance(model, ResolvedModel):
            model = load_registry().resolve(model)
        if model.provider.type != 'openai_compatible':
            raise ProviderConfigError(f"Provider '{model.provider.id}' is not OpenAI-compatible.")
        self.resolved = model
        self.budget = model.budget
        key_env = model.provider.api_key_env
        api_key = os.environ.get(key_env, '').strip() if key_env else ''
        if key_env and not api_key:
            raise ProviderConfigError(f"No API key for provider '{model.provider.id}': set {key_env} in the environment or in .env.")
        self._client = OpenAI(api_key=api_key or 'no-key-required', base_url=model.base_url,
                              max_retries=model.provider.max_retries, timeout=model.provider.timeout_seconds)
        super().__init__(task, model_name=model.model_id)

    def _request_params(self, temperature):
        params = dict(self.resolved.extra_params)
        if self.resolved.temperature_mode == 'pass':
            params['temperature'] = temperature
        elif self.resolved.temperature_mode == 'fixed':
            params['temperature'] = self.resolved.temperature_value
        return params

    def _send_message_strict(self, user_message, temperature=0):
        self._enforce_budget(user_message)

        def call():
            extra = {}
            left = remaining_seconds()
            if left is not None:                       # never wait longer than the stage has left
                extra['timeout'] = max(5.0, min(float(getattr(getattr(self.resolved, 'provider', None), 'timeout_seconds', 120.0)), left))
            completion = self._client.chat.completions.create(
                messages=self._truncate_history(self.memory),
                model=self.model,
                **self._request_params(temperature),
                **extra
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
