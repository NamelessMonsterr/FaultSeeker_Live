import abc
import ast
import json
from typing import Dict, List, Any, Union
import traceback
from ollama import Client as OllamaClient, chat
from openai import OpenAI
import os
from faultseeker.providers import ProviderConfigError, ResolvedModel, load_registry
from time import sleep
from datetime import datetime



PROVIDER_ERROR_TEXT = "An error occurred."      # what _send_message returns when the provider call itself failed


class ModelResponseError(ValueError):
    """The model's reply is unusable under the JSON contract (provider failure, not JSON, or the wrong JSON shape).

    The message describes the problem and never quotes the reply, so nothing the model echoed can leak through it."""


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
    
    def _process_json_response(self, response: str) -> Dict[str, Any]:
        try:
            return eval(response)
        except Exception:
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
                output = eval(''.join(output))
            except Exception:
                pass
            return output
        
    def _process_dict_response(self, response: str) -> Dict[str, Any]:
        try:
            return eval(response)
        except Exception:
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
        text = self._send_message(user_message, temperature)
        if not isinstance(text, str) or not text.strip():
            raise ModelResponseError("the model returned no reply")
        if text.strip() == PROVIDER_ERROR_TEXT:
            raise ModelResponseError("the model call failed (provider error)")
        body = self._unfence(text)
        try:
            value = json.loads(body)
        except ValueError:
            try:
                value = ast.literal_eval(body)
            except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
                raise ModelResponseError(f"the model reply is not valid JSON (expected {wanted}, {len(text)} characters)") from None
        if not isinstance(value, expect):
            raise ModelResponseError(f"the model reply has the wrong JSON type: expected {wanted}, got {type(value).__name__}")
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

    def _send_message(self, user_message: str, temperature = 0.3) -> str:
        self.memory.append({"role": "user", "content": user_message})
        try:
            send = self._client.chat if self._client else chat
            response = send(model=self.model, messages=self.memory, options={'temperature': temperature})
            assistant_response = response['message']['content']
            self.memory.append({"role": "assistant", "content": assistant_response})
            return assistant_response
        except Exception:
            traceback.print_exc()
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

    def _send_message(self, user_message, temperature=0):
        try:
            user_message = user_message[:10000]
            self.memory.append({"role": "user", "content": user_message})
            chat_completion = self._client.chat.completions.create(
                messages=self._truncate_history(self.memory),
                model=self.model,
                **self._request_params(temperature)
            )
            reply = chat_completion.choices[0].message.content
            self.memory.append({"role": "assistant", "content": reply})
            return reply
        except Exception:
            traceback.print_exc()
            self.memory.append({"role": "assistant", "content": ''})
            return PROVIDER_ERROR_TEXT
