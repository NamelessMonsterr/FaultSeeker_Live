import json
import re
from decimal import Decimal, localcontext
from time import time
from faultseeker.forensics.contracts import ask_list, parse_victims
from faultseeker.prompts.forensics.fund_flow_prompts import FundFlowPrompts
from faultseeker.utils.utils import build_agent

class FundFlowAnalyzer:

    def __init__(self, model='gpt-4o-mini'):
        self.prompts = FundFlowPrompts()
        self.agent = build_agent('', model)
        
        self.txn_info = None
        self.graph = None
        self.flow_summary = []
        self.potential_attacker = []
        self.potential_victim = []
        self.balance_change = {}
        
    
    _AMOUNT = re.compile(r"^\s*([0-9][0-9,]*(?:\.[0-9]+)?)")
    RAW_UNIT = 'raw units (decimals unknown)'
    TOKEN_UNIT = 'token units'

    @classmethod
    def _parse_amount(cls, text: str):
        """(exact Decimal, unit) of a transfer label's amount text. '1,234.5' is token units; '1,234 raw units, decimals unknown' is the raw
        integer of a token whose decimals could not be read. Text that is not an amount is an error, never silently zero."""
        match = cls._AMOUNT.match(text or '')
        if not match:
            raise ValueError(f"transfer amount cannot be read: {str(text)[:60]!r}")
        return Decimal(match.group(1).replace(',', '')), (cls.RAW_UNIT if 'raw units' in text else cls.TOKEN_UNIT)

    @staticmethod
    def _plain(value: Decimal) -> str:
        """An exact decimal string without exponent or trailing zeros ('0' for zero, never '-0')."""
        text = format(value, 'f')
        if '.' in text:
            text = text.rstrip('0').rstrip('.')
        return '0' if text in ('', '-0') else text

    def _get_balance_change(self):
        balance_change = {}
        address_memo = {}
        for token_transfer in self.txn_info['token_transfer']['edges']:
            source = token_transfer['source']
            target = token_transfer['target']
            token = token_transfer['label'].split('[')[0].strip()
            token_label = token_transfer['label'].split('[')[1].split(']')[0].strip()
            amount, unit = self._parse_amount(token_transfer['label'].split('(')[1].split(')')[0].strip())
            if source == token:
                continue
            for holder in (source, target):
                balance_change.setdefault(holder, {}).setdefault(token, {'label': token_label, 'amount': Decimal(0), 'unit': self.TOKEN_UNIT})
            if source not in address_memo:
                address_memo[source] = {'label': ''}
            if target not in address_memo:
                address_memo[target] = {'label': ''}
            if token not in address_memo:
                address_memo[token] = {'label': token_label}
            with localcontext() as ctx:
                ctx.prec = 400                                   # exact for any realistic token amount; no float rounding anywhere
                balance_change[source][token]['amount'] -= amount
                balance_change[target][token]['amount'] += amount
            if unit == self.RAW_UNIT:
                balance_change[source][token]['unit'] = balance_change[target][token]['unit'] = self.RAW_UNIT
        for holdings in balance_change.values():
            for entry in holdings.values():
                entry['amount'] = self._plain(entry['amount'])    # JSON-safe, exact (a float or a JSON number would round beyond 2**53)
        self.balance_change = balance_change
        self.address_memo = address_memo
        
    def _identify_victims(self):
        prompt_text = self.prompts.identify_victims.format(balance_change_summary=json.dumps(self.balance_change))
        # Typed contract: a JSON/Python-literal list. A provider failure or an unusable reply raises (the stage fails); it is
        # never read as "no victims". An explicit [] is a valid answer.
        reply = ask_list(self.agent, prompt_text, "victim identification")
        self.potential_victim = parse_victims(reply, self.balance_change)
    
    def _identify_attackers(self):
        self.potential_attacker.append(self.txn_info['address_info']['from_address'])
        for addr in self.txn_info['address_info']['to_address']:
            if addr not in self.potential_victim:
                self.potential_attacker.append(addr)


    def run(self, txn_info):
        self.txn_info = txn_info
        if self.txn_info and self.txn_info['transaction_hash']:
            start = time()
            self._get_balance_change()
            self._identify_victims()
            self._identify_attackers()    
            result = {
                'analyze_duration': time() - start,
                'transaction_hash': self.txn_info['transaction_hash'],
                'potential_attacker': self.potential_attacker,
                'potential_victim': self.potential_victim,
                'balance_change': self.balance_change,
                'address_memo': self.address_memo,
            }
            return result
