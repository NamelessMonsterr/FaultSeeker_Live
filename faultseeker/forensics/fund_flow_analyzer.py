import json
from decimal import Decimal, DecimalException, Inexact, localcontext
from time import time
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
        
    
    def _get_balance_change(self):
        balance_change = {}
        address_memo = {}
        transfers = self.txn_info.get('token_transfer') or {}
        if not isinstance(transfers, dict) or not isinstance(transfers.get('edges', []), list):
            raise ValueError('Token transfer metadata is malformed')
        token_transfers = transfers.get('edges', [])
        # Bounded input exponent/digit lengths make this precision sufficient
        # for exact addition/subtraction across ordinary EVM transfer datasets.
        with localcontext() as context:
            context.prec = 4096
            context.traps[Inexact] = True
            for token_transfer in token_transfers:
                try:
                    source = token_transfer['source']
                    target = token_transfer['target']
                    if not isinstance(source, str) or not source or not isinstance(target, str) or not target:
                        raise ValueError('Invalid transfer addresses')
                    source, target = source.lower(), target.lower()
                    label = token_transfer.get('label', '')
                    if not isinstance(label, str) or '[' not in label or '(' not in label:
                        raise ValueError('Invalid transfer label')
                    token = label.split('[')[0].strip().lower()
                    if not token:
                        raise ValueError('Missing transfer asset')
                    token_label = label.split('[')[1].split(']')[0].strip()
                    amount_str = label.split('(')[1].split(')')[0].strip().replace(',', '')
                    if len(amount_str) > 1024:
                        raise ValueError('Transfer amount exceeds parsing limit')
                    amount = Decimal(amount_str)
                    if not amount.is_finite() or amount < 0 or abs(amount.adjusted()) > 1024:
                        raise ValueError('Invalid transfer amount')
                    if source not in balance_change:
                        balance_change[source] = {token: {'label': token_label, 'amount': Decimal(0)}}
                    elif token not in balance_change[source]:
                        balance_change[source][token] = {'label': token_label, 'amount': Decimal(0)}
                    if target not in balance_change:
                        balance_change[target] = {token: {'label': token_label, 'amount': Decimal(0)}}
                    elif token not in balance_change[target]:
                        balance_change[target][token] = {'label': token_label, 'amount': Decimal(0)}
                    if source not in address_memo:
                        address_memo[source] = {'label': ''}
                    if target not in address_memo:
                        address_memo[target] = {'label': ''}
                    if token not in address_memo:
                        address_memo[token] = {'label': token_label}
                    balance_change[source][token]['amount'] -= amount
                    balance_change[target][token]['amount'] += amount
                    if any(not balance_change[address][token]['amount'].is_finite() for address in (source, target)):
                        raise ValueError('Invalid transfer total')
                except (IndexError, ValueError, KeyError, TypeError, DecimalException):
                    raise ValueError('Token transfer data is malformed; fund-flow analysis is incomplete') from None
        # JSON numbers are commonly coerced back to binary floats. Preserve the
        # exact observed token quantities as decimal strings, never native profit.
        for tokens in balance_change.values():
            for details in tokens.values():
                details['amount'] = format(details['amount'], 'f')
        self.balance_change = balance_change
        self.address_memo = address_memo
        
    def _identify_victims(self):
        prompt_text = self.prompts.identify_victims.format(balance_change_summary=json.dumps(self.balance_change))
        result = self.agent.query(prompt_text)
        if isinstance(result, dict):
            result = result.get('victims')
        if not isinstance(result, list) or any(not isinstance(address, str) for address in result):
            raise ValueError('Invalid victim response; expected an address list')
        self.potential_victim = list(dict.fromkeys(
            address.lower() for address in result if address
            and address.lower() in self.balance_change
            and address.lower() != '0x0000000000000000000000000000000000000000'
        ))

    def _identify_attackers(self):
        info = self.txn_info.get('address_info') or {}
        targets = info.get('to_address') or []
        if isinstance(targets, str):
            targets = [targets]
        candidates = [info.get('from_address')] + list(targets)
        for address in candidates:
            if not isinstance(address, str) or not address:
                continue
            address = address.lower()
            if address == str(info.get('from_address') or '').lower() or address not in self.potential_victim:
                if address not in self.potential_attacker:
                    self.potential_attacker.append(address)


    def run(self, txn_info):
        self.txn_info = txn_info
        self.graph = None
        self.flow_summary = []
        self.potential_attacker = []
        self.potential_victim = []
        self.balance_change = {}
        self.address_memo = {}
        if isinstance(self.txn_info, dict) and self.txn_info.get('transaction_hash'):
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
