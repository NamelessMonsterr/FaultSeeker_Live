import json
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
        for token_transfer in self.txn_info['token_transfer']['edges']:
            source = token_transfer['source']
            target = token_transfer['target']
            token = token_transfer['label'].split('[')[0].strip()
            token_label = token_transfer['label'].split('[')[1].split(']')[0].strip()
            amount = float(token_transfer['label'].split('(')[1].split(')')[0].strip().replace(',', ''))
            if source == token:
                continue
            if source not in balance_change:
                balance_change[source]= {token:{'label': token_label, 'amount': 0}}
            elif token not in balance_change[source]:
                balance_change[source][token] = {'label': token_label, 'amount': 0}
            if target not in balance_change:
                balance_change[target]= {token:{'label': token_label, 'amount': 0}}
            elif token not in balance_change[target]:
                balance_change[target][token] = {'label': token_label, 'amount': 0}
            if source not in address_memo:
                address_memo[source] = {'label': ''}
            if target not in address_memo:
                address_memo[target] = {'label': ''}
            if token not in address_memo:
                address_memo[token] = {'label': token_label}
            balance_change[source][token]['amount'] -= amount
            balance_change[target][token]['amount'] += amount
        self.balance_change = balance_change
        self.address_memo = address_memo
        
    def _identify_victims(self):
        prompt_text = self.prompts.identify_victims.format(balance_change_summary=json.dumps(self.balance_change))
        result = self.agent.query(prompt_text)
        if isinstance(result, list):
            self.potential_victim = [address for address in result if address and (address in self.balance_change) and (address != '0x0000000000000000000000000000000000000000')]
    
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
