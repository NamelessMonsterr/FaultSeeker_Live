import os
import re
import json
import pandas
import subprocess
import urllib.request
import urllib.error
import pytz
from tqdm import tqdm
from dateutil import parser
import time
import networkx as nx
from html.parser import HTMLParser

class TransactionInfoCollector:

    # Public RPC endpoints used as a fallback when the block-explorer HTML
    # is blocked by a WAF / Cloudflare challenge.
    _CHAIN_RPC_MAP = {
        'ETH':       'https://eth.llamarpc.com',
        'ETHEREUM':  'https://eth.llamarpc.com',
        'POLYGON':   'https://polygon-bor-rpc.publicnode.com',
        'POLY':      'https://polygon-bor-rpc.publicnode.com',
        'FANTOM':    'https://rpc.fantom.network',
        'FTM':       'https://rpc.fantom.network',
        'ZKSYNC':    'https://mainnet.era.zksync.io',
        'AVALANCHE': 'https://avalanche-c-chain-rpc.publicnode.com',
        'AVAX':      'https://avalanche-c-chain-rpc.publicnode.com',
        'BSC':       'https://bsc-dataseed.binance.org',
        'BNB':       'https://bsc-dataseed.binance.org',
        'ARBITRUM':  'https://arb1.arbitrum.io/rpc',
        'ARB':       'https://arb1.arbitrum.io/rpc',
        'OPTIMISM':  'https://mainnet.optimism.io',
        'OP':        'https://mainnet.optimism.io',
        'BASE':      'https://mainnet.base.org',
        'GNOSIS':    'https://rpc.gnosischain.com',
    }

    def __init__(self):
        pass
    
    @staticmethod
    def _fetch_website_content(url):
        try:
            result = subprocess.run(
                ['curl', '-s', '-A',
                 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                 url],
                capture_output=True,
                encoding='utf-8',
                errors='ignore',
                check=True
            )
            return result.stdout
        except Exception:
            return None

    @staticmethod
    def _find_and_convert_datetimes(content):
        try:
            pattern = r'([A-Z][a-z]{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} [AP]M UTC)'
            datetime_strings = re.findall(pattern, content)
            if not datetime_strings:
                return ''
            local_tz = pytz.timezone(time.tzname[0])
            converted_datetimes = []
            for dt_str in datetime_strings:
                dt_utc = parser.parse(dt_str)
                dt_local = dt_utc.replace(tzinfo=pytz.UTC).astimezone(local_tz)
                converted_datetimes.append({
                    'original': dt_str,
                    'local': dt_local.strftime('%Y-%m-%d %H:%M:%S %Z')
                })
            return converted_datetimes[0]
        except Exception:
            return ''
    
    @staticmethod
    def _get_transaction_status(content):
        if '<!-- Status -->' in content:
            return content.split('<!-- Status -->')[1].split('</span></div>')[0].split('</i>')[-1].strip()
        else:
            return 'unknown'
    
    @staticmethod
    def _get_transaction_gas(content):
        pass
        
        
    @staticmethod
    def _get_transaction_block(content):
        block_number = -1
        confirmations = -1
        if '<!-- Block Height -->' in content:
            block_number = content.split('<!-- Block Height -->')[1].split('</a></span>')[0].split('>')[-1].strip()
            if 'Block Confirmations' in content:
                confirmations = content.split('Block Confirmations')[0].split('>')[-1].strip()
        else:
            pass
        return {
            'block_number': block_number,
            'confirmations': confirmations
        }

    @staticmethod
    def get_transaction_hash(txn_link):
        pattern = r'(0x[0-9a-fA-F]{64})'
        return re.findall(pattern, txn_link)
    
   
    def get_transaction_link(self, keyword):
        if 'eth' in keyword:
            self.txn_link = 'https://etherscan.io/tx/{}'.format(self.txn_hash)
        elif 'bsc' in keyword:
            self.txn_link = 'https://bscscan.com/tx/{}'.format(self.txn_hash)
        elif 'polygon' in keyword:
            self.txn_link = 'https://polygonscan.com/tx/{}'.format(self.txn_hash)
        elif 'optimism' in keyword:
            self.txn_link = 'https://optimistic.etherscan.com/tx/{}'.format(self.txn_hash)
        elif 'arbitrum' in keyword:
            self.txn_link = 'https://arbiscan.io/tx/{}'.format(self.txn_hash)
        elif 'avalanche' in keyword:
            self.txn_link = 'https://snowtrace.io/tx/{}'.format(self.txn_hash)
        elif 'fantom' in keyword:
            self.txn_link = 'https://ftmscan.com/tx/{}'.format(self.txn_hash)
        elif 'gnosis' in keyword:
            self.txn_link = 'https://gnosisscan.io/tx/{}'.format(self.txn_hash)
        elif 'base' in keyword:
            self.txn_link = 'https://basescan.org/tx/{}'.format(self.txn_hash)
    
    def _process_statement(self, statement, is_for_statement=False):
        class AddressTitles(HTMLParser):
            def __init__(self):
                super().__init__()
                self.matches = []

            def handle_starttag(self, tag, attrs):
                title = dict(attrs).get('title') or ''
                plain = re.fullmatch(r'0x[a-fA-F0-9]{40}', title.strip())
                named = re.fullmatch(r'(.*?)\s*\((0x[a-fA-F0-9]{40})\)', title.strip())
                if plain:
                    self.matches.append(('', plain.group(0)))
                elif named:
                    self.matches.append((named.group(1).strip(), named.group(2)))

        parser = AddressTitles()
        parser.feed(statement)
        name, address = parser.matches[0] if parser.matches else ('', '')
        if is_for_statement:
            if 'title=\'' in name:
                name = name.split('title=')[-1].strip().strip("'")
            value = pattern = r"\$([\d,]+\.\d+)</a>"
            value_found = re.findall(value, statement)
            if value_found:
                value = value_found[0]
            else:
                value = -1
            count = statement.split('</span>')[0].split('>')[-1].strip()
            return name, address, count, value
        else:
            return name, address
        
    def _find_address_info(self, content):
        from_address = ''
        to_address = []
        if '</i>From:' in content:
            from_address_statement = content.split('</i>From:')[1].split('</span>')[0]
            pattern = r"0x[a-fA-F0-9]{40}"
            matches = set(re.findall(pattern, from_address_statement.lower()))
            if len(matches) == 1:
                from_address = list(matches)[0]
        else:
            pass
        if 'Interacted With (To):' in content:
            to_address_statement = content.split('Interacted With (To):')[1].split('</i></div> ')[0]
            pattern = r"0x[a-fA-F0-9]{40}"
            matches = set(re.findall(pattern, to_address_statement.lower()))
            to_address = list(matches)
        elif 'To:' in content:
            to_address_statement = content.split('To:')[1].split('</span>')[0]
            pattern = r"0x[a-fA-F0-9]{40}"
            matches = set(re.findall(pattern, to_address_statement.lower()))
            to_address = list(matches)
        else:
            pass
        return {
            'from_address': from_address,
            'to_address': to_address
        }

    
    def _get_token_transferred(self, content):
        pattern = r'([A-Za-z0-9\-]+)\s+Tokens\s+Transferred:'
        token_list = re.findall(pattern, content)
        # Multiple assets/amounts can move between the same ordered pair.
        # A DiGraph silently overwrites earlier observed transfers.
        graph = nx.MultiDiGraph()
        for token in token_list:
            string_to_be_identified = f'{token} Tokens Transferred:'
            temp = content.split(string_to_be_identified)[1].split('From</span>')
            for t in temp:
                if 'To</span>' in t:
                    ttemp = t.split('To</span>')
                    from_statement = ttemp[0]
                    if 'For</span>' in ttemp[1]:
                        ttemp = ttemp[1].split('For</span>')
                        to_statement = ttemp[0]
                        for_statement = ttemp[1]
                        from_name, from_address = self._process_statement(from_statement)
                        to_name, to_address = self._process_statement(to_statement)
                        for_name, for_address, count, value = self._process_statement(for_statement, is_for_statement=True)
                        graph.add_node(from_address, label=f'{from_address} [{from_name}]')
                        graph.add_node(to_address, label=f'{to_address} [{to_name}]')
                        graph.add_edge(from_address, to_address, label=f'{for_address} [{for_name}] ({count})')
        return nx.node_link_data(graph,edges='edges')

    # temporary function to be removed
    def revise_token_transferred(self):
        os.makedirs(f'{self.cache_path}_revised', exist_ok=True)
        for file in os.listdir(self.cache_path):
            if file.endswith('.json'):
                data = json.load(open(os.path.join(self.cache_path, file), 'r'))
                if 'token_transfer' in data:
                    token_transfer = data['token_transfer']
                    for node in token_transfer['nodes']:
                        node['label'] = node['label'].split('[')[0].strip() if '[' in node['label'] else node['label']
                    for edge in token_transfer['edges']:
                        if len(edge['label']) > 100:
                            matches = re.findall(r'\(([0-9,]+(?:\.[0-9]+)?)\)', edge['label'])
                            amount = matches[0] if matches else ''
                            if 'title=' in edge['label']:
                                label = edge['label'].split('title=')[-1].strip().split(']')[0].strip().strip("'")
                                address = edge['label'].split('[')[0].strip()
                                edge['label'] = f'{address} [{label}] ({amount})'
                    data['token_transfer'] = token_transfer
                with open(os.path.join(f'{self.cache_path}_revised', file), 'w') as f:
                    json.dump(data, f, indent=2)
    
    def get_transaction_link(self, chain: str):
        """Build the block explorer URL for the given chain."""
        chain_upper = chain.upper()
        explorer_map = {
            'ETH':       'https://etherscan.io/tx/',
            'ETHEREUM':  'https://etherscan.io/tx/',
            'BSC':       'https://bscscan.com/tx/',
            'BNB':       'https://bscscan.com/tx/',
            'POLYGON':   'https://polygonscan.com/tx/',
            'POLY':      'https://polygonscan.com/tx/',
            'ARBITRUM':  'https://arbiscan.io/tx/',
            'ARB':       'https://arbiscan.io/tx/',
            'OPTIMISM':  'https://optimistic.etherscan.io/tx/',
            'OP':        'https://optimistic.etherscan.io/tx/',
            'BASE':      'https://basescan.org/tx/',
            'AVALANCHE': 'https://snowtrace.io/tx/',
            'AVAX':      'https://snowtrace.io/tx/',
            'ZKSYNC':    'https://explorer.zksync.io/tx/',
        }
        base_url = explorer_map.get(chain_upper, 'https://etherscan.io/tx/')
        self.txn_link = base_url + self.txn_hash

    @staticmethod
    def _fetch_via_rpc(rpc_url: str, txn_hash: str) -> dict:
        """Fetch transaction data directly from a JSON-RPC node.

        Used as a fallback when the block-explorer HTML is behind a WAF
        (e.g. Cloudflare) and the standard scraper returns no addresses.

        Returns a partial result dict with the same keys as the HTML parser,
        or an empty dict on failure.
        """
        def _rpc(url, method, params):
            payload = json.dumps({
                'jsonrpc': '2.0', 'method': method,
                'params': params, 'id': 1
            }).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={'Content-Type': 'application/json',
                         'User-Agent': 'FaultSeeker/1.0'},
                method='POST'
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return json.loads(resp.read().decode())
            except Exception:
                return {}

        tx_resp = _rpc(rpc_url, 'eth_getTransactionByHash', [txn_hash])
        tx = tx_resp.get('result') or {}
        if not tx:
            return {}

        receipt_resp = _rpc(rpc_url, 'eth_getTransactionReceipt', [txn_hash])
        receipt = receipt_resp.get('result') or {}

        # Pending, missing, pre-status, or malformed receipts do not establish
        # successful execution. Preserve this fallback's success-only contract.
        if not isinstance(receipt, dict) or receipt.get('status') != '0x1':
            return {}
        status = 'Success'

        from_addr = (tx.get('from') or '').lower()
        to_addr   = (tx.get('to')   or '').lower()

        block_hex = tx.get('blockNumber', '0x0')
        block_num = int(block_hex, 16) if block_hex else -1

        return {
            'status': status,
            'gas_consumption': None,
            'block_number': {'block_number': block_num, 'confirmations': -1},
            'address_info': {
                'from_address': from_addr,
                'to_address': [to_addr] if to_addr else [],
            },
            'transaction_hash': txn_hash,
            'transaction_date': '',
            'token_transfer': {},
            '_source': 'rpc_fallback',
        }

    @staticmethod
    def _fetch_via_registry(chain: str, txn_hash: str) -> dict:
        """Same contract as _fetch_via_rpc, but through the configured providers."""
        try:
            from faultseeker.utils.rpc_provider import rpc_call
            tx = rpc_call(chain.lower(), 'eth_getTransactionByHash', [txn_hash], timeout=20)
            if not isinstance(tx, dict) or not tx:
                return {}
            receipt = rpc_call(chain.lower(), 'eth_getTransactionReceipt', [txn_hash], timeout=20)
        except Exception:
            return {}
        if not isinstance(receipt, dict) or receipt.get('status') != '0x1':
            return {}
        from_addr = (tx.get('from') or '').lower()
        to_addr = (tx.get('to') or '').lower()
        try:
            block_num = int(tx.get('blockNumber') or '0x0', 16)
        except (TypeError, ValueError):
            block_num = -1
        return {
            'status': 'Success', 'gas_consumption': None,
            'block_number': {'block_number': block_num, 'confirmations': -1},
            'address_info': {'from_address': from_addr, 'to_address': [to_addr] if to_addr else []},
            'transaction_hash': txn_hash, 'transaction_date': '', 'token_transfer': {},
            '_source': 'rpc_fallback',
        }

    def run(self, txn_hash: str, chain: str) -> dict:
        """
        Collect transaction information for given transaction hash and chain.

        Primary path: parse the block-explorer HTML page.
        Fallback path: if HTML scraping yields no addresses (e.g. Cloudflare WAF
        blocks the request), query the chain RPC directly via JSON-RPC.

        Args:
            txn_hash: Transaction hash
            chain: Chain identifier (eth, bsc, polygon, etc.)

        Returns:
            Dictionary containing transaction information
        """
        self.txn_hash = txn_hash
        self.get_transaction_link(chain)

        # ── Primary: HTML scraping ────────────────────────────────────────────
        content = self._fetch_website_content(self.txn_link)

        if content:
            status_info = self._get_transaction_status(content)
            if status_info.lower() in ['failed', 'reverted']:
                return {}

            block_info   = self._get_transaction_block(content)
            tx_date      = self._find_and_convert_datetimes(content)
            address_info = self._find_address_info(content)
            token_transfer = self._get_token_transferred(content)
            gas          = self._get_transaction_gas(content)

            html_result = {
                'status':           status_info,
                'gas_consumption':  gas,
                'block_number':     block_info,
                'address_info':     address_info,
                'transaction_hash': txn_hash,
                'transaction_date': tx_date,
                'token_transfer':   token_transfer,
                '_source':          'html_scrape',
            }

            # If addresses were successfully extracted, we are done.
            has_from = bool(address_info.get('from_address'))
            has_to   = bool(address_info.get('to_address'))
            if has_from or has_to:
                return html_result

        # ── Fallback: direct JSON-RPC ─────────────────────────────────────────
        # Prefer the operator-configured provider registry ({CHAIN}_RPC_URL, the
        # same endpoint that served the trace) over hardcoded public nodes,
        # which are rate-limited/keyed and absent for many supported chains.
        rpc_result = self._fetch_via_registry(chain, txn_hash)
        if rpc_result:
            return rpc_result
        rpc_url = self._CHAIN_RPC_MAP.get(chain.upper())
        if rpc_url:
            rpc_result = self._fetch_via_rpc(rpc_url, txn_hash)
            if rpc_result:
                return rpc_result

        # If we got this far, return whatever the HTML gave us (may be partial).
        return html_result if content else {}
      
                       
if __name__ == "__main__":
    # df = pandas.read_csv('./transaction_links.csv')
    # df = df.dropna(subset=['txn_link'])
    # df['txn_link'] = df['txn_link'].apply(lambda x: eval(x))
    # for txn_links in tqdm(df['txn_link'].to_list()[868:]):
    #     for txn_link in txn_links:
    #         TransactionInfoCollector(txn_link).run()
    # TransactionInfoCollector('').revise_token_transferred()
    
    # df = pandas.read_csv('./dumps/transaction_links_defi.csv')
    # df = df.dropna(subset=['attack_tx'])
    # df['attack_tx'] = df['attack_tx'].apply(eval)
    # txn_links_list = df['attack_tx'].tolist()
    # collector = TransactionInfoCollector()
    # for txn_links in tqdm(txn_links_list):
    #     for txn_link in txn_links:
    #         TransactionInfoCollector().run_with_txn_link(txn_link)
            
    # collector = TransactionInfoCollector()
    # df = pandas.read_csv('./dumps/transaction_links_dappfl.csv')
    # for _,row in tqdm(df.iterrows()):
    #     txn_hash = row['transaction_hash']
    #     chain = row['chain']
    #     collector.run_with_txn_hash(txn_hash, chain)
    
    
    collector = TransactionInfoCollector()
    df = pandas.read_csv('./dumps/transaction_links_metatrustalert.csv')
    for _,row in tqdm(df.iterrows()):
        collector.run_with_txn_link(row['attack_tx'])
