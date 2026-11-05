import os
import re
import json
import pandas
import subprocess
import urllib.request
import pytz
from tqdm import tqdm
from dateutil import parser
import time
from urllib.parse import urlparse

class ContractInfoCollector:

    # Mirrors TransactionInfoCollector._CHAIN_RPC_MAP — used as fallback when
    # the block explorer is WAF-protected (e.g. Avalanche's snowtrace.io).
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

    def __init__(self, cache_path='./data/cache/contract_info'):
        self.cache_path = cache_path
        os.makedirs(cache_path, exist_ok=True)
    
    # Maximum wall-clock seconds for a single curl fetch.
    _FETCH_TIMEOUT_SECS = 15

    @staticmethod
    def _fetch_website_content(url):
        """Fetch URL content via curl with bounded timeout.

        curl --max-time limits total transfer time; subprocess timeout kills
        the process if curl itself hangs before that limit fires.
        Both are needed: subprocess.run timeout is wall-clock from Python's
        perspective; curl --max-time is enforced inside the curl process.
        """
        try:
            result = subprocess.run(
                ['curl', '-s', '-A',
                 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                 '--max-time', str(ContractInfoCollector._FETCH_TIMEOUT_SECS),
                 url],
                capture_output=True,
                encoding='utf-8',
                errors='ignore',
                check=True,
                # Hard outer deadline; doubles the curl limit to allow for startup.
                timeout=ContractInfoCollector._FETCH_TIMEOUT_SECS * 2,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return None
        except subprocess.CalledProcessError:
            # print(f"Error fetching website: {e}")
            return None

    @staticmethod
    def _find_and_convert_datetimes(content):
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
    
    # Maps netloc keyword (most-specific first) → base explorer URL
    _EXPLORER_ADDRESS_MAP = [
        ('optimistic.etherscan',  'https://optimistic.etherscan.io/address/'),
        ('bscscan',               'https://bscscan.com/address/'),
        ('polygonscan',           'https://polygonscan.com/address/'),
        ('arbiscan',              'https://arbiscan.io/address/'),
        ('snowtrace',             'https://snowtrace.io/address/'),
        ('basescan',              'https://basescan.org/address/'),
        ('ftmscan',               'https://ftmscan.com/address/'),
        ('gnosisscan',            'https://gnosisscan.io/address/'),
        ('etherscan',             'https://etherscan.io/address/'),
    ]

    def _get_contract_address_link(self, address: str, chain: str):
        """Build a block-explorer address URL from the active txn_link.

        Uses urlparse to extract the netloc so that a keyword like 'eth'
        cannot accidentally fire against a path or query-string segment.
        """
        txn_link = getattr(self, 'txn_link', '') or ''
        netloc = urlparse(txn_link).netloc.lower()

        for keyword, base_url in self._EXPLORER_ADDRESS_MAP:
            if keyword in netloc:
                self.contract_link = base_url + address
                return

        # Fallback: default to Ethereum mainnet
        self.contract_link = f'https://etherscan.io/address/{address}'
            
    def _is_contract(self, content):
        if 'Contract Creator' in content:
            return True
        return False
            
    def _get_contract_creator(self, content):
        pass
        
    def _check_cache(self, txn_hash):
        txn_hash = txn_hash.lower()
        cache_file = os.path.join(self.cache_path, f"{txn_hash}.json")
        if os.path.exists(cache_file):
            with open(cache_file, 'r') as f:
                return json.load(f)
        return None  
    
    def _save_cache(self, txn_hash, data):
        txn_hash = txn_hash.lower()
        cache_file = os.path.join(self.cache_path, f"{txn_hash}.json")
        with open(cache_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    @staticmethod
    def _is_contract_via_rpc(rpc_url: str, address: str) -> dict:
        """Determine if `address` is a contract via eth_getCode on an RPC node.

        A contract has bytecode (len > 2, i.e. not just '0x').
        Returns a result dict compatible with the HTML-scrape output.
        """
        try:
            payload = json.dumps({
                'jsonrpc': '2.0', 'method': 'eth_getCode',
                'params': [address, 'latest'], 'id': 1
            }).encode()
            req = urllib.request.Request(
                rpc_url, data=payload,
                headers={'Content-Type': 'application/json',
                         'User-Agent': 'FaultSeeker/1.0'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                code = data.get('result', '0x')
                is_contract = len(code) > 2  # '0x' = EOA, longer = smart contract
                return {
                    'contract_address': address,
                    'creator': None,
                    'is_contract': is_contract,
                    '_source': 'rpc_fallback',
                }
        except Exception:
            return {}

    def run(self, address, chain):
        """Check whether address is a contract on the given chain.

        Note: _get_contract_address_link builds the explorer URL from
        self.txn_link (set by caller before run()), not from the chain argument.
        The chain argument is used only for the RPC fallback when HTML scraping
        is unavailable or returns no contract creator. Latest bytecode is fetched,
        not historical state at the attack transaction block.
        """
        self._get_contract_address_link(address, chain)
        if self.contract_link:
            content = self._fetch_website_content(self.contract_link)
            if content:
                is_contract = self._is_contract(content)
                if is_contract:
                    creator = self._get_contract_creator(content)
                    result = {
                        "contract_address": address,
                        "creator": creator,
                        "is_contract": is_contract
                    }
                    self._save_cache(address, result)
                    return result
                else:
                    return {'is_contract': False}

        # Fallback: use RPC to check bytecode when HTML scraping fails.
        rpc_url = self._CHAIN_RPC_MAP.get((chain or '').upper())
        if rpc_url:
            rpc_result = self._is_contract_via_rpc(rpc_url, address)
            if rpc_result:
                return rpc_result

        return {}

                             
if __name__ == "__main__":
    # df = pandas.read_csv('./transaction_links.csv')
    # df = df.dropna(subset=['txn_link'])
    # df['txn_link'] = df['txn_link'].apply(lambda x: eval(x))
    # for txn_links in tqdm(df['txn_link'].to_list()[868:]):
    #     for txn_link in txn_links:
    #         TransactionInfoCollector(txn_link).run()
    # TransactionInfoCollector('').revise_token_transferred()
    
    df = pandas.read_csv('./dumps/transaction_links_defi.csv')
    df = df.dropna(subset=['attack_tx'])
    df['attack_tx'] = df['attack_tx'].apply(eval)
    txn_links_list = df['attack_tx'].tolist()
    for txn_links in tqdm(txn_links_list):
        for txn_link in txn_links:
            ContractInfoCollector(txn_link).run()
        