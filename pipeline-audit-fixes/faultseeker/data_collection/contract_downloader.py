import os
import logging
import json
import shutil
import tempfile
import re
import hashlib
from faultseeker.utils.solidityParser.loc_parser import get_loc_info
from faultseeker.utils.explorer_provider import explorer_call, print_explorer_stats
from dotenv import load_dotenv
load_dotenv(override=True)


LOGGGING_FILE_PATH = './logs/get_source_code.log'
os.makedirs(os.path.dirname(LOGGGING_FILE_PATH), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename=LOGGGING_FILE_PATH, filemode='w'
)

CONTRACT_SOURCES = {
    'eth': 'https://etherscan.io/contractsverified',
    'bsc': 'https://bscscan.com/contractsverified',
    'poly': 'https://polygonscan.com/contractsverified',
    'fantom': 'https://ftmscan.com/contractsverified',
    'arbi': 'https://arbiscan.io/contractsverified',
    'avax': 'https://snowtrace.io/contractsverified',
    'opt': 'https://optimistic.etherscan.io/contractsverified',
    'base': 'https://basescan.org/contractsverified',
    'zksync': 'https://explorer.zksync.io/contractsverified',
    'linea': 'https://lineascan.build/contractsverified',
    'scroll': 'https://scrollscan.com/contractsverified',
    'gnosis': 'https://gnosisscan.io/contractsverified',
    'celo': 'https://celoscan.io/contractsverified',
    'cronos': 'https://cronoscan.com/contractsverified',
    'moonbeam': 'https://moonscan.io/contractsverified',
}


class ContractDownloader:

    def __init__(self, chain: str, address: list,
                 output_dir: str = './temp2',
                 cache_dir: str = './data/cache/contracts'):
        if not isinstance(chain, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', chain):
            raise ValueError('Invalid chain cache identity')
        addresses = [address] if isinstance(address, str) else list(address)
        if any(not isinstance(item, str) or not re.fullmatch(r'0x[0-9a-fA-F]{40}', item) for item in addresses):
            raise ValueError('Invalid contract address cache identity')
        self.chain = chain.lower()
        self.address = addresses
        self.output_dir = output_dir
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def get_source_code(chain, address, output_dir):
        """Download contract source code via block explorer API (adaptive failover)."""
        os.makedirs(output_dir, exist_ok=True)
        data = explorer_call(chain, {
            'module': 'contract',
            'action': 'getsourcecode',
            'address': address,
        })
        if not data or data.get('status') != '1' or not data.get('result'):
            logging.warning(f'No source for {address}[{chain}]: {data.get("message") if data else "all endpoints failed"}')
            return

        result = data['result'][0]
        source_code   = result.get('SourceCode', '')
        contract_name = result.get('ContractName', 'Contract') or 'Contract'
        # Explorer metadata is untrusted; never interpret it as a filesystem path.
        contract_name = re.sub(r'[^A-Za-z0-9_-]', '_', str(contract_name))[:120] or 'Contract'

        if not source_code:
            return

        # Handle multi-file source (JSON format wrapped in {{ }})
        if source_code.startswith('{{'):
            try:
                inner = json.loads(source_code[1:-1])
                sources = inner.get('sources', {})
                for path, content in sources.items():
                    basename = os.path.basename(path.replace('\\', '/'))
                    basename = re.sub(r'[^A-Za-z0-9_.-]', '_', basename)[:120] or 'Contract.sol'
                    safe_name = hashlib.sha256(path.encode('utf-8')).hexdigest()[:16] + '_' + basename
                    impl_dir  = os.path.join(output_dir, 'Implementation')
                    os.makedirs(impl_dir, exist_ok=True)
                    with open(os.path.join(impl_dir, safe_name), 'w', encoding='utf-8') as f:
                        f.write(content.get('content', ''))
                return
            except Exception:
                pass

        # Single file source
        impl_dir = os.path.join(output_dir, 'Implementation')
        os.makedirs(impl_dir, exist_ok=True)
        out_file = os.path.join(impl_dir, f'{contract_name}.sol')
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write(source_code)
        logging.info(f'Downloaded {address}[{chain}] -> {out_file}')

    @staticmethod
    def get_abi(chain: str, address: str) -> list | None:
        """Fetch ABI for a verified contract. Returns parsed list or None."""
        data = explorer_call(chain, {
            'module': 'contract',
            'action': 'getabi',
            'address': address,
        })
        if not data or data.get('status') != '1':
            return None
        try:
            return json.loads(data['result'])
        except Exception:
            return None

    @staticmethod
    def get_internal_txns(chain: str, txn_hash: str) -> list:
        """Fetch internal transactions for a hash (lightweight trace proxy)."""
        data = explorer_call(chain, {
            'module': 'account',
            'action': 'txlistinternal',
            'txhash': txn_hash,
            'sort':   'asc',
        })
        if not data or data.get('status') != '1':
            return []
        return data.get('result', [])



    def process_log(chain, address, output_root):
        f = open(LOGGGING_FILE_PATH, 'r')
        lines = f.readlines()
        f.close()
        output = []
        temp_output = ""

        # split the log file based on projects
        for line in lines:
            if "==========================================" in line:
                if temp_output != "":
                    output.append(temp_output)
                temp_output = ""
            else:
                temp_output += line
        
        # find projects with implementations
        implementations = {}
        for content in output:
            if f'{address}[{chain}]' in content:
                if 'Implementation/' in content:
                    content_lines = content.split('\n')
                    project_name = content_lines[0].split(' - ')[-1]
                    for line in content_lines:
                        path = line.split(' ')[-1].strip()
                        if 'Implementation/' in line:
                            if project_name not in implementations:
                                implementations[project_name] = [path]
                            else:
                                implementations[project_name].append(path)
            
        
        # save implementation to respective project dir
        for project_name in implementations:
            # temp = project_name.split('[')
            # address_temp = temp[0].strip()
            # chain_temp = temp[1].replace(']','').strip()
            project_dir = os.path.join(output_root, 'Implementation')
            os.makedirs(project_dir, exist_ok=True)
            for path in implementations[project_name]:
                # copy the file to project dir
                try:
                    shutil.copy(path, project_dir)
                except Exception:
                    # traceback.print_exc()
                    pass
             
    @staticmethod
    def parse_contract(output_dir):
        output = {}
        for root,_, files in os.walk(output_dir):
            for file in files:
                if file.endswith('.sol'):
                    content = open(os.path.join(root, file), 'r', encoding='utf-8').read()
                    lines = content.split('\n')
                    result = get_loc_info(content)
                    for contract in result:
                        for function in result[contract]['functions']:
                            primary = result[contract]['functions'][function]
                            for loc in primary.get('overloads', [primary]):
                                if isinstance(loc.get('start_offset'), int) and isinstance(loc.get('end_offset'), int):
                                    function_content = content[loc['start_offset']:loc['end_offset']]
                                else:
                                    function_content = '\n'.join(lines[loc['start_line']-1:loc['end_line']])
                                info = {'path': os.path.join(root, file).replace(output_dir, '.'),
                                        'start_line': loc['start_line'], 'end_line': loc['end_line'],
                                        'content': function_content, 'contract': contract,
                                        'kind': loc.get('kind', 'function'), 'has_body': loc.get('has_body')}
                                output.setdefault(function, []).append(info)
        return output
    
    def _load_cached_functions(self, path, address):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cached = json.load(f)
        except (OSError, ValueError):
            return None
        # Older bare dictionaries may have been contaminated by shared scratch
        # files. Never promote them to a bound cache just because the filename fits.
        if (not isinstance(cached, dict) or cached.get('schema_version') != 2
                or cached.get('address') != address or cached.get('chain') != self.chain
                or cached.get('parser_contract') != 'solidity-spans-v1'
                or cached.get('source_kind') != 'explorer_current'
                or cached.get('historical_binding') != 'unverified'):
            return None
        functions = cached.get('functions')
        if not isinstance(functions, dict) or not functions:
            return None
        for name, entries in functions.items():
            if not isinstance(name, str) or not name or not isinstance(entries, list) or not entries:
                return None
            for entry in entries:
                if (not isinstance(entry, dict) or not isinstance(entry.get('content'), str)
                        or not isinstance(entry.get('path'), str)
                        or type(entry.get('start_line')) is not int
                        or type(entry.get('end_line')) is not int
                        or not 1 <= entry['start_line'] <= entry['end_line']):
                    return None
        return functions

    def _write_cached_functions(self, path, address, functions):
        envelope = {'schema_version': 2, 'parser_contract': 'solidity-spans-v1', 'address': address, 'chain': self.chain,
                    'source_kind': 'explorer_current', 'historical_binding': 'unverified',
                    'functions': functions}
        temporary_path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=self.cache_dir,
                                             prefix='source-', suffix='.tmp', delete=False) as f:
                temporary_path = f.name
                json.dump(envelope, f, indent=4)
            os.replace(temporary_path, path)
        finally:
            if temporary_path is not None and os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def run(self):
        output = {}
        for address in self.address:
            address = address.lower()
            path = os.path.join(self.cache_dir, f'{address}_{self.chain}.json')
            cached = self._load_cached_functions(path, address)
            if cached is not None:
                output[address] = cached
                continue
            # Own only this request's scratch directory. Never parse stale files or
            # delete caller-owned source/Implementation directories.
            os.makedirs(self.output_dir, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='contract-', dir=self.output_dir) as scratch:
                self.get_source_code(self.chain, address, scratch)
                data = self.parse_contract(scratch)
                if data:
                    self._write_cached_functions(path, address, data)
            output[address] = data
        return output

if __name__ == '__main__':
    ContractDownloader('bsc','0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c').run()
