import re
import subprocess
from bs4 import BeautifulSoup
import pandas as pd
import os
import traceback
import pandas
from tqdm import tqdm
import subprocess
import logging
import json
import shutil
from faultseeker.utils.solidityParser.loc_parser import get_loc_info
        


LOGGGING_FILE_PATH = './logs/get_source_code.log'
os.makedirs(os.path.dirname(LOGGGING_FILE_PATH), exist_ok=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',filename=LOGGGING_FILE_PATH, filemode='w')


CONTRACT_SOURCES ={
    'eth': 'https://etherscan.io/contractsverified',
    'bsc': 'https://bscscan.com/contractsverified',
    'poly': 'https://polygonscan.com/contractsverified',
    'fantom': 'https://ftmscan.com/contractsverified',
    'arbi': 'https://arbiscan.io/contractsverified',
    'avax': 'https://snowtrace.io/contractsverified',
    'opt': 'https://optimistic.etherscan.io/contractsverified',
    'base': 'https://basescan.org/contractsverified'
}
    
def describe_source_lookup(outcome: dict) -> str:
    """One honest sentence about why a contract's source was not retrieved: what each lookup reported, the likely cause when the
    evidence supports one, and uncertainty otherwise. It never claims that adding a key would recover the source."""
    sourcify = outcome.get('sourcify', 'not tried')
    explorer = outcome.get('explorer', 'not tried')
    parts = [f"Sourcify: {sourcify}", f"Etherscan API ({'key configured' if outcome.get('explorer_key_configured') else 'no ETHERSCAN_API_KEY'}): {explorer}"]
    cause = outcome.get('cause', 'unknown')
    meaning = {
        'explorer_credentials': 'the explorer reported a missing or invalid API key; a valid key may allow the lookup, which is not guaranteed to find source',
        'explorer_rate_limited': 'the explorer reported rate limiting; the source may exist but could not be fetched this time',
        'lookup_unreachable': 'a lookup service could not be reached; this is a connectivity problem, not evidence that the contract is unverified',
        'unverified': 'neither service has verified source for this address',
        'no_files': 'neither lookup returned source files and neither said why; whether the contract is unverified is not established',
        'unknown': 'the cause could not be determined from the lookup output',
    }.get(cause, 'the cause could not be determined from the lookup output')
    return "; ".join(parts) + f". Likely cause: {meaning}."


def _scrub(text) -> str:
    """Removes the explorer API key from lookup output before it is stored, printed or reported."""
    text = str(text)
    key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
    return text.replace(key, '[redacted]') if key else text


def _classify_lookup(outcome: dict) -> str:
    text = " ".join(str(outcome.get(k, '')) for k in ('sourcify', 'explorer')).lower()
    if 'could not be reached' in text or 'unreachable' in text:
        return 'lookup_unreachable'
    if re.search(r'api[ _-]?key', text):
        return 'explorer_credentials'
    if re.search(r'rate.?limit|max rate', text):
        return 'explorer_rate_limited'
    if 'no verified match' in outcome.get('sourcify', '') and re.search(r'not verified|unverified', outcome.get('explorer', '').lower()):
        return 'unverified'
    if 'no verified match' in outcome.get('sourcify', '') and outcome.get('explorer', '').startswith('returned no source files'):
        return 'no_files'        # a zero exit and no files, with nothing in the output that says why: absence is not established
    return 'unknown'


class ContractDownloader:
    # address(lower) -> what each lookup reported for the contracts looked up in THIS process (never persisted, never contains a key).
    lookup_outcomes = {}

    def __init__(self, chain:str, address:list, output_dir:str='./temp2', cache_dir:str='./data/cache/contracts'):
        self.chain = chain.lower()
        self.address = address
        self.output_dir = output_dir
        self.cache_dir = cache_dir
        # os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def _run_getcode(chain, address, output_dir):
        from faultseeker import chains
        known = chains.get(chain)
        network_args = ['--chainid', str(known['chain_id'])] if known else ['-n', chain]
        command = ['getCode', *network_args, '-a', address, '-o', output_dir]
        explorer_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
        if explorer_key:
            command += ['-k', explorer_key]
        ret = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, shell = False)
        out, err = _scrub(ret.stdout.decode('utf-8', 'ignore')), _scrub(ret.stderr.decode('utf-8', 'ignore'))
        logging.info('==========================================')
        logging.info(f'{address}[{chain}]')
        logging.info(out)
        logging.info(err)
        if err != '':
            print(f'{address}[{chain}]')
            print(err)
        logging.info('==========================================')
        return (out + ' ' + err).strip()[:2000]            # what the tool said (key scrubbed), so a zero exit is read for what it reports

    @staticmethod
    def _has_sources(output_dir):
        return any(f.endswith('.sol') for _, _, files in os.walk(output_dir) for f in files)

    @staticmethod
    def get_source_code(chain, address, output_dir):
        """Download verified source into output_dir.

        With ETHERSCAN_API_KEY set: getCode (Etherscan API) first, Sourcify (free, keyless) if that fails or finds
        nothing. Without a key: Sourcify first, then a keyless getCode attempt. If nothing yields source, a clear
        'Contract source unavailable' line is printed and the call returns without raising.
        """
        from faultseeker import chains
        from faultseeker.data_collection import source_fetcher
        os.makedirs(output_dir, exist_ok=True)
        known = chains.get(chain)
        has_key = bool(os.environ.get('ETHERSCAN_API_KEY', '').strip())
        outcome = {'chain': chain, 'explorer_key_configured': has_key}
        ContractDownloader.lookup_outcomes[address.lower()] = outcome

        def via_sourcify():
            if not known:
                outcome['sourcify'] = f"not tried (chain '{chain}' is not in the supported chain list)"
                return False
            try:
                found = source_fetcher.fetch(known['chain_id'], address, output_dir) > 0
            except source_fetcher.SourceUnavailable as exc:
                outcome['sourcify'] = f'could not be reached or answered with an error ({_scrub(exc)})'
                print(f'Sourcify lookup failed for {address}[{chain}]: {_scrub(exc)}', flush=True)
                return False
            outcome['sourcify'] = 'found' if found else 'no verified match'
            return found

        def via_getcode():
            try:
                said = ContractDownloader._run_getcode(chain, address, output_dir)
            except (subprocess.CalledProcessError, OSError) as exc:
                detail = (getattr(exc, 'stderr', b'') or b'').decode('utf-8', 'ignore').strip()[:200] if isinstance(
                    getattr(exc, 'stderr', None), bytes) else str(exc)[:200]
                detail = _scrub(detail)
                outcome['explorer'] = f"failed ({detail or type(exc).__name__})"
                print(f'getCode failed for {address}[{chain}]: {detail}', flush=True)
                return False
            found = ContractDownloader._has_sources(output_dir)
            note = " ".join(_scrub(said or '').split())[:200]
            outcome['explorer'] = 'found' if found else (f'returned no source files ({note})' if note else 'returned no source files')
            return found

        order = (via_getcode, via_sourcify) if has_key else (via_sourcify, via_getcode)
        for attempt in order:
            if attempt():
                outcome['cause'] = 'found'
                return
        outcome['cause'] = _classify_lookup(outcome)
        print(f'Contract source unavailable for {address}[{chain}]: {describe_source_lookup(outcome)} '
              f'Setting ETHERSCAN_API_KEY may widen coverage but does not guarantee the source is found.', flush=True)


    @staticmethod
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
                except Exception as e:
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
                            loc = result[contract]['functions'][function]
                            function_content = '\n'.join(lines[loc['start_line']-1:loc['end_line']])
                            info = {
                                'path':os.path.join(root,file).replace(output_dir,'.'),
                                'start_line':loc['start_line'],
                                'end_line':loc['end_line'],
                                'content':function_content
                            }
                            if function not in output:
                                output[function] = []
                            output[function].append(info)
        return output
    
    def run(self):
        output = {}
        for address in self.address:
            path = os.path.join(self.cache_dir, f'{address.lower()}_{self.chain}.json')
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    output[address.lower()] = json.load(f)
            else:
                self.get_source_code(self.chain, address, self.output_dir)
                # self.process_log(self.chain, address, self.output_dir)
                data = self.parse_contract(self.output_dir)
                if data:
                    with open(os.path.join(self.cache_dir, f'{address.lower()}_{self.chain}.json'), 'w') as f:
                        json.dump(data, f, indent=4)
                if os.path.exists(self.output_dir):
                    try:
                        shutil.rmtree(self.output_dir)
                    except Exception as e:
                        continue
                if os.path.exists('./Implementation'):
                    shutil.rmtree('./Implementation')
                output[address.lower()] = data
        return output

if __name__ == '__main__':
    ContractDownloader('bsc','0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c').run()