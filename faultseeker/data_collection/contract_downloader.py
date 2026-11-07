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
    
class ContractDownloader:

    def __init__(self, chain:str, address:list, output_dir:str='./temp2', cache_dir:str='./data/cache/contracts'):
        self.chain = chain.lower()
        self.address = address
        self.output_dir = output_dir
        self.cache_dir = cache_dir
        # os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)

    @staticmethod
    def get_source_code(chain, address, output_dir):
        os.makedirs(output_dir, exist_ok=True)
        from faultseeker import chains
        known = chains.get(chain)
        network_args = ['--chainid', str(known['chain_id'])] if known else ['-n', chain]
        command = ['getCode', *network_args, '-a', address, '-o', output_dir]
        explorer_key = os.environ.get('ETHERSCAN_API_KEY', '').strip()
        if explorer_key:
            command += ['-k', explorer_key]
        ret = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, shell = False)
        logging.info('==========================================')
        logging.info(f'{address}[{chain}]')
        logging.info(ret.stdout.decode('utf-8'))
        logging.info(ret.stderr.decode('utf-8'))
        if ret.stderr.decode('utf-8') != '':
            print(f'{address}[{chain}]')
            print(ret.stderr.decode('utf-8'))
        logging.info('==========================================')


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