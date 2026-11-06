from pathlib import Path
import pytest
from faultseeker.data_collection.txn_info_collector import TransactionInfoCollector


def test_recorded_etherscan_target_attributes_after_title():
    html = (Path(__file__).parent / 'fixtures/etherscan_transfer_target_20261105.html').read_text(encoding='utf-8')
    _, address = TransactionInfoCollector()._process_statement(html)
    assert address.lower() == '0xc793113f1548b97e37c409f39244ee44241bf2b3'


@pytest.mark.parametrize('quote', ["'", '"'])
def test_address_title_with_later_attributes(quote):
    address = '0x' + 'a' * 40
    _, actual = TransactionInfoCollector()._process_statement(
        f'<span title={quote}{address}{quote} data-truncate="address">short</span>')
    assert actual == address


def test_parallel_transfers_are_preserved():
    a, b, token = ['0x' + c * 40 for c in '123']
    def transfer(amount):
        return (f"From</span><a title='{a}'>A</a>To</span><a title='{b}'>B</a>"
                f"For</span><span>{amount}</span><a title='TEST ({token})'>asset</a>")
    graph = TransactionInfoCollector()._get_token_transferred(
        'ERC-20 Tokens Transferred:' + transfer('2') + transfer('3'))
    assert len(graph['edges']) == 2
    assert [row['label'] for row in graph['edges']] == [
        f'{token} [TEST] (2)', f'{token} [TEST] (3)']
