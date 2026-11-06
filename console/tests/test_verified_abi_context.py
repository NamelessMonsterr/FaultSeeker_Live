"""Mocked source/RPC contracts, no provider or on-chain integration claims."""
import json
import httpx
import pytest
from app.verified_abi_context import VerifiedABIContext
ADDRESS = '0x' + '1' * 40
ABI = [{"type": "function", "name": "transfer", "inputs": [{"type": "address"}, {"type": "uint256"}]}]

def fixture(**changes):
    return {"chainId": "1", "address": ADDRESS, "runtimeMatch": "exact_match",
            "runtimeBytecode": {"onchainBytecode": "0x1234"}, "abi": ABI, **changes}

def context(source=None, code='0x1234', chain='0x1'):
    calls=[]
    def get(request):
        calls.append(str(request.url))
        return httpx.Response(200,json=fixture() if source is None else source)
    def post(endpoint, body, timeout):
        calls.append('rpc')
        request=json.loads(body)
        assert request[1]['params'] == [ADDRESS,'0x123']
        return json.dumps([{'jsonrpc':'2.0','id':1,'result':chain},{'jsonrpc':'2.0','id':2,'result':code}]).encode()
    result=VerifiedABIContext(1,'0x123','https://rpc.invalid',transport=httpx.MockTransport(get),post=post)
    return result,calls

def test_verified_context_is_selector_address_and_block_bound_and_cached():
    obj,calls=context()
    result=obj.lookup(ADDRESS,'0xa9059cbb')
    assert result['status']=='verified'
    assert result['signature']=='transfer(address,uint256)'
    assert result['scope']=='block_end_state'
    assert result['block_number']=='0x123'
    assert obj.lookup(ADDRESS.upper(),'0xa9059cbb')==result
    assert len(calls)==2

@pytest.mark.parametrize('source,code,chain',[
    (fixture(address='0x'+'2'*40),'0x1234','0x1'),
    (fixture(chainId='56'),'0x1234','0x1'),
    (fixture(runtimeMatch='match'),'0x1234','0x1'),
    (fixture(),'0xabcd','0x1'),(fixture(),'0x1234','0x38'),
])
def test_unverified_or_mismatched_contract_never_supplies_a_name(source,code,chain):
    obj,_=context(source,code,chain)
    result=obj.lookup(ADDRESS,'0xa9059cbb')
    assert result['status']!='verified'
    assert 'signature' not in result and 'abi' not in result

def test_unknown_selector_and_disabled_route_do_not_invent_identity():
    obj,_=context()
    assert obj.lookup(ADDRESS,'0x12345678')['status']=='selector_not_found'
    disabled=VerifiedABIContext(1,'0x123',None)
    assert disabled.lookup(ADDRESS,'0xa9059cbb')['status']=='disabled'

def test_budget_and_invalid_targets_do_not_trigger_fetches():
    obj,calls=context()
    obj.max_contracts=0
    assert obj.lookup(ADDRESS,'0xa9059cbb')['status']=='budget_exhausted'
    assert obj.lookup('../escape','0xa9059cbb')['status']=='invalid_target'
    assert not calls


def test_source_throttle_stops_new_contract_lookups():
    calls=[]
    def reply(request):
        calls.append(request)
        return httpx.Response(429,text='PRIVATE')
    obj=VerifiedABIContext(1,'0x123','https://rpc.invalid',transport=httpx.MockTransport(reply))
    assert obj.lookup(ADDRESS,'0xa9059cbb')['status']=='provider_limited'
    assert obj.lookup('0x'+'2'*40,'0xa9059cbb')['status']=='provider_limited'
    assert len(calls)==1


def test_rpc_throttle_stops_new_contract_lookups():
    from app.rpc_transport import RPCDestinationError
    obj,calls=context()
    def limited(*args,**kwargs):
        raise RPCDestinationError('RPC endpoint returned HTTP 429.',status_code=429)
    obj.post=limited
    assert obj.lookup(ADDRESS,'0xa9059cbb')['status']=='provider_limited'
    assert obj.lookup('0x'+'2'*40,'0xa9059cbb')['status']=='provider_limited'
    assert len(calls)==1


def test_verified_historical_hedgey_abi_fixture_resolves_tuple_signature():
    from pathlib import Path
    fixture=json.loads((Path(__file__).parent/'fixtures/hedgey_verified_abi.json').read_text())
    source=fixture['source']
    requests=[]
    def reply(request):
        requests.append(str(request.url))
        return httpx.Response(200,json=source)
    def post(endpoint,body,timeout):
        assert json.loads(body)==fixture['provenance']['rpc_request']
        return json.dumps(fixture['rpc_response']).encode()
    obj=VerifiedABIContext(1,'0x12c69cf',fixture['provenance']['rpc_endpoint'],transport=httpx.MockTransport(reply),post=post)
    address=source['address']
    create=obj.lookup(address,'0xefd86b62')
    cancel=obj.lookup(address,'0xf412e4c7')
    assert create['status']==cancel['status']=='verified'
    assert create['signature'].startswith('createLockedCampaign(bytes16,(')
    assert cancel['signature']=='cancelCampaign(bytes16)'
    assert len(requests)==1


def test_ambiguous_selector_is_not_assigned_a_name():
    abi=[{'type':'function','name':'burn','inputs':[{'type':'uint256'}]},
         {'type':'function','name':'collate_propagate_storage','inputs':[{'type':'bytes16'}]}]
    obj,_=context(fixture(abi=abi))
    result=obj.lookup(ADDRESS,'0x42966c68')
    assert result['status']=='ambiguous_selector' and 'signature' not in result


def test_expired_shared_lookup_budget_prevents_rpc_or_new_source_calls():
    now=[0]
    calls=[]
    def reply(request):
        calls.append('source')
        now[0]=31
        return httpx.Response(200,json=fixture())
    def post(*args,**kwargs):
        pytest.fail('Expired budget reached RPC')
    obj=VerifiedABIContext(1,'0x123','https://rpc.invalid',transport=httpx.MockTransport(reply),post=post,clock=lambda:now[0])
    assert obj.lookup(ADDRESS,'0xa9059cbb')['status']=='budget_exhausted'
    assert obj.lookup('0x'+'2'*40,'0xa9059cbb')['status']=='budget_exhausted'
    assert calls==['source']


def test_concurrent_same_contract_lookups_share_one_fetch():
    from concurrent.futures import ThreadPoolExecutor
    import threading
    obj,calls=context()
    entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
    def reply(request):
        calls.append('source')
        entered.set()
        assert release.wait(2)
        return httpx.Response(200,json=fixture())
    obj.transport=httpx.MockTransport(reply)
    def second():
        second_started.set()
        return obj.lookup(ADDRESS,'0xa9059cbb')
    with ThreadPoolExecutor(max_workers=2) as pool:
        first=pool.submit(obj.lookup,ADDRESS,'0xa9059cbb')
        assert entered.wait(2)
        other=pool.submit(second)
        assert second_started.wait(2)
        # Let a competing cache miss reach the HTTP barrier in the old implementation.
        threading.Event().wait(0.1)
        release.set()
        assert first.result()['status']==other.result()['status']=='verified'
    assert calls.count('source')==1 and calls.count('rpc')==1


def source_context(document=None):
    obj,calls=context()
    source={**fixture(),'compilation':{'fullyQualifiedName':'contracts/Test.sol:Test'},
            'sources':{'contracts/Test.sol':{'content':'// SPDX-License-Identifier: MIT\ncontract Test { function transfer(address,uint256) external {} }'}}}
    def reply(request):
        if 'sources' in str(request.url):
            calls.append('source')
            return httpx.Response(200,json=source if document is None else document)
        calls.append('abi')
        return httpx.Response(200,json=fixture())
    obj.transport=httpx.MockTransport(reply)
    return obj,calls


def test_verified_main_source_is_bytecode_bound_and_cached():
    obj,calls=source_context()
    result=obj.source_for(ADDRESS,'0xa9059cbb')
    assert result['status']=='verified'
    assert result['sources'][0]['path']=='contracts/Test.sol'
    assert 'function transfer' in result['sources'][0]['source_code']
    assert result['sources'][0]['scope']=='verified_main_compilation_unit'
    assert obj.source_for(ADDRESS,'0xa9059cbb')==result
    assert calls==['abi','rpc','source']


@pytest.mark.parametrize('change',[
    {'runtimeBytecode':{'onchainBytecode':'0xabcd'}},
    {'address':'0x'+'2'*40}, {'chainId':'56'}, {'runtimeMatch':'match'},
    {'compilation':{'fullyQualifiedName':'missing.sol:Test'}},
    {'sources':{'contracts/Test.sol':{'content':'x'*65537}}},
])
def test_unbound_or_oversize_source_is_not_returned(change):
    base={**fixture(),'compilation':{'fullyQualifiedName':'contracts/Test.sol:Test'},
          'sources':{'contracts/Test.sol':{'content':'contract Test {}'}}}
    obj,_=source_context({**base,**change})
    result=obj.source_for(ADDRESS,'0xa9059cbb')
    assert result['status']!='verified' and not result.get('sources')



def timed_context(cost=1, budget=30):
    now, calls = [0.0], []
    def reply(request):
        address = request.url.path.rsplit('/', 1)[-1]
        now[0] += cost
        kind = 'source' if 'sources' in str(request.url) else 'abi'
        calls.append(kind)
        document = fixture(address=address)
        if kind == 'source':
            document.update(compilation={'fullyQualifiedName': 'C.sol:C'}, sources={'C.sol': {'content': 'contract C {}'}})
        return httpx.Response(200, json=document)
    def post(*args, **kwargs):
        now[0] += cost
        calls.append('rpc')
        return json.dumps([{'id': 1, 'result': '0x1'}, {'id': 2, 'result': '0x1234'}]).encode()
    obj = VerifiedABIContext(1, '0x123', 'https://rpc.invalid', transport=httpx.MockTransport(reply), post=post, clock=lambda: now[0], time_budget=budget)
    return obj, now, calls


def test_model_idle_time_does_not_consume_lookup_budget():
    obj, now, calls = timed_context()
    assert obj.lookup(ADDRESS, '0xa9059cbb')['status'] == 'verified'
    now[0] += 300
    assert obj.lookup('0x' + '2' * 40, '0xa9059cbb')['status'] == 'verified'
    assert calls == ['abi', 'rpc', 'abi', 'rpc']


def test_model_idle_time_does_not_consume_source_budget():
    obj, now, calls = timed_context()
    second = '0x' + '2' * 40
    assert obj.lookup(ADDRESS, '0xa9059cbb')['status'] == 'verified'
    assert obj.lookup(second, '0xa9059cbb')['status'] == 'verified'
    assert obj.source_for(ADDRESS, '0xa9059cbb')['status'] == 'verified'
    now[0] += 300
    assert obj.source_for(second, '0xa9059cbb')['status'] == 'verified'
    assert calls.count('source') == 2


def test_lookup_budget_stays_shared_after_idle_and_target_change():
    obj, now, calls = timed_context(budget=3)
    assert obj.lookup(ADDRESS, '0xa9059cbb')['status'] == 'verified'
    now[0] += 300
    assert obj.lookup('0x' + '2' * 40, '0xa9059cbb')['status'] == 'budget_exhausted'
    assert obj.lookup('0x' + '3' * 40, '0xa9059cbb')['status'] == 'budget_exhausted'
    assert calls == ['abi', 'rpc', 'abi']
