import re
    
    
class TraceNode:
    """Represents a single node in the transaction trace."""
    def __init__(self, type, gas=None, address=None, function=None, params=None, 
                 call_type=None, value=None, children=None, contract_type=None):
        self.type = type
        self.gas = gas
        self.address = address
        self.function = function
        self.params = params
        self.call_type = call_type
        self.value = value
        self.contract_type = contract_type
        self.children = children or []
    
    def to_dict(self):
        """Convert node to dictionary representation."""
        return {
            'type': self.type,
            'gas': self.gas,
            'address': self.address,
            'function': self.function,
            'params': self.params,
            'call_type': self.call_type,
            'value': self.value,
            'contract_type': self.contract_type,
            'children': [child.to_dict() for child in self.children]
        }
    
    @classmethod
    def from_dict(cls, data):
        """Create a TraceNode from a dictionary."""
        node = cls(
            type=data['type'],
            gas=data.get('gas'),
            address=data.get('address'),
            function=data.get('function'),
            params=data.get('params'),
            call_type=data.get('call_type'),
            value=data.get('value'),
            contract_type=data.get('contract_type')
        )
        node.children = [cls.from_dict(child) for child in data.get('children', [])]
        return node

class TraceParser:    
    def __init__(self):
        self.line_pattern = re.compile(r'^(?P<prefix>(?:\s*│\s*)*(?:\s*├─\s*|\s*└─\s*)?)?(?P<content>.+)$')
        self.call_pattern = re.compile(r'^\[(\d+)\]\s+(0x[a-fA-F0-9]+)::([^(]+)\((.*)\)(?:\s+\[([^\]]+)\])?$')
        self.return_pattern = re.compile(r'^←\s+\[Return\]\s+(.+)$')
        self.contract_creation_pattern = re.compile(r'^\[(\d+)\]\s*→\s+new\s+([^@]+)@(0x[a-fA-F0-9]{40})$')
        self.address_call_memo = {}
        self.created_address = []

        
    def parse(self, trace_text, depth_limit=1000):
        self.address_call_memo = {}
        self.created_address = []
        lines = trace_text.strip().split('\n')
        root = None
        stack = []
        prev_depth = -1
        
        for line in lines:
            match = self.line_pattern.match(line)
            if not match:
                continue
                
            prefix = match.group('prefix') or ''
            content = match.group('content')        
            depth = prefix.count('│') + (1 if '├─' in prefix or '└─' in prefix else 0)
            node = self._parse_node(content)
            if not node:
                continue
            if depth == 0:
                root = node
                stack = [root]
                prev_depth = 0
                continue
            elif depth > depth_limit:
                continue
            if depth > prev_depth:
                stack[-1].children.append(node)
                stack.append(node)
            elif depth < prev_depth:
                while len(stack) > depth:
                    stack.pop()
                stack[-1].children.append(node)
                stack.append(node)
            else:
                stack.pop()
                stack[-1].children.append(node)
                stack.append(node)
            prev_depth = depth
        return root
    
    def _parse_node(self, content):
        content = content.strip()
        call_match = self.call_pattern.match(content)
        if call_match:
            gas, address, function, params, call_type = call_match.groups()
            if address.lower() not in self.address_call_memo:
                self.address_call_memo[address.lower()] = []
            if function not in self.address_call_memo[address.lower()]:
                self.address_call_memo[address.lower()].append(function)
            return TraceNode(
                type='call',
                gas=int(gas),
                address=address,
                function=function,
                params=params.strip(),
                call_type=call_type
            )
        return_match = self.return_pattern.match(content)
        if return_match:
            return TraceNode(
                type='return',
                value=return_match.group(1)
            )
        creation_match = self.contract_creation_pattern.match(content)
        if creation_match:
            gas, contract_type, address = creation_match.groups()
            if address.lower() not in self.created_address:
                self.created_address.append(address.lower())
            return TraceNode(
                type='create',
                gas=int(gas),
                address=address,
                function=f'new {contract_type}',
                params='',
                call_type='create'
            )
            
            
        return None
    
    def get_address_call_memo(self):
        return self.address_call_memo
    
    def get_created_address(self):
        return self.created_address
