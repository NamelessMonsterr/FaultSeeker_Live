// SPDX-License-Identifier: MIT
// A synthetic stand-in for a verified lending-style contract (NOT the real Seneca Chamber source).
pragma solidity ^0.8.0;

interface IToken { function balanceOf(address a) external view returns (uint256); }

contract ChamberLike {
    mapping(address => uint256) public balances;
    uint8 internal constant ACTION_BORROW = 5;
    uint8 internal constant ACTION_CALL = 30;

    function deposit(uint256 amount) external {
        balances[msg.sender] += amount;
    }

    function performOperations(uint8[] calldata actions, uint256[] calldata values, bytes[] calldata datas)
        external
        payable
        returns (uint256 value1, uint256 value2)
    {
        for (uint256 i = 0; i < actions.length; i++) {
            if (actions[i] == ACTION_CALL) {
                (address callee, bytes memory callData, , , ) = abi.decode(datas[i], (address, bytes, bool, bool, uint8));
                // the target and calldata come straight from the caller
                (bool ok, ) = callee.call{value: values[i]}(callData);
                require(ok, "call failed");
            }
        }
    }

    function skim(IToken token, address to) external {
        balances[to] += token.balanceOf(address(this));
    }
}
