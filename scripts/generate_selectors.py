#!/usr/bin/env python3
"""Regenerates faultseeker/utils/known_selectors.json from the canonical signatures below.

Run:  python scripts/generate_selectors.py   (needs pycryptodome or eth-utils; both come with requirements.txt)
tests/test_selectors.py re-derives every selector with keccak (and with `cast sig` when Foundry is installed).
"""
import json
from pathlib import Path

SIGNATURES = [
    # ERC-20 / ERC-721 / common token and vault functions
    "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)",
    "balanceOf(address)", "allowance(address,address)", "totalSupply()", "name()", "symbol()", "decimals()",
    "mint(address,uint256)", "burn(uint256)", "burnFrom(address,uint256)", "deposit()", "withdraw(uint256)",
    "safeTransferFrom(address,address,uint256)", "safeTransferFrom(address,address,uint256,bytes)",
    "ownerOf(uint256)", "setApprovalForAll(address,bool)",
    # Flash-loan lenders (names matched by utils.get_function_calls_to_expand)
    "flashLoan(address,address,uint256,bytes)",                        # ERC-3156
    "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",  # Aave v2 / v3
    "flashLoan(address,address[],uint256[],bytes)",                    # Balancer vault
    "flashLoan(uint256,uint256,address,bytes)",                        # DODO
    "flashLoanSimple(address,address,uint256,bytes,uint16)",           # Aave v3
    "flashFee(address,uint256)", "maxFlashLoan(address)",
    "flash(address,uint256,uint256,bytes)",                            # Uniswap v3 pool
    # Flash-loan callbacks
    "executeOperation(address[],uint256[],uint256[],address,bytes)",   # Aave v2 / v3
    "executeOperation(address,uint256,uint256,address,bytes)",         # Aave v3 simple
    "onFlashLoan(address,address,uint256,uint256,bytes)",              # ERC-3156
    "receiveFlashLoan(address[],uint256[],uint256[],bytes)",           # Balancer
    "uniswapV2Call(address,uint256,uint256,bytes)", "pancakeCall(address,uint256,uint256,bytes)",
    "swap(uint256,uint256,address,bytes)",                             # Uniswap v2 / Pancake pair
    "uniswapV3FlashCallback(uint256,uint256,bytes)", "uniswapV3SwapCallback(int256,int256,bytes)",
    "DVMFlashLoanCall(address,uint256,uint256,bytes)", "DPPFlashLoanCall(address,uint256,uint256,bytes)",
    "DSPFlashLoanCall(address,uint256,uint256,bytes)",
    "callFunction(address,(address,uint256),bytes)",                   # dYdX
    "onMorphoFlashLoan(uint256,bytes)",
]


def keccak(data: bytes) -> bytes:
    try:
        from Crypto.Hash import keccak as k
        return k.new(digest_bits=256, data=data).digest()
    except ImportError:
        from eth_utils import keccak as ek
        return ek(data)


def main():
    table = {}
    for sig in SIGNATURES:
        sel = keccak(sig.encode()).hex()[:8]
        assert table.get(sel, sig) == sig, f"selector collision for {sel}"
        table[sel] = sig
    out = Path(__file__).resolve().parents[1] / "faultseeker" / "utils" / "known_selectors.json"
    out.write_text(json.dumps(dict(sorted(table.items(), key=lambda kv: kv[1])), indent=1) + "\n")
    print(f"wrote {len(table)} selectors to {out}")


if __name__ == "__main__":
    main()
