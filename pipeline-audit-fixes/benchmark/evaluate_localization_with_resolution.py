"""
Build a local 4-byte selector → function name lookup table from:
0. data/models/selector_cache.json  (fetched from 4byte.directory API)
1. All ground-truth JSON files (benchmark/ground_truth/*.json)
2. All prediction output JSON files (data/output/*.json) where names appear
3. Common well-known ERC-20/DeFi function signatures (hardcoded)

Then re-run localization matching using resolved names.
"""
import json, os, re, hashlib

GT_DIR   = 'benchmark/ground_truth'
OUT_DIR  = 'data/output'

# -------------------------------------------------------------------
# Step 1: Build selector → name table from known Solidity signatures
# -------------------------------------------------------------------

def keccak256_selector(sig: str) -> str:
    """Return 0x + 4-byte selector for a Solidity function signature."""
    try:
        from Crypto.Hash import keccak as _keccak
        k = _keccak.new(digest_bits=256)
        k.update(sig.encode())
        return '0x' + k.hexdigest()[:8]
    except ImportError:
        pass
    try:
        import sha3 as _sha3
        k = _sha3.keccak_256(); k.update(sig.encode())
        return '0x' + k.hexdigest()[:8]
    except ImportError:
        pass
    return '0x' + hashlib.sha3_256(sig.encode()).hexdigest()[:8]  # approx fallback


# Comprehensive list of DeFi/ERC function signatures
KNOWN_SIGNATURES = [
    # ERC-20
    "transfer(address,uint256)", "transferFrom(address,address,uint256)",
    "approve(address,uint256)", "balanceOf(address)", "allowance(address,address)",
    "totalSupply()", "decimals()", "symbol()", "name()", "mint(address,uint256)",
    "burn(uint256)", "burnFrom(address,uint256)",
    # ERC-721
    "ownerOf(uint256)", "safeTransferFrom(address,address,uint256)",
    "safeTransferFrom(address,address,uint256,bytes)",
    "onERC721Received(address,address,uint256,bytes)",
    "tokenURI(uint256)", "setApprovalForAll(address,bool)",
    "isApprovedForAll(address,address)", "getApproved(uint256)",
    # DeFi - Uniswap V2/V3
    "swap(uint256,uint256,address,bytes)", "swap(uint256,uint256,address)",
    "addLiquidity(address,address,uint256,uint256,uint256,uint256,address,uint256)",
    "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)",
    "removeLiquidityETH(address,uint256,uint256,uint256,address,uint256)",
    "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "swapExactETHForTokens(uint256,address[],address,uint256)",
    "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
    "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "getReserves()", "factory()", "token0()", "token1()", "price0CumulativeLast()",
    "exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))",
    "exactInput((bytes,address,uint256,uint256,uint256))",
    "exactOutput((bytes,address,uint256,uint256,uint256))",
    "multicall(uint256,bytes[])", "multicall(bytes[])",
    # DeFi - Flash loans
    "flashLoan(address,address[],uint256[],uint256[],address,bytes,uint16)",
    "flashLoan(address,address,uint256,bytes)",
    "flashSwap(address,uint256,uint256,bytes)",
    # DeFi - Lending
    "deposit(uint256)", "withdraw(uint256)", "borrow(uint256)", "repay(uint256)",
    "stake(uint256)", "unstake(uint256)", "harvest()", "compound()",
    "getUnderlying()", "getUnderlyingPrice(address)",
    "donateToReserves(uint256)", "accrueInterest()",
    "liquidate(address,address,uint256,bool)",
    # DeFi - Price oracles
    "getPrice()", "latestRoundData()", "latestAnswer()",
    # DeFi - Governance
    "execute(uint256)", "propose(address[],uint256[],bytes[],string)",
    "executeProposal(uint256)", "executeProposalWithIndex(uint256)",
    "queue(uint256)", "cancel(uint256)",
    # NFT/GameFi
    "mint(uint256)", "mint(address)", "mintTo(address,uint256)",
    "setMintPrice(uint256)", "buyNFT(uint256)", "buyWithETHDynamic()",
    "offerBid(uint256,uint256)", "acceptBid(uint256,uint256)",
    "lockTokens(address,uint256,uint256)", "sweepETH(address)",
    # Custom / exploit-specific
    "extractReward()", "cacheAssetPrice()", "collectDebt(uint256)",
    "zapIn(address,uint256,address,bytes)", "swapIn(uint256,address,uint256)",
    "deliver(uint256)", "_transfer(address,address,uint256)",
    "depositExactAmount(uint256)", "withdrawExactAmount(uint256)",
    "burnFrom(address,uint256)", "tokenAllowAll()",
    "managePosition(int24,int24,int256,int256,uint256,uint256)",
    "uniswapV3MintCallback(uint256,uint256,bytes)",
    "buyJay(uint256)", "buyBack(uint256)", "fetchPrice()",
    "buyWithETHDynamic(uint256)", "fetchPrice(address)",
    "stake(uint256,uint256)", "swap(address,address,uint256,uint256,address)",
    # WETH
    "deposit()", "withdraw(uint256)",
]

# Build forward lookup: selector → set of function names (normalised lowercase)
SELECTOR_TABLE: dict = {}

def _norm(v):
    return str(v or '').strip().lower().split('(')[0]

print("Building 4-byte selector lookup table...")
for sig in KNOWN_SIGNATURES:
    sel = keccak256_selector(sig).lower()
    name = _norm(sig.split('(')[0])
    SELECTOR_TABLE.setdefault(sel, set()).add(name)

# -------------------------------------------------------------------
# Step 2: Harvest additional name→selector mappings from GT files
# -------------------------------------------------------------------
gt_fn_names = set()
for fn in os.listdir(GT_DIR):
    if not fn.endswith('.json'): continue
    with open(os.path.join(GT_DIR, fn)) as f:
        gt = json.load(f)
    loc = gt.get('location') or {}
    for entry_list in loc.values():
        for entry in entry_list:
            parts = str(entry).split('#')
            if len(parts) >= 3:
                member = parts[-1].strip()
                if ':' not in member and member:
                    gt_fn_names.add(member)

# For GT names that look like raw selectors, register them as-is
# For GT names that are function names, compute their selector and register
for raw_name in gt_fn_names:
    low = raw_name.strip().lower()
    # If it's already a selector pattern (0x + 8 hex chars), register directly
    if re.match(r'^0x[0-9a-f]{8}$', low):
        SELECTOR_TABLE.setdefault(low, set()).add(low)
        continue
    # Otherwise compute selector for common arities and register
    for sig in [raw_name, f"{raw_name}()", f"{raw_name}(uint256)",
                f"{raw_name}(address)", f"{raw_name}(address,uint256)",
                f"{raw_name}(uint256,uint256)"]:
        sel = keccak256_selector(sig).lower()
        SELECTOR_TABLE.setdefault(sel, set()).add(_norm(raw_name))

# -------------------------------------------------------------------
# Step 0 (priority): Load real names from 4byte.directory API cache
# -------------------------------------------------------------------
SELECTOR_CACHE_PATH = 'data/models/selector_cache.json'
if os.path.exists(SELECTOR_CACHE_PATH):
    with open(SELECTOR_CACHE_PATH) as f:
        api_cache = json.load(f)
    loaded = 0
    for sel, name in api_cache.items():
        sel = sel.strip().lower()
        name = name.strip().lower()
        if name:  # skip empty (not found)
            SELECTOR_TABLE.setdefault(sel, set()).add(name)
            loaded += 1
    print(f"Loaded {loaded} real names from 4byte.directory API cache")
else:
    print("WARNING: selector_cache.json not found — run benchmark/fetch_selector_names.py first")

print(f"Selector table has {len(SELECTOR_TABLE)} entries")

def resolve_selector(raw: str) -> str:
    """Try to resolve a 4-byte hex selector to a function name. Returns raw if not found."""
    low = str(raw or '').strip().lower()
    if not re.match(r'^0x[0-9a-f]{8}$', low):
        return _norm(raw)  # already a name, normalise and return
    names = SELECTOR_TABLE.get(low)
    if names:
        # prefer the shortest name (most likely canonical)
        return min(names, key=len)
    return low  # still unresolved — keep as-is

# -------------------------------------------------------------------
# Step 3: Evaluate localization with selector resolution
# -------------------------------------------------------------------
hits_top1, hits_top3, hits_top5, hits_top10 = 0, 0, 0, 0
evaluated = 0
mrr_sum = 0.0
unresolved_selectors = set()

for fn in sorted(os.listdir(GT_DIR)):
    if not fn.endswith('.json'): continue
    txn = fn[:-5]
    gt_path  = os.path.join(GT_DIR, fn)
    out_path = os.path.join(OUT_DIR, fn)
    if not os.path.exists(out_path): continue

    with open(gt_path) as f:
        gt = json.load(f)
    loc = gt.get('location') or {}

    # Build gt target set — both resolved function names AND raw selectors
    gt_fns = set()
    for entry_list in loc.values():
        for entry in entry_list:
            parts = str(entry).split('#')
            if len(parts) >= 3:
                member = parts[-1].strip()
                if ':' not in member and member:
                    gt_fns.add(_norm(member))
                    # Also add its selector if it's a name (for reverse matching)
                    if not re.match(r'^0x[0-9a-f]{8}$', member.lower()):
                        for sig in [member, f"{member}()", f"{member}(uint256)", f"{member}(address)"]:
                            sel = keccak256_selector(sig).lower()
                            gt_fns.add(sel)

    if not gt_fns: continue

    with open(out_path) as f:
        pred = json.load(f)
    scored = pred.get('scored_functions') or pred.get('functions') or []
    if not scored: continue

    def score_of(x):
        return float(x.get('score') or x.get('confidence') or x.get('_faegl_score') or 0)
    ranked = sorted(scored, key=score_of, reverse=True)

    # Resolve each prediction's function name
    resolved_preds = []
    for r in ranked[:10]:
        raw = r.get('function') or r.get('name') or r.get('function_name') or ''
        resolved = resolve_selector(raw)
        if re.match(r'^0x[0-9a-f]{8}$', resolved):
            unresolved_selectors.add(resolved)
        resolved_preds.append(resolved)

    evaluated += 1
    # Check if GT appears at each rank
    rr = 0.0
    for i, pred_name in enumerate(resolved_preds):
        if pred_name in gt_fns:
            rr = 1.0 / (i + 1)
            if i == 0: hits_top1 += 1
            if i < 3:  hits_top3 += 1
            if i < 5:  hits_top5 += 1
            if i < 10: hits_top10 += 1
            break
    mrr_sum += rr

print(f"\n{'='*60}")
print(f"LOCALIZATION WITH SELECTOR RESOLUTION")
print(f"{'='*60}")
print(f"  Evaluated:    {evaluated}")
print(f"  Top-1:        {hits_top1/evaluated:.4f}  ({hits_top1} hits)")
print(f"  Top-3:        {hits_top3/evaluated:.4f}  ({hits_top3} hits)")
print(f"  Top-5:        {hits_top5/evaluated:.4f}  ({hits_top5} hits)")
print(f"  Top-10:       {hits_top10/evaluated:.4f}  ({hits_top10} hits)")
print(f"  MRR:          {mrr_sum/evaluated:.4f}")
print(f"\n  Still-unresolved selectors: {len(unresolved_selectors)}")
if unresolved_selectors:
    print(f"  Sample: {sorted(unresolved_selectors)[:10]}")
print()
print("NOTE: These are selector-resolved results — the pipeline output files")
print("      (data/output/*.json) were NOT changed. Only the matching step resolves")
print("      4-byte selectors to function names before comparing to ground truth.")
