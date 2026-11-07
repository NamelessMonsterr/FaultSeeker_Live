"""Single source of truth for supported networks.

`id` is the identifier used everywhere in the pipeline: it is also the foundry.toml RPC alias passed to
`cast`. `support` is 'full' (exercised by the paper's benchmark), 'beta' (wired through every module but not
benchmarked), 'partial' (Stage 1 forensics can work, but contract source cannot be downloaded so Stage 2
will fail) or 'unsupported' (cannot work with this pipeline). `note` explains any limitation.
"""
from typing import Dict, Optional

_NO_SOURCE = ("Contract source download is not available for this network through getCode (Etherscan API), so "
              "Stage 1 forensics can run but function analysis (Stage 2) will fail.")
_CHAINS = [
    # id, label, short, chain_id, explorer host, support, note
    ("eth", "Ethereum", "ETH", 1, "etherscan.io", "full", ""),
    ("bsc", "BNB Smart Chain", "BNB", 56, "bscscan.com", "full", ""),
    ("polygon", "Polygon PoS", "POL", 137, "polygonscan.com", "beta", ""),
    ("arbitrum", "Arbitrum One", "ARB", 42161, "arbiscan.io", "beta", ""),
    ("optimism", "Optimism", "OP", 10, "optimistic.etherscan.io", "beta", ""),
    ("base", "Base", "BASE", 8453, "basescan.org", "beta", ""),
    ("avalanche", "Avalanche C-Chain", "AVAX", 43114, "snowtrace.io", "beta", ""),
    ("fantom", "Fantom Opera", "FTM", 250, "ftmscan.com", "partial", _NO_SOURCE),
    ("zksync", "zkSync Era", "ZK", 324, "explorer.zksync.io", "unsupported",
     "zkSync Era transactions cannot be replayed with Foundry's cast, and its explorer is not scrapable."),
    ("linea", "Linea", "LINEA", 59144, "lineascan.build", "beta", ""),
    ("scroll", "Scroll", "SCR", 534352, "scrollscan.com", "beta", ""),
    ("gnosis", "Gnosis (xDai)", "GNO", 100, "gnosisscan.io", "beta", ""),
    ("celo", "Celo", "CELO", 42220, "celoscan.io", "beta", ""),
    ("cronos", "Cronos", "CRO", 25, "cronoscan.com", "partial", _NO_SOURCE),
    ("moonbeam", "Moonbeam", "GLMR", 1284, "moonscan.io", "beta", ""),
    ("aurora", "Aurora (NEAR EVM)", "AURORA", 1313161554, "aurorascan.dev", "partial", _NO_SOURCE),
]

CHAINS: Dict[str, dict] = {
    c[0]: {"id": c[0], "label": c[1], "short": c[2], "chain_id": c[3], "explorer": c[4],
           "support": c[5], "note": c[6],
           "tx_url": f"https://{c[4]}/tx/", "address_url": f"https://{c[4]}/address/"}
    for c in _CHAINS
}
# Names older code paths and links may use.
ALIASES = {"mainnet": "eth", "ethereum": "eth", "poly": "polygon", "matic": "polygon", "arbi": "arbitrum",
           "opt": "optimism", "avax": "avalanche", "ftm": "fantom", "xdai": "gnosis"}


def get(chain: str) -> Optional[dict]:
    chain = (chain or "").strip().lower()
    return CHAINS.get(ALIASES.get(chain, chain))
