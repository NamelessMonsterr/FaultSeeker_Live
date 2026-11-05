# Source parser boundaries

The location listener preserves same-name overloads as an ordered `overloads` list on the legacy name entry. Single definitions keep the existing name lookup. Exact character offsets distinguish functions sharing a line. Constructor, receive and fallback definitions supported by the installed grammar are recorded explicitly.

The downloader preserves every alternative and extracts exact spans instead of whole source lines. Names from separate compilation contracts remain unverified alternatives; this is not a function-selector/ABI binding. Plain analyzer retrieval accepts single-line source and labels binding unverified. The console's independently verified historical source path remains a separate boundary.

Explorer multifile paths receive a path-derived hash prefix and sanitized basename so a/b.sol and a_b.sol cannot overwrite each other. Source caches retain envelope schema2 but require parser_contract=solidity-spans-v1; old line-only parser caches are refetched, not relabelled valid. Current explorer cache still has historical_binding=unverified.

Unsupported valid Solidity is an explicit limitation, not recovered parser success. Offline reproduction on 2026-11-04: pragma solidity ^0.8.19; type Units is uint256; contract C { function foo(Units x) external pure returns(Units) { return x; } } raises the safe unavailable-source ValueError. This repository has generated Python parser files but no .g4 grammar or ANTLR generator jar; antlr4 is not available as a local command. No generator downloaded/installed and no regex replacement used to pretend this language feature is supported. Modern value-type grammar support remains deferred until the matching grammar/generator can be supplied and tested.

Initial analysis task trees now distinguish supplied versus unavailable source and do not claim retrieval completed automatically. Preserving a source span does not establish implementation vulnerability, historical bytecode equality, imported dependency coverage or full transaction analysis.
