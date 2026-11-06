# Fund-flow output contract

`balance_change` remains address -> asset -> {label, amount}. New `amount` values are JSON-safe decimal strings to preserve exact arithmetic relative to the supplied transfer labels. Previously saved reports may contain floats; the console can still display them. No token quantity is converted into native profit or USD value.

Transfers and model-selected victim candidates are distinct evidence. Candidate participants/victims remain hypotheses, not confirmed attackers or unauthorized losses. Victim prompts now request a JSON object {"victims": [...]}; the parser also accepts the historical plain list. Malformed responses fail explicitly.

Each run resets roles and balances. Address identity is case-insensitive. Transfers from an asset's own contract are retained. Malformed, nonfinite, negative or parsing-limit-exceeding amounts fail the fund-flow section rather than silently dropping data. Decimal arithmetic traps inexact operations; amount strings and exponents are bounded to prevent pathological parsing/formatting work. Numeric quantities are not aggregated across asset units.

Compatibility: amount changed from a binary floating-point value to a decimal string. Downstream numeric clients should parse it as decimal, not a float. Existing in-project consumers pass this nested context to prompts/reports; the removed SignalExtractor gross-profit inference is not restored. Precision of an already rounded explorer label cannot be recovered here; raw-log/source provenance remains a separate requirement.

Trace-derived deterministic signals still run before model-dependent address classification. They do not infer a native profit from token deltas or model roles. Function-analysis empty selection or elapsed-cycle limit raises analysis_incomplete; the console labels incomplete work partial/INCONCLUSIVE and skips scoring. Configured iteration ceilings remain unchanged; reaching a ceiling is bounded-analysis completion, not proof of exhaustive forensic coverage. The loop clock is checked between cycles, not a hard interrupt of an in-flight request; shared endpoint budgets separately bound model transport.
