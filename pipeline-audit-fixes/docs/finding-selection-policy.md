# Finding selection and ranking policy

User decision (2026-11-04): retain all analyzed findings and rank them; show depth as context.

Finalization retains every analyzed target keyed by function and address. Model-ranked known targets come first; omitted targets are appended instead of discarded. Duplicate ranking entries do not duplicate findings. Target identity and evidence/confidence data are copied without mutating the analysis record. Depth remains in the report and evidence cards but is neither an exclusion rule nor a confidence boost.

Stage3 ranks retained findings using the existing evidence/confidence components. Unavailable/incompatible calibration remains explicitly heuristic. Model ranking supports a JSON object {"ranked_functions": [...]} and historical plain lists; unknown targets or malformed ranking responses fail explicitly. A model's ordering is not proof of vulnerability.

The policy does not claim every observed call was analyzed or that every retained candidate is a confirmed vulnerability. Existing trace provenance and partial/error handling remain required. Tests use synthetic findings and controlled stage/model boundaries, not invented historical ground truth.
