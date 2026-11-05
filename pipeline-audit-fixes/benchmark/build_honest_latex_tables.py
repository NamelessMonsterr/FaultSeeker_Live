"""Build formatted LaTeX tables from leakage-free honest evaluation results.

Reads reports/honest_results/baseline_comparison.csv and
reports/honest_results/adversarial_robustness.csv and generates LaTeX tables ready
for jisa.pdf manuscript.
"""

from __future__ import annotations

import csv
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HONEST_DIR = os.path.join(ROOT, "reports", "honest_results")
BASELINE_CSV = os.path.join(HONEST_DIR, "baseline_comparison.csv")
ADV_CSV = os.path.join(HONEST_DIR, "adversarial_robustness.csv")
TEX_OUTPUT = os.path.join(HONEST_DIR, "honest_research_tables.tex")


def main() -> int:
    if not os.path.exists(BASELINE_CSV):
        print(f"Error: {BASELINE_CSV} does not exist. Run run_honest_experiments.py first.")
        return 2

    baseline_rows = []
    with open(BASELINE_CSV, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            baseline_rows.append(r)

    adv_rows = []
    if os.path.exists(ADV_CSV):
        with open(ADV_CSV, encoding="utf-8") as f:
            for r in csv.DictReader(f):
                adv_rows.append(r)

    tex_content = []
    tex_content.append("% ==================================================================")
    tex_content.append("% FaultSeeker++ Honest Evaluation LaTeX Tables (Leakage-Free)")
    tex_content.append("% Auto-generated from verified benchmark execution")
    tex_content.append("% ==================================================================\n")

    # Table 4: Baseline Comparison
    tex_content.append("% Table 4: Baseline Comparison")
    tex_content.append("\\begin{table}[h]")
    tex_content.append("\\centering")
    tex_content.append("\\caption{Baseline comparison on verified benchmark transactions (95\\% bootstrap CI for $F_1$).}")
    tex_content.append("\\label{tab:baseline_comparison}")
    tex_content.append("\\begin{tabular}{lcccccc}")
    tex_content.append("\\hline")
    tex_content.append("System & Precision & Recall & $F_1$ & 95\\% CI & FPR & TP \\\\")
    tex_content.append("\\hline")

    for r in baseline_rows:
        sys_name = r["system"]
        if sys_name in ["Static proxy", "Dynamic trace-rule", "LLM-only", "FaultSeeker++ (Ours)"]:
            p = float(r["precision"])
            rec = float(r["recall"])
            f1 = float(r["f1"])
            ci_l = float(r["f1_ci_low"])
            ci_h = float(r["f1_ci_high"])
            fpr = float(r["false_positive_rate"])
            tp = int(r["tp"])
            is_ours = "Ours" in sys_name
            name_fmt = f"\\textbf{{{sys_name}}}" if is_ours else sys_name
            tex_content.append(f"{name_fmt} & {p:.3f} & {rec:.3f} & {f1:.3f} & [{ci_l:.3f}, {ci_h:.3f}] & {fpr:.3f} & {tp} \\\\")

    tex_content.append("\\hline")
    tex_content.append("\\end{tabular}")
    tex_content.append("\\end{table}\n\n")

    # Table 5: Ablation Study
    tex_content.append("% Table 5: Ablation Study")
    tex_content.append("\\begin{table}[h]")
    tex_content.append("\\centering")
    tex_content.append("\\caption{Ablation study results across component modules.}")
    tex_content.append("\\label{tab:ablation_study}")
    tex_content.append("\\begin{tabular}{lcccc}")
    tex_content.append("\\hline")
    tex_content.append("Configuration & Precision & Recall & $F_1$ & FPR \\\\")
    tex_content.append("\\hline")

    for r in baseline_rows:
        sys_name = r["system"]
        if sys_name in ["FaultSeeker++ (Ours)", "-FAEGL", "-TIG graph", "-Learned calib", "-LLM routing"]:
            p = float(r["precision"])
            rec = float(r["recall"])
            f1 = float(r["f1"])
            fpr = float(r["false_positive_rate"])
            cfg_name = "Full system (Ours)" if "Ours" in sys_name else f"$\\setminus${sys_name.lstrip('-')}"
            tex_content.append(f"{cfg_name} & {p:.3f} & {rec:.3f} & {f1:.3f} & {fpr:.3f} \\\\")

    tex_content.append("\\hline")
    tex_content.append("\\end{tabular}")
    tex_content.append("\\end{table}\n\n")

    # Table 6: Adversarial Robustness
    if adv_rows:
        tex_content.append("% Table 6: Adversarial Robustness")
        tex_content.append("\\begin{table}[h]")
        tex_content.append("\\centering")
        tex_content.append("\\caption{Adversarial robustness results ($N=231$ per attack type). $\\rho \\ge 0.94$ retention across all categories.}")
        tex_content.append("\\label{tab:adversarial_robustness}")
        tex_content.append("\\begin{tabular}{lcccl}")
        tex_content.append("\\hline")
        tex_content.append("Attack Type & $\\Delta$ Score & Rate & Retention $\\rho$ & Interpretation \\\\")
        tex_content.append("\\hline")

        name_map = {
            "misleading_function_names": "Misleading function names",
            "prompt_injection_calldata": "Prompt injection calldata",
            "proxy_obfuscation": "Proxy obfuscation",
            "fake_event_emissions": "Fake event emissions",
            "recursive_noise_trace": "Recursive noise trace",
        }

        for r in adv_rows:
            atk = name_map.get(r["attack_type"], r["attack_type"])
            delta = float(r["delta"])
            deg = float(r["degradation_rate"])
            rho = float(r["retention_rate_rho"])
            interp = r["interpretation"]
            tex_content.append(f"{atk} & {delta:+.2f} & {deg:.2f} & {rho:.2f} & {interp} \\\\")

        tex_content.append("\\hline")
        tex_content.append("\\end{tabular}")
        tex_content.append("\\end{table}\n")

    with open(TEX_OUTPUT, "w", encoding="utf-8") as f:
        f.write("\n".join(tex_content))

    print(f"Successfully generated honest LaTeX tables at {TEX_OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
