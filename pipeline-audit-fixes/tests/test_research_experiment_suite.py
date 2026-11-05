import csv

from benchmark.run_research_experiments import (
    ablation_systems,
    baseline_systems,
    evaluate_system,
    load_rows,
)


def test_research_experiment_suite_generates_nontrivial_comparisons(tmp_path):
    exploit_pool = tmp_path / "pool.csv"
    benign = tmp_path / "benign.csv"
    exploit_pool.write_text(
        "\n".join(
            [
                "txn_hash,chain,vuln_type,source,source_incident_id,title,pool_status,validation_status,merge_blocker",
                f"0x{'1' * 64},eth,Reentrancy,test,i,t,verified_benchmark,verified_ground_truth,",
                f"0x{'2' * 64},eth,Unknown,test,i,t,source_backed_candidate,source_poc_tx_candidate_pending_rpc,",
                f"0x{'3' * 64},bsc,Price Manipulation,test,i,t,source_backed_candidate,source_poc_tx_candidate_pending_rpc,",
            ]
        ),
        encoding="utf-8",
    )
    with benign.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["txn_hash", "chain", "source", "validation_status"],
        )
        writer.writeheader()
        for idx in range(20):
            writer.writerow(
                {
                    "txn_hash": "0x" + f"{idx + 10:064x}",
                    "chain": "eth",
                    "source": "test",
                    "validation_status": "address_label_benign_candidate",
                }
            )

    rows = load_rows(str(exploit_pool), str(benign), benign_limit=20)
    full = evaluate_system("Full system + FAEGL", ablation_systems()["Full system + FAEGL"], rows)
    no_faegl = evaluate_system("Without FAEGL", ablation_systems()["Without FAEGL"], rows)
    static = evaluate_system("Static proxy baseline", baseline_systems()["Static proxy baseline"], rows)

    assert len(rows) == 23
    assert full["recall"] >= no_faegl["recall"]
    assert full["f1"] >= static["f1"]
