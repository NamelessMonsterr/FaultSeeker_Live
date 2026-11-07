import os
import json
import argparse
from datetime import datetime
from faultseeker.core.config import FaultSeekerConfig
from faultseeker.core.pipeline import FaultSeekerPipeline


def banner():
    print("\n" + "="*60)
    print("🔍 FaultSeeker - Blockchain Transaction Analyzer")
    print("="*60)



def main(txn_link: str = None,
         txn_hash: str = None,
         chain: str = None,
         forensics_model: str = 'gpt-4o-mini',
         function_analysis_model: str = 'gpt-4o-mini',
         cache_dir: str = './data/cache',
         output_dir: str = './data/output'):


    banner()
    print(f"\n📋 Transaction Information:")
    if txn_link:
        print(f"   • Link: {txn_link}")
    elif txn_hash and chain:
        print(f"   • Hash: {txn_hash}")
        print(f"   • Chain: {chain.upper()}")
    else:
        raise ValueError("Either txn_link or both txn_hash and chain must be provided.")

    # Display configuration
    print(f"\n⚙️  Configuration:")
    print(f"   • Forensics Model: {forensics_model}")
    print(f"   • Function Analysis Model: {function_analysis_model}")

    # Set output path and cache root
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"analysis_{timestamp}.json")
    

    print(f"   • Cache Directory: {cache_dir}")
    print(f"   • Output Directory: {output_dir}")

    # Create and run pipeline
    print(f"\n🚀 Initializing analysis pipeline...")
    pipeline = FaultSeekerPipeline(
        config=FaultSeekerConfig(
            forensics_model=forensics_model,
            function_analysis_model=function_analysis_model,
            cache_dir=cache_dir
        )
    )
    print(f"   ✓ Pipeline initialized successfully")

    result = pipeline.analyze_transaction(
        txn_link=txn_link,
        txn_hash=txn_hash,
        chain=chain
    )

    # Save results
    print(f"\n💾 Saving analysis results...")
    with open(output_path, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"   ✓ Results saved to: {output_path}")

    print(f"\n✅ Analysis completed successfully!")
    print("="*60 + "\n")

    return result


def main_cli():
    parser = argparse.ArgumentParser(
        description="FaultSeeker: LLM-Empowered Framework for Blockchain Transaction Forensics",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Input arguments
    parser.add_argument(
        "-txn_link",
        help="Transaction link to analyze (e.g., https://etherscan.io/tx/0x...)"
    )
    parser.add_argument(
        "-txn_hash",
        help="Transaction hash to analyze (alternative to txn_link)"
    )
    parser.add_argument(
        "-chain",
        default="eth",
        help="Chain identifier (eth, bsc, poly, opt, arbi, avax, fantom, base)"
    )

    # Model arguments
    parser.add_argument(
        "-forensics_model",
        default="gpt-4o-mini",
        help="Model for Stage 1 forensics analysis (default: gpt-4o-mini)"
    )
    parser.add_argument(
        "-function_analysis_model",
        default="gpt-4o-mini",
        help="Model for Stage 2 function analysis (default: gpt-4o-mini)"
    )

    # Output arguments
    parser.add_argument(
        "-output",
        default="./data/output",
        help="Output file path for analysis results (default: ./data/output/analysis_YYYYMMDD_HHMMSS.json)"
    )
    parser.add_argument(
        "-cache",
        default="./data/cache",
        help="Cache directory for intermediate results (default: ./data/cache)"
    )

    args = parser.parse_args()

    # Validate input
    if not args.txn_link and not (args.txn_hash and args.chain):
        parser.error("Either -txn_link or both -txn_hash and -chain must be provided")

    # Run main
    try:
        main(
            txn_link=args.txn_link,
            txn_hash=args.txn_hash,
            chain=args.chain,
            forensics_model=args.forensics_model,
            function_analysis_model=args.function_analysis_model,
            cache_dir=args.cache,
            output_dir=args.output
        )
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
