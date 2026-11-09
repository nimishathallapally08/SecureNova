"""Display one saved Project 3 case for a screenshot; no inference is performed."""

import argparse
import json
from pathlib import Path

PROJECT = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_id", help="Case ID, or ordinary-refund-control")
    parser.add_argument("--run", type=Path, required=True,
                        help="Directory containing a Project 3 manifest and results")
    args = parser.parse_args()

    manifest = json.loads((args.run / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "complete":
        parser.error("The selected run is not complete")
    if args.case_id == "ordinary-refund-control":
        result = json.loads((args.run / "negative-control.json").read_text(encoding="utf-8"))
    else:
        results = json.loads((args.run / "results.json").read_text(encoding="utf-8"))
        matches = [item for item in results if item["case_id"] == args.case_id]
        if len(matches) != 1:
            parser.error(f"Case not found or duplicated: {args.case_id}")
        result = matches[0]
    if result["case_id"] != args.case_id:
        parser.error("Control record does not match the requested case")

    print(f"SAVED RUN: {args.run}")
    print(f"BACKEND: {manifest['backend']} (recorded response; no new model request)")
    if manifest.get("indirect_setup") == "intentionally_vulnerable_demo":
        print("INDIRECT SETUP: intentionally vulnerable, synthetic JWT only")
    print(f"\nCASE: {result['case_id']} ({result['family']})")
    if result["document"]:
        print(f"DOCUMENT:\n{result['document']}")
    print(f"PROMPT:\n{result['prompt']}")
    print(f"MODEL RESPONSE:\n{result['model_response'] or '(no text response)'}")
    if result["requested_tools"]:
        print("MODEL TOOL CALLS:")
        print(json.dumps(result["requested_tools"], indent=2))
    print(f"EXECUTED MOCK ACTIONS: {json.dumps(result['executed_actions'])}")
    print(f"OUTCOME: {'SUCCESS' if result['attack_success'] else 'FAILED'}")
    print(f"SUCCESS DEFINITION: {result['success_definition']}")


if __name__ == "__main__":
    main()
