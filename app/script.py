import json
import glob
from pathlib import Path

TRACES_ROOT = Path("traces")

EXPECTED_OUTCOMES = {
    "normal": "success",
    "no_pkce_accepted": "success",
    "no_pkce_rejected": "token_error",
    "pkce_downgrade": "success",
    "redirect_flaw_strict": "redirect_uri_rejection",
    "redirect_flaw_misconfig": "code_issued_to_malicious_redirect",
    "refresh_misuse_rejected": "refresh_misuse_rejected",
    "refresh_misuse_stolen": "refresh_misuse_accepted",
}

def main():
    print(f"{'Scenario':<26}{'Total':>7}{'Expected':>10}{'%':>8}{'Other':>8}{'%':>8}")
    print("-" * 67)

    grand_total = 0
    grand_expected = 0

    for scenario_dir in sorted(TRACES_ROOT.iterdir()):
        if not scenario_dir.is_dir():
            continue
        scenario = scenario_dir.name
        expected_result = EXPECTED_OUTCOMES.get(scenario)

        files = sorted(scenario_dir.glob("*.json"))
        total = len(files)
        expected_count = 0

        for f in files:
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
            except Exception as e:
                print(f"  PARSE ERROR {f}: {e}")
                continue
            result = d.get("outcome", {}).get("result")
            if result == expected_result:
                expected_count += 1

        other_count = total - expected_count
        expected_pct = (expected_count / total * 100) if total else 0
        other_pct = 100 - expected_pct if total else 0

        print(f"{scenario:<26}{total:>7}{expected_count:>10}{expected_pct:>7.1f}%{other_count:>8}{other_pct:>7.1f}%")

        grand_total += total
        grand_expected += expected_count

    print("-" * 67)
    overall_pct = (grand_expected / grand_total * 100) if grand_total else 0
    print(f"{'TOTAL':<26}{grand_total:>7}{grand_expected:>10}{overall_pct:>7.1f}%")

if __name__ == "__main__":
    main()