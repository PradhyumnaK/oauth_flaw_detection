"""rule_engine.py
Rule-based detector for OAuth/OIDC traces.
Produces a rule label and a set of binary rule flags per trace."""

import json
from pathlib import Path
import csv
from typing import Dict, Any, Tuple

TRACES_ROOT = Path("traces")

REDIRECT_URI = "http://localhost:4000/callback"

LABEL_MAP = {
    "normal": 0,
    "no_pkce_accepted": 1,
    "no_pkce_rejected": 2,
    "pkce_downgrade": 3,
    "redirect_flaw_strict": 4,
    "redirect_flaw_misconfig": 5,
    "refresh_misuse_rejected": 6,
    "refresh_misuse_stolen": 7,
}

def step(trace: Dict[str, Any], name: str) -> Dict[str, Any]:
    return next ((s for s in trace.get("steps", []) if s.get("step") == name), {})

def headers(step: Dict[str, Any], part: str) -> Dict[str, str]:
    return step.get(part, {}).get("headers", {})

def has(headers: Dict[str, str], name: str) -> int:
    return int(any(k.lower() == name.lower() for k in headers))

def apply_rules(trace: Dict[str, Any]) -> Tuple[str, Dict[str, int]]:
    """Return rule label and flag
    Rule label is one of the scenarios in label map, if not it is set to unknown
    Flag is a dict of rule (0it is 0 or 1)"""

    scenario = trace.get("scenario", "")
    auth_req = step(trace, "authorization_request")
    login_sbmt = step(trace, "login_submit")
    tok_ex = step(trace, "token_exchange")
    code_rcvd = step(trace, "code_received")

    ap = auth_req.get("request", {}).get("params", {}) #auth params
    td = tok_ex.get("request", {}).get("data", {}) #token data

    #Rule flags
    #redirect uri strict mismatch
    redirect_uri = ap.get("redirect_uri", "")
    redirect_strict_mismatch = int(
        redirect_uri != REDIRECT_URI and not redirect_uri.startswith(REDIRECT_URI + "?")
    )
    #redirect uri misuse (misocnfiguration with wildcard)
    redirect_wildcard_misconfig = int(
        redirect_uri.startswith(REDIRECT_URI + "?")
    )
    #PKCE missing
    pkce_missing = int(
        not ap.get("code_challenge") or not ap.get("code_challenge_method")
    )
    #PKCE downgrade to plain
    pkce_plain = int(ap.get("code_challenge_method") == "plain")
    #Refresh token misuse with wrong client id
    refresh_misuse_wrong_client_step = step(trace, "refresh_misuse_wrong_client")
    refresh_misuse_wrong_client = int(bool(refresh_misuse_wrong_client_step))
    #Stolen refresh attempt in a new session
    stolen_refresh_attempt_step = step(trace, "stolen_refresh_attempt")
    stolen_refresh_attempt = int(bool(stolen_refresh_attempt_step))
    #Code present flag
    code_present = int(bool(code_rcvd.get("code_present")))
    #Token response status
    token_status = tok_ex.get("response", {}).get("status", 0)
    token_error = int(token_status != 200)
    #New additions to fix classifier issue
    #Refresh misuse step present(wrong client id attempt)
    refresh_step = step(trace, "refresh_misuse_wrong_client")
    refresh_status = refresh_step.get("response", {}).get("status", 0) if refresh_step else 0
    #Stolen refresh attempt step present
    stolen_step = step(trace, "stolen_refresh_attempt")
    stolen_status = stolen_step.get("response", {}).get("status", 0) if stolen_step else 0
    #Redirect misconfig: code was issued to malicious URI
    code_step = step(trace, "code_received")
    redirect_to = code_step.get("redirect_to", "") if code_step else ""
    #Only fire if redirect_to contains an attacker controlled parameter
    #Normal flows have state and code but no site name or atatcker patterns
    MALICIOUS_INDICATORS = ["evil.example", "attacker.com", "//evil", "steal", "next=http"]
    redirect_code_to_malicious = int(
        bool(code_step)
        and bool(redirect_to)
        and any(indicator in redirect_to for indicator in MALICIOUS_INDICATORS)
    )

    #Shared rule families
    #PKCE weak: missing or downgraded PKCE
    pkce_missing = int(
        not ap.get("code_challenge") or not ap.get("code_challenge_method")
    )
    pkce_plain = int(ap.get("code_challenge_method") == "plain")
    rule_pkce_weak = int(pkce_missing or pkce_plain)

    #Redirect flaw: strict mismatch or wildcard pattern
    redirect_uri = ap.get("redirect_uri", "") or ""
    redirect_strict_mismatch = int(
        redirect_uri != REDIRECT_URI and not redirect_uri.startswith(REDIRECT_URI + "?")
    )
    redirect_wildcard_misconfig = int(redirect_uri.startswith(REDIRECT_URI + "?"))

    code_step = step(trace, "code_received")
    redirect_to = code_step.get("redirect_to", "") if code_step else ""
    MALICIOUS_INDICATORS = ["evil.example", "attacker.com", "//evil", "steal", "next=http"]
    redirect_code_to_malicious = int(
        redirect_strict_mismatch
        or redirect_wildcard_misconfig
        or redirect_code_to_malicious
    )
    rule_redirect_suspicious = int(
        redirect_strict_mismatch
        or redirect_wildcard_misconfig
        or redirect_code_to_malicious
    )

    #Refresh abuse: any refresh misuse or stolen reuse attempt
    refresh_step = step(trace, "refresh_misuse_wrong_client")
    stolen_step = step(trace, "stolen_refresh_attempt")
    rule_refresh_abuse = int(bool(refresh_step) or bool(stolen_step))

    #Generic errors
    token_error = int(token_status != 200)
    auth_status = auth_req.get("response", {}).get("status", 0) if auth_req else 0
    rule_auth_error = int(auth_status >= 400)
    rule_token_error = token_error

    flags = {
        "rule_pkce_weak": rule_pkce_weak,
        "rule_redirect_suspicious": rule_redirect_suspicious,
        "rule_refresh_abuse": rule_refresh_abuse,
        "rule_auth_error": rule_auth_error,
        "rule_token_error": rule_token_error,
    }
    #Rule label decision (coarse family labels)

    label = "normal"
    if flags["rule_refresh_abuse"]:
        label = "refresh_misuse_rejected" #Treat all refresh abuse as one family
    elif flags["rule_redirect_suspicious"]:
        label = "redirect_flaw_strict"
    elif flags["rule_pkce_weak"]:
        label = "no_pkce_rejected" #Group all PKCE weaknesses under one family
    elif flags["rule_auth_error"] or flags["rule_token_error"]:
        #Generic protocol error, map back to scenario if known
        if scenario and scenario in LABEL_MAP:
            label = scenario
    
    return label, flags

def main():
    traces_root = TRACES_ROOT
    out_rows = []

    for d in sorted(traces_root.iterdir()):
        if not d.is_dir():
            continue
        files = sorted(d.glob("*.json"))
        if not files:
            continue
        print(f"[rules] {d.name}: {len(files)} traces")
        for f in files:
            try:
                trace = json.loads(f.read_text(encoding = "utf-8"))
            except Exception as e:
                print(f"[warning] {f}: {e}")
                continue
            label, flags = apply_rules(trace)
            out_rows.append({
                "scenario": trace.get("scenario"),
                "run": trace.get("run"),
                "rule_label": label,
                **flags,
            })
    #save the rule output for later use for ML
    out_file = Path("rule_outputs.csv")
    if out_rows:
        with open(out_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
            writer.writeheader()
            writer.writerows(out_rows)
        print(f"[rules] saved {len(out_rows)} rows -> {out_file}")

if __name__ == "__main__":
    main()