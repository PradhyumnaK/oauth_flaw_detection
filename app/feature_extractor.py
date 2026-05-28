"""feature_extractor.py
Extracts 37 feature vectors from OAuth flow traces.
32 of those are taken from Munonye and Peter's work (2022).
5 new feature vectors are added considering the new RFC 9700 standards."""

import json
import csv
from pathlib import Path
from collections import Counter

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

def step(trace, name):
    return next((s for s in trace.get("steps", []) if s.get("step") == name), {})

def headers(s, part):
    return s.get(part, {}).get("headers", {})

def has(headers, name):
    return int(any(k.lower() == name.lower() for k in headers))

def extract(trace):
    auth_req = step(trace, "authorization_request")
    login_sbmt = step(trace, "login_submit")
    tok_ex = step(trace, "token_exchange")
    code_rcvd = step(trace, "code_received")

    ap = auth_req.get("request", {}).get("params", {}) #auth request params
    td = tok_ex.get("request", {}).get("data", {}) #token request data
    ld = login_sbmt.get("request", {}).get("data", {}) #login data
    ah =  headers(auth_req, "request") #auth request headers
    th = headers(tok_ex, "response") #token response headers
    lh = headers(login_sbmt, "request") #login request headers

    try:
        tb = json.loads(tok_ex.get("response", {}).get("body_snippet", "{}"))
    except Exception:
        tb = {}
    
    method_map = {"S256": 2, "plain": 1}

    return {
        "scenario": trace.get("scenario"),
        "run": trace.get("run"),
        "x1": int(ap.get("response_type") == "code"),
        "x2": int(bool(ap.get("client_id"))),
        "x3": int(ap.get("redirect_uri") == REDIRECT_URI),
        "x4": int(bool(ap.get("scope"))),
        "x5": int(bool(ap.get("state"))),
        "x6": int(bool(ap.get("code_challenge"))),
        "x7": method_map.get(ap.get("code_challenge_method", ""), 0),
        "x8": int(td.get("grant_type") == "authorization_code"),
        "x9": int(bool(code_rcvd.get("code_present"))),
        "x10": int(td.get("redirect_uri") == REDIRECT_URI),
        "x11": int(bool(td.get("client_id"))),
        "x12": int(bool(ld.get("username"))),
        "x13": int(bool(ld.get("password"))),
        "x14": int(bool(tb.get("access_token"))),
        "x15": int(bool(tb.get("token_type"))),
        "x16": int("expires_in" in tb),
        "x17": int(bool(tb.get("refresh_token"))),
        "x18": has(th, "Cache-Control"),
        "x19": has(ah, "Accept"),
        "x20": has(ah, "Accept-Language"),
        "x21": has(ah, "Connection"),
        "x22": has(ah, "Host"),
        "x23": has(th, "Content-Type"),
        "x24": has(lh, "Cookie"),
        "x25": has(th, "Content-Length"),
        "x26": has(ah, "Origin"),
        "x27": has(ah, "Referer"),
        "x28": has(ah, "User-Agent"),
        "x29": has(ah, "Accept-Encoding"),
        "x30": len({s.get("request", {}).get("method") for s in trace.get("steps", [])} - {None}),
        "x31": has(th, "Referrer-Policy"),
        "x32": has(ah, "X-Requested-With"),
        "x33": int(bool(ap.get("nonce"))),
        "x34": int(ap.get("code_challenge_method") == "S256"),
        "x35": int("iss" in (code_rcvd.get("redirect_to") or "")),
        "x36": int(ap.get("redirect_uri", "").split("?")[0] == REDIRECT_URI),
        "x37": int(bool(step(trace, "refresh_misuse"))),
        "label": LABEL_MAP.get(trace.get("scenario", ""), -1),        
    }

def main():
    traces_root = Path("traces")
    rows = []

    for d in sorted(traces_root.iterdir()):
        if not d.is_dir() or d.name not in LABEL_MAP:
            print(f"[skip] {d.name}")
            continue
        files = sorted(d.glob("*.json"))
        print(f"[load] {d.name}: {len(files)} traces")
        for f in files:
            try:
                rows.append(extract(json.loads(f.read_text(encoding="utf-8"))))
            except Exception as e:
                print(f"[warning] {f}: {e}")
    
    out = Path("dataset.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"\n Saved {len(rows)} rows -> {out}")
    for scenario, n in sorted(Counter(r["scenario"] for r in rows).items()):
        print(f"{scenario:35s} label={LABEL_MAP[scenario]} n={n}")
    
if __name__ == "__main__":
    main()