import base64
import hashlib
import json
import os
import secrets
import requests
import html
import re
import time
import random
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:15.0) Firefox/15.0.1",
]

SCOPES = [
    "openid",
    "openid profile",
    "openid email",
    "openid profile email",
]
TRACES_ROOT = Path("traces")
TRACES_ROOT.mkdir(exist_ok=True)

USERNAME = "test"
PASSWORD = "test"

REALM="master"
KEYCLOAK_BASE="http://localhost:8080"
CLIENT_ID="testing"
REDIRECT_URI="http://localhost:4000/callback"
TRACES_DIR="traces"

def b64url_no_padding(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def pkce_pair():
    verifier=b64url_no_padding(secrets.token_bytes(32))
    digest=hashlib.sha256(verifier.encode("ascii")).digest()
    challenge=b64url_no_padding(digest)
    return verifier,challenge

def get_login_action_url(html_text: str) -> str:
    """Extract Keycloak login form action URL from HTML."""
    m = re.search(r'action="([^"]+)"', html_text)
    if not m:
        raise RuntimeError("Could not find login form action in Keycloak HTML")
    return html.unescape(m.group(1))

def extract_code_from_location(location: str) -> str:
    """Extract code from redirect URL."""
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    code = qs.get("code", [None])[0]
    if not code:
        raise RuntimeError(f"No 'code' parameter in redirect: {location}")
    return code

def timed_request(session: requests.Session, method: str, url: str, ** kwargs) -> dict:
    """Send HTTP request via session and return a structured record with timing."""
    t0 = time.time()
    resp = session.request(method, url, allow_redirects=False, **kwargs)
    t1 = time.time()
    duration_in_ms = int((t1-t0)*1000)
    return {
        "response": resp,
        "duration_in_ms": duration_in_ms,
    }

def build_normal_auth_request():
    """
    Perform: discovery, PKCE, auth URL, trace.
    Returns auth_endpoint, auth_url, auth_params, code_verifier, trace.
    """
    os.makedirs(TRACES_DIR, exist_ok=True)

    #Fetch discovery doc from Keycloak
    discovery_url = f"{KEYCLOAK_BASE}/realms/{REALM}/.well-known/openid-configuration"
    resp = requests.get(discovery_url)
    resp.raise_for_status()
    meta=resp.json()

    auth_endpoint = meta["authorization_endpoint"]
    token_endpoint = meta["token_endpoint"]

    #Generate PKCE and state/none
    code_verifier, code_challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    #Scope variation
    scope = random.choice(SCOPES)

    #Build authorization URL
    auth_params={
        "response_type":"code",
        "client_id":CLIENT_ID,
        "redirect_uri":REDIRECT_URI,
        "scope":scope,
        "state":state,
        "nonce":nonce,
        "code_challenge":code_challenge,
        "code_challenge_method":"S256",
    }
    #auth_url=f"{auth_endpoint}?{urlencode(auth_params)}"

    return auth_endpoint, token_endpoint, auth_params, code_verifier

def run_normal_flow(run: int=1) -> dict:
    """Automated normal authorization code and PKCE flow: 
    authorization request, login, code reception, token exchange
    Writes traces/normal_<run>.json and returns trace dict."""
    os.makedirs(TRACES_DIR, exist_ok=True)
    session = requests.Session()

    #Choose a random user agent for every flow from the defined user agents
    user_agent = random.choice(USER_AGENTS)
    default_headers = {"User-Agent": user_agent}

    auth_endpoint, token_endpoint, auth_params, code_verifier = build_normal_auth_request()

    trace = {
        "scenario": "normal",
        "run": run,
        "chosen_scope": auth_params.get("scope"),
        "user_agent": user_agent,
        "steps": [],
        "outcome": {},
    }

    #Step 1: authorization request (client -> AS)
    #auth_resp = session.get(auth_endpoint, params=auth_params, allow_redirects=False)
    auth_rec = timed_request (
        session,
        "GET",
        auth_endpoint,
        params=auth_params,
        headers=default_headers,
    )
    auth_resp = auth_rec["response"]
    trace["steps"].append({
        "step": "authorization_request",
        "duration_in_ms": auth_rec["duration_in_ms"],
        "request": {
            "method": "GET",
            "url": auth_endpoint,
            "params": auth_params,  
            "headers": default_headers, 
        },
        "response": {
            "status": auth_resp.status_code,
            "headers": dict(auth_resp.headers),
            "location": auth_resp.headers.get("Location"),
            "body_snippet": auth_resp.text[:500],
        },
    })

    if auth_resp.status_code not in (200, 302):
        trace["outcome"] = {
            "result": "auth_request_failed",
            "status": auth_resp.status_code,
            "issue": "authorization_endpoint_rejected_request",
            "reason": "Authorization endpoint did not return 200/302 for normal flow",
        }
        return save_trace(trace, run)
    
    login_url = auth_resp.headers.get("Location") or auth_resp.url

    #Step 2: GET login page (browser -> AS)
    #login_page = session.get(login_url, allow_redirects=False)
    login_rec = timed_request(
        session,
        "GET",
        login_url,
        headers = default_headers,
    )
    login_page = login_rec["response"]
    login_action = get_login_action_url(login_page.text)
    cookie = login_page.headers.get("Set-Cookie", "")
    
    #Log login page as its own step with headers and a snippet of HTML
    trace["steps"].append({
        "step": "login_page",
        "duration_in_ms": login_rec["duration_in_ms"],
        "request": {
            "method": "GET",
            "url": login_url,
            "headers": default_headers,
        },
        "response": {
            "status": login_page.status_code,
            "headers": dict(login_page.headers),
            "body_snippet": login_page.text[:500],
            "login_form_action": login_action,
        },
    })

    #Step 3: Submit credentials (user confirms request)
    #login_resp = session.post(
     #   login_action,
      #  data={"username": USERNAME, "password": PASSWORD},
       # headers={"Cookie": cookie},
        #allow_redirects=False,
    #)
    login_headers = {
        "Cookie": cookie,
        "User-Agent": user_agent,
    }
    login_rec = timed_request(
        session,
        "POST",
        login_action,
        data={"username": USERNAME, "password": PASSWORD},
        headers=login_headers,
    )
    login_resp = login_rec["response"]
    redirect_back = login_resp.headers.get("Location", "")
    trace["steps"].append({
        "step": "login_submit",
        "duration_in_ms": login_rec["duration_in_ms"],
        "request": {
            "method": "POST",
            "url": login_action,
            "data": {"username": USERNAME, "password": "***"},
            "headers": login_headers,
        },
        "response": {
            "status": login_resp.status_code,
            "headers": dict(login_resp.headers),
            "location": redirect_back,
            "body_snippet": login_resp.text[:500],
        },
    })

    if not redirect_back:
        trace["outcome"] = {
            "result": "login_failed_no_redirect",
            "status": login_resp.status_code,  
            "issue": "no_redirect_after_login",
            "reason": "Login POST did not include Location header back to redirect_uri",
        }
        return save_trace(trace, run)
    
    #Step 4: AS generates code and redirects to client (3 returns code)
    try:
        code = extract_code_from_location(redirect_back)
    except RuntimeError as e:
        trace["outcome"] = {"result": "no_code_in_redirect", "details": str(e)}
        return save_trace(trace, run)
    
    trace["steps"].append({
        "step": "code_received",
        "redirect_to": redirect_back,
        "code_present": True,
    })

    #Step 5: Client requests token (4 tokens token)
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    #token_resp = session.post(token_endpoint, data=token_data, allow_redirects=False)
    token_rec = timed_request(
        session, 
        "POST",
        token_endpoint,
        data=token_data,
        headers=default_headers,
    )
    token_resp = token_rec["response"]


    #Omit code and code_verifier for safety
    trace["steps"].append({
        "step": "token_exchange",
        "duration_in_ms": token_rec["duration_in_ms"],
        "request": {
            "method": "POST",
            "url": token_endpoint,
            "data": {
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
            },
            "headers": default_headers,
        },
        "response": {
            "status": token_resp.status_code,
            "headers": dict(token_resp.headers),
            "body_snippet": token_resp.text[:500],
        },
    })

    if token_resp.status_code == 200:
        trace["outcome"] = {
            "result": "success", 
            "status": 200,
            "issue": None,
            "reason": "Tokens successfully issued for normal PKCE flow",
        }
    else:
        trace["outcome"] = {
            "result": "token_error", 
            "status": token_resp.status_code,
            "issue": "token_endpoint_error",
            "reason": "Token endpoint did not return 200 for authorization_code request",
        }

    return save_trace(trace, run)   

def save_trace(trace: dict, run: int) -> dict:
    scenario = trace.get("scenario", "unknown")
    scenario_dir = TRACES_ROOT / scenario
    scenario_dir.mkdir(parents=True, exist_ok=True)

    #out_file = os.path.join(TRACES_DIR, f"normal_{run}.json")
    out_file = scenario_dir / f"{scenario}_{run}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(trace, f, indent=2)
    print(f"[run {run}] Trace saved to {out_file}")
    return trace

def main():
    #Run the normal flow 125 times to create 125 randomized flow traces
    for run in range(1,126):
        print(f"Running normal flow: #{run}")
        run_normal_flow(run=run)


if __name__=="__main__":
    main()