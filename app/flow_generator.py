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
import http
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs
STOLEN_REFRESH_TOKENS: list[str] = []

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
    #Removing allow_redirects parameter in resp
    #allow_redirects is passed via **kwargs so each call controls redirect behaviour explicitly
    resp = session.request(method, url, **kwargs)
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

class AllowSecureOnHTTP(http.cookiejar.DefaultCookiePolicy):
    """Allow secure cookies to be stored and sent over plain HTTP.
    This is needed because Keycloak secure flag even on localhost."""

    def set_ok(self, cookie, request):
        cookie.secure = False
        return super().set_ok(cookie, request)
    
    def return_ok(self, cookie, request):
        cookie.secure = False
        return super().return_ok(cookie, request)
    
def make_session() -> requests.Session:
    session = requests.Session()
    session.cookies.set_policy(AllowSecureOnHTTP())
    return session

def run_flow(scenario: str, build_auth_fn, run: int=1, mutate_token_request_fn=None) -> dict:
    """Shared core for all flows (normal and flawed)
    -Scenario: label for traces directory and outcome.scenario
    -build_auth_fn: function returning auth_endpoint, token_endpoint, auth_params, code_verifier
    -mutate_token_request_fn: provides dict for all flaws using token_data dict"""

    os.makedirs(TRACES_DIR, exist_ok=True)
    session = make_session()

    #Choose a random user agent for every flow from the defined user agents
    user_agent = random.choice(USER_AGENTS)
    default_headers = {"User-Agent": user_agent}

    auth_endpoint, token_endpoint, auth_params, code_verifier = build_auth_fn()

    trace = {
        "scenario": scenario,
        "run": run,
        "chosen_scope": auth_params.get("scope"),
        "user_agent": user_agent,
        "steps": [],
        "outcome": {},
    }

    #Step 1: authorization request (client -> AS)
    #allow_redirects is always set to False, so that we control each hop and the session
    #cookie jar is updated one request at a time
    auth_rec = timed_request (
        session,
        "GET",
        auth_endpoint,
        params=auth_params,
        headers=default_headers,
        allow_redirects=False,
    )
    auth_resp = auth_rec["response"]

    if auth_resp.status_code not in (200, 302):
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
            },
        })
        trace["outcome"] = {
            "result": "auth_request_failed",
            "status": auth_resp.status_code,
            "issue": "authorization_endpoint_rejected_request",
            "reason": "Authorization endpoint did not return 200/302",
        }
        return save_trace(trace, run)
    
    #Keycloak returns 200 with the login form directly or 302 to the login page URL.
    #We need to handle both explicitly
    if auth_resp.status_code == 302:
        login_page_url = auth_resp.headers.get("Location")
        login_page_rec = timed_request(
            session,
            "GET",
            login_page_url,
            headers=default_headers,
            allow_redirects=False,
        )
        login_page_resp = login_page_rec["response"]
        form_html = login_page_resp.text
        form_status = login_page_resp.status_code
        form_headers = dict(login_page_resp.headers)
        step1_duration = auth_rec["duration_in_ms"] + login_page_rec["duration_in_ms"]

    else:
        #200 login form is in the body directly and second request is not needed
        form_html = auth_resp.text
        form_status = auth_resp.status_code
        form_headers = dict(auth_resp.headers)
        step1_duration = auth_rec["duration_in_ms"]
    
    try:
        login_action = get_login_action_url(form_html)
    except RuntimeError as e:
        trace["steps"].append({
            "step": "authorization_request",
            "duration_in_ms": step1_duration,
            "request": {
                "method": "GET",
                "url": auth_endpoint,
                "params": auth_params,
                "headers": default_headers,
            },
            "response": {
                "status": form_status,
                "headers": form_headers,
                "body_snippet": form_html[:500]
            }
        })
        trace["outcome"] = {"result": "no_login_form", "details": str(e)}
        return save_trace(trace, run)
    
    trace["steps"].append({
        "step": "authorization_request",
        "duration_in_ms": step1_duration,
        "request": {
            "method": "GET",
            "url": auth_endpoint,
            "params": auth_params,
            "headers": default_headers,
        },
        "response": {
            "status": form_status,
            "headers": form_headers,
            "login_form_action": login_action,
            "body_snippet": form_html[:500],
        },
    })

    #Step 2: Submit credentials (user confirms request) (browser -> AS)
    #Manual cookie header is not needed, session manages cookies automatically
    login_headers = {
        "User-Agent": user_agent,
    }
    login_rec = timed_request(
        session,
        "POST",
        login_action,
        data={"username": USERNAME, "password": PASSWORD},
        headers=login_headers,
        allow_redirects=False,
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
    #This check can be removed later for flawed scenarios
    if not redirect_back.startswith(REDIRECT_URI):
        trace["outcome"] = {
            "result": "login_failed_bad_redirect",
            "status": login_resp.status_code,  
            "issue": "login_post_failed",
            "reason": f"Keycloak returned {login_resp.status_code} on login post, expected 302 to {REDIRECT_URI}, got: {redirect_back}",
        }
        return save_trace(trace, run)
    
    #Step 3: AS generates code and redirects to client (3 returns code)
    #Here we are extracting code from redirect
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

    #Step 4: Client requests token (4 tokens token)
    #Token exchange (client -> AS)
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    if mutate_token_request_fn is not None:
        token_data = mutate_token_request_fn(token_data)

    token_rec = timed_request(
        session, 
        "POST",
        token_endpoint,
        data=token_data,
        headers=default_headers,
        allow_redirects=False,
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
                "grant_type": token_data.get("grant_type"),
                "client_id": token_data.get("client_id"),
                "redirect_uri": token_data.get("redirect_uri"),
                #Fix to solve classifier issue
                "code_verifier_sent": bool(token_data.get("code_verifier")),
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
            "reason": f"Tokens successfully issued for {scenario} flow",
        }
    else:
        trace["outcome"] = {
            "result": "token_error", 
            "status": token_resp.status_code,
            "issue": "token_endpoint_error",
            "reason": "Token endpoint did not return 200 for authorization_code request",
        }

    return save_trace(trace, run)   

def run_normal_flow(run: int = 1) -> dict:
    """Normal authorization + PKCE flow"""
    return run_flow(
        scenario="normal",
        run=run,
        build_auth_fn=build_normal_auth_request,
        mutate_token_request_fn=None,
    )

def build_open_redirect_auth_request():
    """Flaw: authorization request with an unregistered redirect_uri
    that includes an atatcker controlled open redirect parameter.
    Keycloak should reject this at the auth endpoint."""
    
    os.makedirs(TRACES_DIR, exist_ok=True)

    discovery_url = f"{KEYCLOAK_BASE}/realms/{REALM}/.well-known/openid-configuration"
    resp = requests.get(discovery_url)
    resp.raise_for_status()
    meta = resp.json()
    auth_endpoint = meta["authorization_endpoint"]
    token_endpoint = meta["token_endpoint"]

    code_verifier, code_challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    scope = random.choice(SCOPES)

    #Varying suffix to avoid identical traces
    suffixes = [
        "?next=http://evil.example/steal",
        "?redirect=http://attacker.com",
        "?url=//evil.example",
        "?r=http://evil.example/cb",
    ]

    redirect_variants = [
        REDIRECT_URI + random.choice(suffixes), #wildcard
        REDIRECT_URI.replace("4000", "4001"), #different port
        REDIRECT_URI + "/extra", #extra path segment
        "http://localhost:4000/cb", #similar but not identical path
    ]

    malicious_redirect = REDIRECT_URI + random.choice(redirect_variants)

    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": malicious_redirect,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return auth_endpoint, token_endpoint, auth_params, code_verifier

def run_open_redirect_flow(run: int = 1, scenario: str = "redirect_flaw") -> dict:
    """Flaw scenario: redirect_flaw
    The AS is expected to reject the redirect_uri. The flaw is in the client's request"""
    trace = run_flow(
        scenario = scenario,
        build_auth_fn=build_open_redirect_auth_request,
        run=run,
        mutate_token_request_fn=None,
    )

    #Case 1: AS rejected the request at auth endpoint (this is when redirect uri is stricly defined).
    if trace.get("steps"):
        first_step = trace["steps"][0]
        status  = first_step["response"].get("status")
        if status not in (200, 302):
            auth_params = first_step["request"].get("params", {})
            bad_redirect = auth_params.get("redirect_uri")
            trace["outcome"] = {
                "result": "redirect_uri_rejection",
                "status": status,
                "issue": "unregistered_redirect_uri",
                "reason": f"AS rejected redirect_uri not matching registered value: {bad_redirect}",
            }
            save_trace(trace, run)
            return trace

    #Case 2: AS accepted but code was sent to the malicious redirect (this is when "*" is used at the end of the redirect uri).
    code_step = next((s for s in trace.get("steps", []) if s["step"] == "code_received"), None)
    if code_step:
        redirect_to = code_step.get("redirect_to", "")
        #Code URL has more parameters after the registered callback
        if "?" in redirect_to and any(
            suffix in redirect_to
            for suffix in ["evil.example", "attacker.com", "//evil"]
        ):
            trace["outcome"] = {
                "result": "code_issued_to_malicious_redirect",
                "status": 200,
                "issue": "open_redirector_exploited",
                "reason": f"Authorization code was delivered to attacker URI: {redirect_to}",
            }
            save_trace(trace, run)
    return trace

def build_pkce_downgrade_auth_request():
    """Flaw: PKCE downgrade. Use code challenge method as 'plain' instead of 'S256'
    code challenge is same as the code verifier."""
    os.makedirs(TRACES_DIR, exist_ok=True)

    discovery_url = f"{KEYCLOAK_BASE}/realms/{REALM}/.well-known/openid-configuration"
    resp = requests.get(discovery_url)
    resp.raise_for_status()
    meta = resp.json()
    auth_endpoint = meta["authorization_endpoint"]
    token_endpoint = meta["token_endpoint"]

    #Misusing the verifier directly as the challenge with some variants
    code_verifier, _ = pkce_pair()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    scope = random.choice(SCOPES)

    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "nonce": nonce,
    }

    downgrade_variants = [
        {"code_challenge": code_verifier, "code_challenge_method": "plain"},
        {"code_challenge": code_verifier[:10], "code_challenge_method": "S256"}, #Truncated challenge
        {"code_challenge": code_verifier[:16], "code_challenge_method": "plain"}, #Truncated+plain
    ]
    auth_params.update(random.choice(downgrade_variants))

    return auth_endpoint, token_endpoint, auth_params, code_verifier

def run_pkce_downgrade(run: int = 1) -> dict:
    """Flaw: pkce_downgrade. PKCE uses plain instead of S256."""
    trace = run_flow(
        scenario="pkce_downgrade",
        build_auth_fn=build_pkce_downgrade_auth_request,
        run=run,
        mutate_token_request_fn=None,
    )
    outcome = trace.get("outcome", {})
    if outcome.get("result") == "success":
        outcome["reason"] = "Tokens issued despite PKCE using plain method"
        trace["outcome"] = outcome
        save_trace(trace, run)
    return trace

def build_no_pkce_auth_request():
    """Flaw: no PKCE parameters in the auth request"""
    os.makedirs(TRACES_DIR, exist_ok=True)

    discovery_url = f"{KEYCLOAK_BASE}/realms/{REALM}/.well-known/openid-configuration"
    resp = requests.get(discovery_url)
    resp.raise_for_status()
    meta = resp.json()
    auth_endpoint = meta["authorization_endpoint"]
    token_endpoint = meta["token_endpoint"]

    #We will still generate a verifier, we just don't send challenge fields
    code_verifier, _ = pkce_pair()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    scope = random.choice(SCOPES)

    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        #Removed PKCE fields
    }
    #Varying how PKCE absence looks
    pkce_absent_variant = random.choice([
        {}, #Pure no PKCE, completely absent
        {"code_challenge": code_verifier}, #challenge without method
        {"code_challenge_method": "S256"}, #method without challenge
    ])
    auth_params.update(pkce_absent_variant)
    return auth_endpoint, token_endpoint, auth_params, code_verifier

def run_no_pkce_flow(run: int = 1, scenario: str = "no_pkce") -> dict:
    """Flaw scenario: no_pkce. Auth request omits PKCE parameters
    -no_pkce_accepted: verifier stripped and keycloak accepts (PKCE is optional)
    -no_pkce_rejected: verifier is sent without challenge and keycloak rejects"""
    def strip_pkce(token_data: dict) -> dict:
        #Removing code verifier so token exchange matches the auth request
        #which had no PKCE challenge. This is to simulate a client that has no PKCE.
        token_data.pop("code_verifier", None)
        return token_data
    
    if scenario == "no_pkce_accepted":
        mutate_fn = strip_pkce
    else:
        mutate_fn = None

    trace = run_flow(
        scenario=scenario,
        build_auth_fn=build_no_pkce_auth_request,
        run=run,
        mutate_token_request_fn=mutate_fn,
    )
    outcome = trace.get("outcome", {})
    if outcome.get("result") == "success":
        outcome["reason"] = "Tokens issued despite missing PKCE parameters"
        trace["outcome"] = outcome
        save_trace(trace, run)
    return trace

def run_refresh_misuse_flow(run: int = 1, scenario: str = "refresh_misuse") -> dict:
    """Flaw scenario: refresh_misuse
    -refresh_misuse_rejected:
        Normal auth +login +token flow, then misuse with incorrect client id.
    -refresh_misuse_stolen:
        Use a refresh token stolen from a previous run in a new session
        with correct client id (this is the attack simulation)."""
    os.makedirs(TRACES_DIR, exist_ok=True)
    scenario = scenario.lower()

    user_agent = random.choice(USER_AGENTS)
    default_headers = {"User-Agent": user_agent}

    #Scenario: stolen refresh token misuse
    if scenario == "refresh_misuse_stolen":
        #We only need token endpoint and the stolen token here
        _, token_endpoint, _, _ = build_normal_auth_request()
        
        trace = {
            "scenario": scenario,
            "run": run,
            "user_agent": user_agent,
            "steps": [],
            "outcome": {},
        }

        if not STOLEN_REFRESH_TOKENS:
            trace["outcome"] = {
                "result": "no_stolen_token_available",
                "issue": "stolen_token_pool_empty",
                "reason": "No refresh tokens available, run refresh_misuse_rejected scenario first",
            }
            return save_trace(trace, run)
        stolen_token = STOLEN_REFRESH_TOKENS[(run-1)%len(STOLEN_REFRESH_TOKENS)]

        #Logging a synthetic context step to show where the token originated from
        trace["steps"].append({
            "step": "legitimate_session_context",
            "duration_in_ms": 0,
            "request": {"method": "N/A", "url": "(prior session)", "data": {}},
            "response": {
                "status": None,
                "note": "Refresh token was originally issued to a legitimate client session"
                        "and subsequently obtained by an attacker (e.g. via token leakage, XSS,"
                        "or insecure storage)."
            },
        })

        attacker_session = make_session()

        refresh_data = {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": stolen_token,
        }
        refresh_rec = timed_request(
            attacker_session,
            "POST",
            token_endpoint,
            data=refresh_data,
            headers=default_headers,
            allow_redirects=False,
        )
        refresh_resp = refresh_rec["response"]

        trace["steps"].append({
            "step": "stolen_refresh_attempt",
            "duration_in_ms": refresh_rec["duration_in_ms"],
            "request": {
                "method": "POST",
                "url": token_endpoint,
                "data": {
                    "grant_type": "refresh_token",
                    "client_id": CLIENT_ID,
                },
                "headers": default_headers,
                "note": "New session with no original cookies, attacker using stolen refresh token",
            },
            "response": {
                "status": refresh_resp.status_code,
                "headers": dict(refresh_resp.headers),
                "body_snippet": refresh_resp.text[:500],
            },
        })

        if refresh_resp.status_code == 200:
            trace["outcome"] = {
                "result": "refresh_misuse_accepted",
                "status": 200,
                "issue": "stolen_refresh_token_accepted",
                "reason": "AS issued new tokens using a stolen refresh token with correct client id",
            }

        else:
            trace["outcome"] = {
                "result": "stolen_token_rejected",
                "status": refresh_resp.status_code,
                "issue": "stolen_refresh_token_rejected",
                "reason": f"AS rejected stolen refresh token: {refresh_resp.text[:200]}",
            }
        return save_trace(trace, run)

    #Scenario: refresh misuse rejected by AS
    session = make_session()
    auth_endpoint, token_endpoint, auth_params, code_verifier = build_normal_auth_request()

    trace = {
        "scenario": scenario,
        "run": run,
        "chosen_scope": auth_params.get("scope"),
        "user_agent": user_agent,
        "steps": [],
        "outcome": {},
    }

    #Step 1:auth+login form
    auth_rec = timed_request(
        session,
        "GET",
        auth_endpoint,
        params=auth_params,
        headers=default_headers,
        allow_redirects=False,
    )
    auth_resp = auth_rec["response"]

    if auth_resp.status_code not in (200, 302):
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
            },
        })
        trace["outcome"] = {
            "result": "auth_request_failed",
            "status": auth_resp.status_code,
            "issue": "authorization_endpoint_rejected_request",
            "reason": "Authorization endpoint did not return 200/302"
        }
        return save_trace(trace, run)
    
    if auth_resp.status_code == 302:
        login_page_url = auth_resp.headers.get("Location")
        login_page_rec = timed_request(
            session,
            "GET",
            login_page_url,
            headers=default_headers,
            allow_redirects=False,   
        )
        login_page_resp = login_page_rec["response"]
        form_html = login_page_resp.text
        form_status = login_page_resp.status_code
        form_headers = dict(login_page_resp.headers)
        step1_duration = auth_rec["duration_in_ms"] + login_page_rec["duration_in_ms"]
    else:
        form_html = auth_resp.text
        form_status = auth_resp.status_code
        form_headers = dict(auth_resp.headers)
        step1_duration = auth_rec["duration_in_ms"]
    
    try:
        login_action = get_login_action_url(form_html)
    except RuntimeError as e:
        trace["steps"].append({
            "step": "authorization_request",
            "duration_in_ms": step1_duration,
            "request": {
                "method": "GET",
                "url": auth_endpoint,
                "params": auth_params,
                "headers": default_headers,
            },
            "response": {
                "status": form_status,
                "headers": form_headers,
                "body_snippet": form_html[:500],
            },
        })
        trace["outcome"] = {"result": "no_login_form", "details": str(e)}
        return save_trace(trace, run)
    
    trace["steps"].append({
        "step": "authorization_request",
        "duration_in_ms": step1_duration,
        "request": {
            "method": "GET",
            "url": auth_endpoint,
            "params": auth_params,
            "headers": default_headers,
        },
    })

    #Step 2:login submit
    login_headers = {"User-Agent": user_agent}
    login_rec = timed_request(
        session,
        "POST",
        login_action,
        data={"username": USERNAME, "password": PASSWORD},
        headers=login_headers,
        allow_redirects=False,
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
    if not redirect_back.startswith(REDIRECT_URI):
        trace["outcome"] = {
            "result": "login_failed_bad_redirect",
            "status": login_resp.status_code,
            "issue": "login_post_failed",
            "reason": f"Expected 302 to {REDIRECT_URI}, got: {redirect_back}",
        }
        return save_trace(trace, run)
    
    #Step 3:code received
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

    #Step 4:token exchange
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }
    token_rec = timed_request(
        session,
        "POST",
        token_endpoint,
        data=token_data,
        headers=default_headers,
        allow_redirects=False,
    )
    token_resp = token_rec["response"]

    trace["steps"].append({
        "step": "token_exchange",
        "duration_in_ms": token_rec["duration_in_ms"],
        "request": {
            "method": "POST",
            "url": token_endpoint,
            "data": {
                "grant_type": token_data["grant_type"],
                "client_id": token_data["client_id"],
                "redirect_uri": token_data["redirect_uri"],
            },
            "headers": default_headers,
        },
        "response": {
            "status": token_resp.status_code,
            "headers": dict(token_resp.headers),
            "body_snippet": token_resp.text[:500],
        },
    })

    if token_resp.status_code != 200:
        trace["outcome"] = {
            "result": "token_error",
            "status": token_resp.status_code,
            "issue": "token_endpoint_error",
            "reason": "Initial token exchange failed, refresh misuse not attempted",
        }
        return save_trace(trace, run)
    
    #Step 5:Misuse refresh token and store it for stolen variant
    token_json = token_resp.json()
    refresh_token = token_json.get("refresh_token")

    if not refresh_token:
        trace["outcome"] = {
            "result": "no_refresh_token",
            "status": 200,
            "issue": "no_refresh_in_response",
            "reason": "IdP did not issue a refresh token, misuse not attempted",
        }
        return save_trace(trace, run)
    
    #Store refresh token for later stolen token run
    STOLEN_REFRESH_TOKENS.append(refresh_token)
    
    #Flawed refresh using wrong client id
    misuse_variants = [
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID + "-wrong",
            "refresh_token": refresh_token,
        },
        {
            "grant_type": "refresh_token",
            "client_id": CLIENT_ID.upper(), #case variation
            "refresh_token": refresh_token,
        },
        {
            "grant_type": "Refresh_token",
            "client_id": CLIENT_ID,
            "refresh_token": "invalid_token_" + secrets.token_urlsafe(8),
        },
    ]
    refresh_data = random.choice(misuse_variants)

    refresh_rec = timed_request(
        session,
        "POST",
        token_endpoint,
        data=refresh_data,
        headers=default_headers,
        allow_redirects=False,  
    )
    refresh_resp = refresh_rec["response"]

    trace["steps"].append({
        "step": "refresh_misuse_wrong_client",
        "duration_in_ms": refresh_rec["duration_in_ms"],
        "request": {
            "method": "POST",
            "url": token_endpoint,
            "data": {
                "grant_type": "refresh_token",
                "client_id": refresh_data["client_id"],
            },
            "headers": default_headers,
        },
        "response": {
            "status": refresh_resp.status_code,
            "headers": dict(refresh_resp.headers),
            "body_snippet": refresh_resp.text[:500],
        },
    })

    trace["outcome"] = {
        "result": "refresh_misuse_rejected",
        "status": refresh_resp.status_code,
        "issue": "refresh_token_misuse",
        "reason": "Client used refresh token with incorrect client id",
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
    """Run all scenarios 125 times to get 125 flows for each scenario
    Note: The strict open redirect flows must be run separately with 
    strict redirect uri set in the Keycloak admin for the client."""
    
    #Run the normal flow 125 times to create 125 randomized flow traces
    for run in range(1,156):
        print(f"Running normal flow: #{run}")
        run_normal_flow(run=run)
    
    #Open redirect flow that Keycloak rejects
    for run in range(1, 156):
        print(f"Running strict open redirect flow: #{run}")
        run_open_redirect_flow(run=run, scenario = "redirect_flaw_strict")
    
    #Open redirect flow that Keycloak accepts
    for run in range(1, 156):
        print(f"Running misconfigured open redirect flow: #{run}")
        run_open_redirect_flow(run=run, scenario = "redirect_flaw_misconfig")
    
    #PKCE downgrade flows
    for run in range(1, 156):
        print(f"PKCE downgrade flow: #{run}")
        run_pkce_downgrade(run=run)
    
    #No PKCE rejected flows
    for run in range(1, 156):
        print(f"Strict No PKCE flow: #{run}")
        run_no_pkce_flow(run=run, scenario = "no_pkce_rejected")
    
    #No PKCE accepted flows
    for run in range(1, 156):
        print(f"Misconfigured No PKCE flow: #{run}")
        run_no_pkce_flow(run=run, scenario = "no_pkce_accepted")

    #Rejected refresh misuse flows
    for run in range(1, 156):
        print(f"Rejected refresh misuse flow: #{run}")
        run_refresh_misuse_flow(run=run, scenario="refresh_misuse_rejected")
    
    #Refresh misuse token stolen
    for run in range(1, 156):
        print(f"Stolen refresh misuse token flow: #{run}")
        run_refresh_misuse_flow(run=run, scenario="refresh_misuse_stolen")

if __name__=="__main__":
    main()