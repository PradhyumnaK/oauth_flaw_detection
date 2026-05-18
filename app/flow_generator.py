import base64
import hashlib
import json
import os
import secrets
from urllib.parse import urlencode
import requests

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

    #Generate PKCE and state/none
    code_verifier, code_challenge = pkce_pair()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    #Build authorization URL
    auth_params={
        "response type":"code",
        "client_id":CLIENT_ID,
        "redirect_uri":REDIRECT_URI,
        "scope":"openid",
        "state":state,
        "nonce":nonce,
        "code_challenge":code_challenge,
        "code_challenge_method":"S256",
    }
    auth_url=f"{auth_endpoint}?{urlencode(auth_params)}"

    trace={
        "scenario":"normal",
        "stage":"authorization_url_built",
        "authorization_endpoint":auth_endpoint,
        "auth_params":auth_params,
        "code_verifier":"stored_in_memory", #would be kept by generator
    }
    return auth_endpoint, auth_url, auth_params, code_verifier, trace

def main():
    auth_endpoint, auth_url, auth_params, code_verifier, trace = build_normal_auth_request()

    print("\nAuthorization URL for normal flow:")
    print(auth_url)

    #Save as first trace
    out_file=os.path.join(TRACES_DIR, "normal_auth_request.json")
    with open(out_file,"w",encoding="utf-8") as f:
        json.dump(trace,f,indent=2)
    
    print(f"\nTrace saved to {out_file}\n")


if __name__=="__main__":
    main()