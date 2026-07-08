from flask import Flask
from flask import flash, redirect, render_template, request, url_for, session, abort
from authlib.integrations.flask_client import OAuth
from authlib.common.security import generate_token
import os
#New, for the graph
import json
from functools import wraps
from pathlib import Path
from pyvis.network import Network

app=Flask(__name__)
app.secret_key=os.urandom(24)

#Keycloak configuration
KEYCLOAK_ISSUER = "http://localhost:8080/realms/master"
CLIENT_ID = "testing"
REDIRECT_URI = "http://localhost:4000/callback"

TRACES_ROOT = Path("traces")
GRAPHS_DIR = Path("static/graphs")
GRAPHS_DIR.mkdir(parents=True, exist_ok=True)

SCENARIO_DESCRIPTIONS = {
    "normal": 
        "A conformant OAuth 2.0 authorization code flow with PKCE."
        "All steps complete successfully and tokens are issued as expected under RFC 9700.",
    
    "no_pkce_accepted":
        "The client omits PKCE parameters entirely. Keycloak is configured to"
        "treat PKCE as optional, so the flow completes and tokens are issued"
        "despite the absence of a code_challenge, a violation of RFC 9700 clause 2.1.1.",
    
    "no_pkce_rejected":
        "The client omits the PKCE challenge but still sends a code_verifier at "
        "token exchange. The authorization server rejects the request with "
        "invalid_grant, since a verifier with no corresponding challenge cannot "
        "be validated.",

    "pkce_downgrade":
        "The client uses the weaker 'plain' PKCE method instead of the "
        "RFC 9700-mandated S256. The authorization server accepts this, "
        "demonstrating that PKCE method enforcement is not guaranteed by "
        "default IdP configuration.",

    "redirect_flaw_strict":
        "The client sends an authorization request with an unregistered "
        "redirect_uri containing an attacker-controlled suffix. The "
        "authorization server performs exact string matching and rejects "
        "the request at the first step, as required by RFC 9700 clause 4.1.3.",

    "redirect_flaw_misconfig":
        "The same malicious redirect_uri is sent, but the client is registered "
        "with a wildcard redirect URI. The authorization server accepts the "
        "request and issues an authorization code to the attacker-controlled "
        "URI : a real open-redirector vulnerability.",

    "refresh_misuse_rejected":
        "After a normal flow completes, the refresh token is replayed with an "
        "incorrect client_id. The authorization server rejects the request, "
        "confirming that refresh tokens are correctly bound to their issuing "
        "client.",

    "refresh_misuse_stolen":
        "A refresh token obtained from a previous session is replayed from a "
        "new session with the correct client_id, simulating a stolen token "
        "attack. The authorization server cannot distinguish the legitimate "
        "client from the attacker, since the token itself is valid.",
}

SCENARIO_DISPLAY_NAMES = {
    "normal": "Normal PKCE flow",
    "no_pkce_accepted": "No PKCE (accepted)",
    "no_pkce_rejected": "No PKCE (rejected)",
    "pkce_downgrade": "PKCE downgrade (plain)",
    "redirect_flaw_strict": "Redirect flaw (strict)",
    "redirect_flaw_misconfig": "Redirect flaw (misconfigured)",
    "refresh_misuse_rejected": "Refresh misuse (rejected)",
    "refresh_misuse_stolen": "Refresh misuse (stolen token)",
}

oauth = OAuth(app)

keycloak = oauth.register(
    'keycloak',
    client_id = CLIENT_ID,
    server_metadata_url = f'{KEYCLOAK_ISSUER}/.well-known/openid-configuration',
)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def trace_to_graph(trace, output_path):
    """Convert a trace JSON into an interactive graph and save it"""
    net = Network(height="500px", width="100%", directed=True, bgcolor="#000000", font_color="#d3d3d3")
    
    outcome = trace.get("outcome", {})
    is_flaw = outcome.get("result", "success") != "success"
    steps = trace.get("steps", [])

    for i,s in enumerate(steps):
        name = s.get("step", f"step_{i}")
        status = s.get("response", {}).get("status", "")
        colour = "#008000"

        if is_flaw:
            #coloring the step in red if the status is not success
            #or if not any of the known misuse steps
            if status not in (200, 302, None, ""):
                colour = "#ff0000"
            elif name in ("refresh_token_wrong_client", "stolen_refresh_attempt"):
                colour = "#ff0000"
        
        net.add_node(i,
                     label=f"{name}\n[{status}]" if status else name,
                     color=colour,
                     title=f"{name} status {status}")
    
    for i in range(len(steps) - 1):
        src = steps[i]
        method = src.get("request", {}).get("method", "")
        status = src.get("response", {}).get("status", "")
        status_str = str(status) if status is not None else ""
        net.add_edge(i, i+1, label=f"{method} {status_str}".strip(), color="#708090", font={"color": "#D31D1D"})
    
    #outcome node at the end
    result = outcome.get("result", "success")
    net.add_node(len(steps),
                 label=f"OUTCOME\n{result}",
                 color="#008000" if not is_flaw else "#ff0000",
                 shape="ellipse",
                 title=outcome.get("reason", ""))
    
    if steps:
        net.add_edge(len(steps) - 1, len(steps), color="#708090")
    
    net.set_options("""
    {
        "edges": {"font": {"size": 10, "color": "#708090"}},
        "nodes": {"font": {"size": 12}},
        "physics": {"enabled": false}
    }
    """)
    net.save_graph(str(output_path))

@app.route("/")
def home():
    if not session.get("logged_in"):
        return render_template("login.html")
    return render_template("home.html", user=session.get("user"))

@app.route("/login")
def login():
    #redirect_uri = url_for('callback', _external=True)
    nonce=generate_token()
    session['nonce'] = nonce
    return keycloak.authorize_redirect(url_for("callback", _external=True), nonce=nonce)

@app.route("/callback")
def callback():
    token = keycloak.authorize_access_token()
    nonce = session.pop('nonce', None)
    user = keycloak.parse_id_token(token, nonce=nonce)
    session['user'] = user
    session['logged_in'] = True
    return redirect(url_for('home'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/flows")
@login_required
def list_flows():
    scenarios = {}
    if TRACES_ROOT.exists():
        for d in sorted(TRACES_ROOT.iterdir()):
            if d.is_dir():
                #Fix: Remove "traces" being printed along with the scenarios
                #json_files = list(d.glob("*.json"))
                #if not json_files:
                 #   continue #Skip empty dirs
                runs = sorted(int(f.stem.split("_")[-1]) for f in d.glob("*.json"))
                scenarios[d.name] = runs
    return render_template("flows.html", scenarios=scenarios, scenario_display_names=SCENARIO_DISPLAY_NAMES)

@app.route("/flows/<scenario>/<int:run>")
@login_required
def show_flow(scenario, run):
    trace_path = TRACES_ROOT / scenario / f"{scenario}_{run}.json"
    if not trace_path.exists():
        abort(404)
    
    graph_path = GRAPHS_DIR / f"{scenario}_{run}.html"
    if not graph_path.exists():
        trace_to_graph(json.loads(trace_path.read_text(encoding="utf-8")), graph_path)
    
    return render_template("flow_view.html", 
                           scenario=scenario, 
                           run=run, 
                           graph_name=f"{scenario}_{run}.html",
                           scenario_descriptions=SCENARIO_DESCRIPTIONS,
                           scenario_display_names=SCENARIO_DISPLAY_NAMES,)


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)