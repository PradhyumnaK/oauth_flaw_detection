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
        net.add_edge(i, i+1, label=f"{method} {status}", color="#708090", font={"color": "#D31D1D"})
    
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
                runs = sorted(int(f.stem.split("_")[-1]) for f in d.glob("*.json"))
                scenarios[d.name] = runs
    return render_template("flows.html", scenarios=scenarios)

@app.route("/flows/<scenario>/<int:run>")
@login_required
def show_flow(scenario, run):
    trace_path = TRACES_ROOT / scenario / f"{scenario}_{run}.json"
    if not trace_path.exists():
        abort(404)
    
    graph_path = GRAPHS_DIR / f"{scenario}_{run}.html"
    if not graph_path.exists():
        trace_to_graph(json.loads(trace_path.read_text(encoding="utf-8")), graph_path)
    
    return render_template("flow_view.html", scenario=scenario, run=run, graph_name=f"{scenario}_{run}.html")


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)