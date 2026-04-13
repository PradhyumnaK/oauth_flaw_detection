from flask import Flask
from flask import flash, redirect, render_template, request, url_for, session, abort
from authlib.integrations.flask_client import OAuth
import os

app=Flask(__name__)
app.secret_key=os.urandom(24)

#Keycloak configuration
KEYCLOAK_ISSUER = "http://localhost:8080/admin/master/console/#/master/realms"
CLIENT_ID = 1
REDIRECT_URI = "http://localhost:4000/callback"

oauth = OAuth(app)

keycloak = oauth.register(
    'keycloak',
    client_id = CLIENT_ID,
    server_metadata_url = f'{KEYCLOAK_ISSUER}/.well-known/openid-configuration',
    client_kwargs = {'scope': 'openid profile email'}
)

@app.route("/")
def home():
    if not session.get("logged_in"):
        return render_template("login.html")
    else:
        return "Hello There <a href='/logout'>Logout</a>"

@app.route("/login")
def login():
    redirect_uri = url_for('callback', _external=True)
    return keycloak.authorize_redirect(redirect_uri)

@app.route("/callback")
def callback():
    token = keycloak.authorize_access_token()
    user = keycloak.parse_id_token(token)
    session['user'] = user
    return redirect(url_for('home'))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=4000)