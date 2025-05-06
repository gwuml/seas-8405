from flask import Flask, redirect, url_for, request, session
from saml2 import BINDING_HTTP_POST
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# SAML configuration
saml_settings = {
    "sp": {
        "entityId": "http://localhost:5000/saml/metadata",
        "assertionConsumerService": {
            "url": "http://localhost:5000/saml/sso",
            "binding": BINDING_HTTP_POST,
        },
        "singleLogoutService": {
            "url": "http://localhost:5000/saml/slo",
            "binding": BINDING_HTTP_POST,
        },
    },
    "idp": {
        "entityId": "http://lab-keycloak:8080/realms/LabRealm",
        "singleSignOnService": {
            "url": "http://lab-keycloak:8080/realms/LabRealm/protocol/saml",
            "binding": BINDING_HTTP_POST,
        },
        "singleLogoutService": {
            "url": "http://lab-keycloak:8080/realms/LabRealm/protocol/saml",
            "binding": BINDING_HTTP_POST,
        },
    },
    "security": {
        "authnRequestsSigned": False,
        "logoutRequestSigned": False,
        "logoutResponseSigned": False,
        "signMetadata": False,
    },
    "organization": {
        "name": "Lab SP",
        "displayname": "Lab Service Provider",
        "url": "http://localhost:5000",
    },
}

saml_client = Saml2Client(config=Saml2Config(saml_settings))

@app.route('/')
def index():
    if 'user' in session:
        return f"Welcome, {session['user']}!"
    return '<a href="/saml/login">Login with SAML</a>'

@app.route('/saml/login')
def login():
    req = saml_client.prepare_for_authenticate()
    redirect_url = next((k for k, v in req['headers']), None)
    return redirect(redirect_url)

@app.route('/saml/sso', methods=['POST'])
def sso():
    saml_response = request.form.get('SAMLResponse')
    authn_response = saml_client.parse_authn_request_response(saml_response, BINDING_HTTP_POST)
    if authn_response:
        user_info = authn_response.get_identity()
        session['user'] = user_info.get('uid', ['Unknown'])[0]
        return redirect(url_for('index'))
    return "Authentication failed", 401

@app.route('/saml/metadata')
def metadata():
    metadata = saml_client.create_service_provider_metadata()
    return metadata, 200, {'Content-Type': 'text/xml'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

