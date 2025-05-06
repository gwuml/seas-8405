
from flask import Flask, request, redirect, make_response
from onelogin.saml2.auth import OneLogin_Saml2_Auth
import os

app = Flask(__name__)

@app.route('/')
def index():
    return '<a href="/sso/login">Login with SAML</a>'

@app.route('/sso/login')
def sso_login():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))
    return redirect(auth.login())

@app.route('/sso/acs', methods=['POST'])
def sso_acs():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))
    auth.process_response()
    if auth.is_authenticated():
        return f"User {auth.get_nameid()} successfully logged in via SAML"
    return "Authentication failed", 403

@app.route('/sso/metadata')
def sso_metadata():
    req = prepare_flask_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=os.path.join(os.getcwd(), 'saml'))
    metadata = auth.get_settings().get_sp_metadata()
    return make_response(metadata, 200, {'Content-Type': 'text/xml'})

def prepare_flask_request(req):
    url_data = req.url.split('?')
    return {
        'https': 'on' if req.scheme == 'https' else 'off',
        'http_host': req.host,
        'script_name': req.path,
        'server_port': req.environ.get('SERVER_PORT'),
        'get_data': req.args.copy(),
        'post_data': req.form.copy()
    }

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
