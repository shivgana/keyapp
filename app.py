from flask import Flask, session, redirect, render_template, url_for, request, Response
import requests
import jwt
from jwt.exceptions import ExpiredSignatureError
import uuid 
import urllib
import base64
import json
import time
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = "THIS IS KEY"

auth_url = 'http://localhost:8080/auth/realms/k-splice/protocol/openid-connect/auth'
token_url = 'http://localhost:8080/auth/realms/k-splice/protocol/openid-connect/token'
logout_url = 'http://localhost:8080/auth/realms/k-splice/protocol/openid-connect/logout'
resource_url = "http://localhost:8080/auth/realms/k-splice/authz/protection/resource_set"
introspect_url = 'http://localhost:8080/auth/realms/k-splice/protocol/openid-connect/token/introspect'
CLIENT_ID = os.getenv("CLIENT_ID","keycloaklib")
CLIENT_SECRET = os.getenv("CLIENT_SECRET","5cf65bfe-4949-4e74-bd0a-7a4f93f20455")
ACCESS_T_FORMAT = 'urn:ietf:params:oauth:token-type:jwt'
ID_TOKEN_FORMAT = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
public_key = os.getenv("PUBLIC_KEY","""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAty5HwJExj1RAMM73X+LDm+MpnRQJACZSwQ95B3ofGVzTDsymLkfkQDoHlugDX1/xwlWjHh9hWW8MUIbk0yfx81YsYbhoLQY4mu+/c6ZrBVReWgHgWlEx8H3gRaT/fBv7vLH+j6jRoQhob13qHREYGGB0VV5D17XFwCJjuuJWnw8sW612WorqOUSjvm5UuxXk9hiEDtwYHA+T0s1PrabGCnWktdGyMOHtS51ntVfM2VdPGNZxoxT/VxGp43ZFxL6/e2U81M38neINmVL2WQE/6llFsuR1US4g7oIq7yinr2E4BI2mqVO/o3d6QHAPbC1j63Qey18CZIrogKAOHZzWXQIDAQAB
-----END PUBLIC KEY-----
""")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth', methods=['GET'])
def auth():
    #print(dir(request))
    #print(request.args.get('state'))
    if request.args.get('state') != session['state']:
        return Response("Invalid state", status=400)
    payload = {
        "code": request.args.get('code'),
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost:5000/auth",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    resp = requests.post(token_url, data=payload)
    session['token'] = resp.json()
    return redirect(session['redirect'])
    
@app.route('/login',methods=['GET'])
def login():
    state = str(uuid.uuid4())
    session['state'] = state
    params = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "response_type": "code",
        "state": state,
        "redirect_uri": "http://localhost:5000/auth",
        "scope": "openid app_auth"
    }
    
    auth = auth_url + '?' + urllib.parse.urlencode(params)
    #print(auth)
    return redirect(auth)

@app.route('/public',methods=['GET','POST'])
def public():
    return "<h2>This page is public</h2>"
    

def refresh():
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": session['token']['refresh_token'],
        "grant_type": "refresh_token"
    }
    try:
        resp = requests.post(token_url,data=data)
    except:
        return None
    return resp.json()

   
@app.route('/secured',methods=['GET','POST']) 
def secured():
    data = {}
    if session.get('token','not set') == 'not set':
        session['redirect'] = str(request.url_rule)
        return redirect(url_for('login'))    
    
    data["token"] = session['token']['access_token']
    access_token = data['token']
    #print(base64.b64decode(access_token),validate=False)
    try:
        token_data = jwt.decode(access_token, public_key, audience='app', algorithms=['RS256']) 
        if token_data['exp'] < int(time.time()):
            return redirect(url_for('login'))
    except (ExpiredSignatureError):
        session['token'] = refresh()
    #############
    
    payload = access_token.split('.')[1]
    #print(type(json.loads(token_data)))
    #print(dict(token_data.replace("'","\"")))
    resp = authorize(payload,request.url_rule, request.method)
    #############
    if resp != "200":
        return render_template('unauthorized.html')
    return render_template('secured.html',resp=data)

@app.route('/logout')    
def logout():
    access_token = session['token']['access_token']
    refresh_token = session['token']['refresh_token']
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token
    }
    header = {"authorization": "Bearer {}".format(access_token)}
    resp = requests.post(logout_url, data=payload, headers=header)
    
    session.pop('token',None)
    return redirect(url_for('index'))


def authorize(token,path,method):
    access_token = session['token']['access_token']
    
    ### get resource id
    resource_id = get_res_id(path)
    
    ### get RPT token
    payload  = {
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "audience": CLIENT_ID
    }
    rpt = requests.post(token_url, data=payload, headers={'authorization': 'Bearer {}'.format(access_token)})
    print(rpt.json()['access_token'])
    payload = {
        "token_type_hint": "requesting_party_token", 
        "token": rpt.json()['access_token']
    }
    data = f"{CLIENT_ID}:{CLIENT_SECRET}"
    rpt = requests.post(introspect_url, data=payload, headers={'authorization': 'Basic {}'.format(base64.b64encode(data.encode("utf-8")).decode("utf-8"))})
    print(rpt.json())
    return permission(resource_id, method, rpt.json()['permissions'])
   
def permission(res_id, method, permissions):
    for permission in permissions:
        print(permission)
        if (permission['rsid'] == res_id) and (method in permission['scopes']):
            print(True)
            return "200"
    return "403"
    
def get_res_id(path):
    access_token = session['token']['access_token']
    resource = requests.get('http://localhost:8080/auth/realms/k-splice/authz/protection/resource_set?uri={}'.format(path), headers={'authorization': 'Bearer {}'.format(access_token)})
    print(resource.json())
    if len(resource.json()) == 0 :
        return "Resource not found"
    resource_id = resource.json()[0]
    return resource_id
    
    

if __name__=='__main__':
    app.run()