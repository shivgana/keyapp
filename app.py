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
CLIENT_SECRET = os.getenv("CLIENT_SECRET","QLLglHkHjI45ilcBwEvjmS9Ekzv3mnbl")
ACCESS_T_FORMAT = 'urn:ietf:params:oauth:token-type:jwt'
ID_TOKEN_FORMAT = "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"
public_key = os.getenv("PUBLIC_KEY","""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAySDDzUjUzTp8cD+LtI9fefmbEPXLKRYwdS9CuyZSfqK4xO+XGBDEwjnju3Su4NtxQC6y/xOxLEsQJ57rcazb4Yb0QY1zr4BZYsPEbvvxp6w6fO1Pni9cr2FFmicYDJcKJ2CI6uJ9ZfLUiu6rXlwLRCblRMEI612rJNJ1Wb9L5Up/S5iVOCZOQUSQKBOgMN46AnSADyO/7gLrmanfHslVRtY/1oT0tAqmaR1a+EOr5FuabA5YdwwSWyi6HD/81cnz5HWc+u3vBcWqeIB25huQpRrbw3AKb6bqq9WIaD1BQKbunS6Q1Ir1ye6fVGZcQugVjwXn+KbQt1Mwz+Qh2uJqnwIDAQAB
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
        print(resp.json())
    except:
        return None
    return resp.json()

   
@app.route('/secured',methods=['GET','POST']) 
def secured():
    data = {}
    if session.get('token','not set') == 'not set':
        session['redirect'] = str(request.url_rule)
        return redirect(url_for('login'))    
    print(session['token']['access_token'])
    data["token"] = session['token']['access_token']
    access_token = data['token']
    
    #print(base64.b64decode(access_token),validate=False)
    #try:
    #   token_data =   jwt.decode(access_token, public_key, audience=CLIENT_ID, algorithms=['RS256']) 
    #    if token_data['exp'] < int(time.time()):
    #        return redirect(url_for('login'))
    #except (ExpiredSignatureError):
    #    print("refresh")
    #    token = refresh()
    #    session.pop('token')
    #    session['token'] = token
    #    access_token = token['access_token']
    #    print()
    #############
    token = access_token.split('.')[1]
    resp = authorize(token, request.path, request.method)
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


def authorize(token, path,method):
    access_token = session['token']['access_token']
    print(access_token)
    
    ### get resource id
    resource_id = get_res_id(path)
    
    perm = resource_id+"#"+method
    ### get RPT token
    payload  = {
        "grant_type": "urn:ietf:params:oauth:grant-type:uma-ticket",
        "audience": CLIENT_ID,
        "client_id": CLIENT_ID,
        "claim_token": token,
        "claim_token_format": ID_TOKEN_FORMAT,
        "permission": perm
        }
    rpt = requests.post(token_url, data=payload, headers={'Authorization': 'Bearer {}'.format(access_token)})
    #print(rpt.json())
    if rpt.status_code != 200:
        return 403
    payload = {
        "token_type_hint": "requesting_party_token", 
        "token": rpt.json()['access_token']
    }
    data = f"{CLIENT_ID}:{CLIENT_SECRET}"
    per = requests.post(introspect_url, data=payload, headers={'Authorization': 'Basic {}'.format(base64.b64encode(data.encode("utf-8")).decode("utf-8"))})
    print(per.json())
    return permission(resource_id, method, per.json()['permissions'])
   
def permission(res_id, method, permissions):
    for permission in permissions:
        print(permission)
        if (permission['rsid'] == res_id) and (method in permission['scopes']):
            print(True)
            return 200
    return 403
    
def get_res_id(path):
    payload = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "roles"
    }
    pat = requests.post(token_url, data=payload, headers={"content-type": "application/x-www-form-urlencoded"})
    print(pat.json())
    pat = pat.json()['access_token']
    resource = requests.get('http://localhost:8080/auth/realms/k-splice/authz/protection/resource_set?uri={}'.format(path), headers={'Authorization': 'Bearer {}'.format(pat)})
    print(resource.json())
    if len(resource.json()) == 0:
        return "Resource not found"
    resource_id = resource.json()[0]
    return resource_id
    
    

if __name__=='__main__':
    app.run()