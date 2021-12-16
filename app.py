from flask import Flask, render_template, redirect, url_for, session, request, Response
from keycloak import Client
import time
import requests

app = Flask(__name__)
app.config['SECRET_KEY'] = 'this is sample application'

kc = Client()

@app.route('/login',methods=['GET'])
def login():
    kc.callback_uri = 'http://localhost:5000/login/callback'
    url, state = kc.login()
    session['state'] = state
    return redirect(url)
    
@app.route('/login/callback', methods=['GET'])
def login_callback():
    state = request.args.get('state','unknown')
    _state = session['state']
    
    if state != _state:
        return Response('Invalid State', status=403)
        
    code = request.args.get('code')
    print(code)
    token = kc.callback(code)
    print(token)
    access_token = token['access_token']
    session['token'] = token
    userinfo = kc.fetch_userinfo(access_token)
    session['user'] = userinfo
    
    return redirect(url_for('index'))
    

@app.route('/')
def index():
    return render_template('index.html')
    
    
@app.route('/public')
def public():
    return "<h2>This is public</h2>"
    
@app.route('/secured')
def secured():
    data = {}
    if session.get('token', 'none') == 'none':
        return redirect(url_for('login'))
    data['token'] = session['token']['access_token']
    #access_token = kc.decode(data['token'])
    #if access_token['exp'] > time.time(): 
    #    data['token'] = refresh()
    
    #check authorization
    authz = authorize(request.path, request.method)
    if authz.status_code != 200:
        return render_template('unauthorized.html')
    return render_template('secured.html', resp=data)
    
@app.route('/logout')
def logout():
    token = session['token']
    kc.logout(token['access_token'],token['refresh_token'])
    session.pop('token')
    return redirect(url_for('index'))
    
def authorize(path, method):
    access_token = session['token']['access_token']
    #resources = kc.find_resources()
    res_id = get_res_id(path)
    rpt = kc.rpt(access_token)
    itr = kc.introspect(rpt['access_token'])
    print(itr['permissions'])
    resp = permission(res_id, method, itr['permissions'])
    if resp.status_code == 200:
        return resp
    print(rpt)
    print(itr)
    return resp

def get_res_id(path):
    access_token = session['token']['access_token']
    resource = requests.get('http://localhost:8080/auth/realms/k-splice/authz/protection/resource_set?uri={}'.format(path), headers={'authorization': 'Bearer {}'.format(access_token)})
    print(resource.json())
    if len(resource.json()) == 0 :
        return "Resource not found"
    resource_id = resource.json()[0]
    return resource_id
    
def refresh():
    return kc.refresh_tokens()

def permission(res_id, method, permissions):
    for permission in permissions:
        print(permission)
        if permission['rsid'] == res_id and method in permission['scopes']:
            return Response("Authorized", 200)
    return Response("Unauthorized", 403)
            

if __name__ == '__main__':
    app.run()