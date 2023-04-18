import os
import bcrypt
import json
import jwt
from datetime import datetime, timezone, timedelta
from flask import Flask, request, Response, jsonify
from db import CouchbaseClient


with open('config.json') as f:
    data = json.load(f) 

cb_data = data["couchbase"]
cb_info = {
    "host": cb_data["host"],
    "bucket": cb_data["bucket"],
    "scope": cb_data["scope"],
    "collection": cb_data["default_collection"],
    "username": cb_data["username"],
    "password": cb_data["password"]
}

PROFILE_COLLECTION = cb_data["profiles_collection"]
ACCESS_COLLECTION = cb_data["access_collection"]

JWT_SECRETS = data["jwt_secrets"]
JWT_EXP_MIN = data["jwt_exp_min"]

DEBUG = os.getenv("DEBUG", False)
PASS_SALT = bcrypt.gensalt()

TIMEZONE = timezone.utc

app = Flask(__name__)

db = CouchbaseClient(*cb_info.values())
db.connect()

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('ascii'), PASS_SALT).decode("ascii")
        self.created = datetime.now(tz=TIMEZONE).isoformat()
        self.updated = self.created

def custom_response(status_code, parameter, message):
    response = jsonify({parameter: message})
    response.status_code = status_code
    return response

@app.route('/register', methods=['POST'])
def register_user():
    body = request.get_json()   
    new_user = User(body["username"], body["email"], body["password"])
    if db.user_exists(new_user.username, new_user.email):
        return custom_response(409, "error", "given username/email already exists")
    
    db.register_user(new_user)
    return Response(status=201)

@app.route('/login', methods=['POST'])
def login_user():
    username = request.authorization.username
    password = request.authorization.password
    user = db.get_user(username=username)

    if user == None:
        return custom_response(401, "error", "invalid credentials")

    # check password
    if not bcrypt.checkpw(password.encode('ascii'), user["password"].encode('ascii')):
        return custom_response(401, "error", "invalid credentials")

    # check if it's not already logged in
    token = db.is_logged_in(username)
    if token != None:
        return custom_response(200, "token", token)

    token_exp = datetime.now(tz=TIMEZONE) + timedelta(minutes=JWT_EXP_MIN)
    token = jwt.encode({
        "username": user["username"],
        "email": user["email"],
        "exp": token_exp},
        key=JWT_SECRETS,
        algorithm="HS256"
    )

    db.store_login_access(username, token, request.remote_addr, token_exp)
    return custom_response(200, "token", token)
    
@app.route('/verify', methods=['GET'])
def verify_user():
    token = request.headers["Authorization"].split(" ")[1]

    # check if token is valid and not expired
    try:
        jwt.decode(token, JWT_SECRETS, leeway=60, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return custom_response(401, "error", "token is expired")
    except jwt.InvalidTokenError:
        return custom_response(401, "error", "token is invalid")
    

    
    return Response(status=200)

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)