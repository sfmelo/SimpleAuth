import os
import bcrypt
import json
import jwt
import uuid
from datetime import datetime, timezone, timedelta

from flask import Flask, request, Response, jsonify

from couchbase.auth import PasswordAuthenticator
from couchbase.cluster import Cluster
from couchbase.options import ClusterOptions
from couchbase.exceptions import (
    CouchbaseException,
    BucketNotFoundException,
    DocumentExistsException,
    DocumentNotFoundException,
)
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

class CouchbaseClient:
    def __init__(self, host, bucket, scope, collection, username, password):
        self.host = host
        self.bucket_name = bucket
        self.default_collection = collection
        self.scope_name = scope
        self.username = username
        self.password = password

    def connect(self, **kwargs):
        conn_str = "couchbase://" + self.host
    
        try:
            cluster_opts = ClusterOptions(
                authenticator=PasswordAuthenticator(self.username, self.password)
            )

            self._cluster = Cluster(conn_str, cluster_opts, **kwargs)
        except CouchbaseException as error:
            print(f"Could not connect to cluster. Error: {error}")
            raise
        
        self._bucket = self._cluster.bucket(self.bucket_name)
       
        self._collection = self._bucket.scope(self.scope_name).collection(
            self.default_collection
        )

        try:
            # create index if it doesn't exist
            createIndexProfile = f"CREATE PRIMARY INDEX profile_index ON {self.bucket_name}.{self.scope_name}.{PROFILE_COLLECTION}"
            createIndexAccess = f"CREATE PRIMARY INDEX profile_index ON {self.bucket_name}.{self.scope_name}.{ACCESS_COLLECTION}"
            createIndex = f"CREATE PRIMARY INDEX ON {self.bucket_name}"

            self._cluster.query(createIndexProfile).execute()
            self._cluster.query(createIndexAccess).execute()
            self._cluster.query(createIndex).execute()
        except CouchbaseException as e:
            print("Index already exists")
        except Exception as e:
            print(f"Error: {type(e)}{e}")
    
    def _change_col(self, new_coll):
        self._collection = self._bucket.scope(self.scope_name).collection(
            new_coll
        )

    def _get(self, coll, key):
        if self._collection.name != coll:
            self._change_col(coll)
        return self._collection.get(key)

    def _insert(self, coll, key, doc):
        if self._collection.name != coll:
            self._change_col(coll)
        return self._collection.insert(key, doc)

    def _upsert(self, coll, key, doc):
        if self._collection.name != coll:
            self._change_col(coll)
        return self._collection.upsert(key, doc)

    def _remove(self, coll, key):
        if self._collection.name != coll:
            self._change_col(coll)
        return self._collection.remove(key)
    
    def user_exists(self, username, email):
        q = f"SELECT p.* FROM {self.bucket_name}.{self.scope_name}.{PROFILE_COLLECTION} AS p WHERE username = '{username}' OR email = '{email}'"
        result = self._cluster.query(q)
        
        for _ in result.rows():
            return True
        return False
    
    def get_user(self, username):
        q = f"SELECT p.* FROM {self.bucket_name}.{self.scope_name}.{PROFILE_COLLECTION} AS p USE KEYS 'userprofile:{username}'"
        result = self._cluster.query(q)
        for row in result.rows():
            user = row
        return user

    def register_user(self, user):
        self._upsert(PROFILE_COLLECTION, "userprofile:"+ user.username, user.__dict__)
    
    def store_login_access(self, username, token, ip, exp):
        doc = {
            "token": token,
            "user_id": username,
            "IP": ip,
            "expiry": exp.isoformat(),
            "created": datetime.now(tz=TIMEZONE).isoformat(),
        }

        self._upsert(ACCESS_COLLECTION, str(uuid.uuid4()), doc)
        pass

    def is_logged_in(self, username):
        q = f"SELECT token FROM {self.bucket_name}.{self.scope_name}.{ACCESS_COLLECTION}  WHERE user_id = '{username}' AND STR_TO_MILLIS(expiry) > CLOCK_MILLIS()"
        result = self._cluster.query(q)
        for row in result.rows():
            return row["token"]
        return None
        

cb = CouchbaseClient(*cb_info.values())
cb.connect()

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
    if cb.user_exists(new_user.username, new_user.email):
        return custom_response(409, "error", "given username/email already exists")
    
    cb.register_user(new_user)
    return Response(status=201)

@app.route('/login', methods=['POST'])
def login_user():
    username = request.authorization.username
    password = request.authorization.password
    user = cb.get_user(username=username)

    # check password
    if not bcrypt.checkpw(password.encode('ascii'), user["password"].encode('ascii')):
        return custom_response(401, "error", "invalid credentials")

    # check if it's not already logged in
    token = cb.is_logged_in(username)
    if token != None:
        return custom_response(200, "token", token)

    token_exp = datetime.now(tz=TIMEZONE) + timedelta(minutes=JWT_EXP_MIN)
    token = jwt.encode({
        "username": user["username"],
        "email": user["email"],
        "exp": token_exp},
        JWT_SECRETS
    )

    cb.store_login_access(username, token, request.remote_addr, token_exp)
    return custom_response(200, "token", token)
    
@app.route('/verify', methods=['GET'])
def verify_user():
    token = request.headers["Authorization"].split(" ")[1]

    # check if token is valid and not expired #
    try:
        decoded = jwt.decode(token, JWT_SECRETS, leeway=60)
    except jwt.ExpiredSignatureError:
        return custom_response(401, "error", "token is expired")
    except jwt.InvalidTokenError:
        return custom_response(401, "error", "token is invalid")
    
    return Response(status=200)

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)