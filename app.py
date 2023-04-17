import os
import bcrypt
import datetime
import json
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
with open('couchbase.json') as f:
    data = json.load(f) 

cb_info = {
    "host": data["host"],
    "bucket": data["bucket"],
    "scope": data["scope"],
    "collection": data["default_collection"],
    "username": data["username"],
    "password": data["password"]
}

PROFILE_COLLECTION = data["profiles_collection"]
ACCESS_COLLECTION = data["access_collection"]

DEBUG = os.getenv("DEBUG", False)
PASS_SALT = bcrypt.gensalt()

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

    def get(self, coll, key):
        if self._collection.name != coll:
            self._change_col(self, coll)
        return self._collection.get(key)

    def insert(self, coll, key, doc):
        if self._collection.name != coll:
            self._change_col(self, coll)
        return self._collection.insert(key, doc)

    def upsert(self, coll, key, doc):
        if self._collection.name != coll:
            self._change_col(self, coll)
        return self._collection.upsert(key, doc)

    def remove(self, coll, key):
        if self._collection.name != coll:
            self._change_col(self, coll)
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
            print(row)

cb = CouchbaseClient(*cb_info.values())
cb.connect()

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('ascii'), PASS_SALT).decode("ascii")
        self.created = datetime.datetime.now().isoformat()
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
    
    cb.upsert(PROFILE_COLLECTION, "userprofile:" + new_user.username, new_user.__dict__)
    return Response(status=201)

@app.route('/login', methods=['POST'])
def login_user():
    username = request.authorization.username
    password = request.authorization.password
    cb.get_user(username=username)
    # get matching user from couchbase #
    
    # create and store in couchbase access document #

    # return token #

    return Response(status=200)
    
@app.route('/verify', methods=['GET'])
def verify_user():
    token = request.headers["Authorization"].split(" ")[1]

    # check if token is valid and not expired #
    pass

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)