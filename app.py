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
    DocumentExistsException,
    DocumentNotFoundException,
)

DEBUG = os.getenv("DEBUG", False)
PASS_SALT = bcrypt.gensalt()

app = Flask(__name__)

class CouchbaseClient:
    def __init__(self, host, bucket, scope, collection, username, password):
        self.host = host
        self.bucket_name = bucket
        self.collection_name = collection
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
            self.collection_name
        )
    
    def get(self, key):
        return self._collection.get(key)

    def insert(self, key, doc):
        return self._collection.insert(key, doc)

    def upsert(self, key, doc):
        return self._collection.upsert(key, doc)

    def remove(self, key):
        return self._collection.remove(key)

    def query(self, strQuery, *options, **kwargs):
        # options are used for positional parameters
        # kwargs are used for named parameters

        # bucket.query() is different from cluster.query()
        return self._cluster.query(strQuery, *options, **kwargs)

with open('couchbase.json') as f:
    data = json.load(f) 

cb_info = {
    "host": data["host"],
    "bucket": data["bucket"],
    "scope": data["scope"],
    "collection": data["collection"],
    "username": data["username"],
    "password": data["password"]
}
cb = CouchbaseClient(*cb_info.values())
cb.connect()

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('ascii'), PASS_SALT).decode("ascii")
        self.created = datetime.datetime.now().isoformat()
        self.updated = self.created

@app.route('/register', methods=['POST'])
def register_user():
    body = request.get_json()    
    new_user = User(body["username"], body["email"], body["password"])
    cb.upsert(new_user.username, new_user.__dict__)
    return Response(status=201)

@app.route('/login', methods=['POST'])
def login_user():
    username = request.authorization.username
    password = request.authorization.password

    # get matching user from couchbase #
    
    # create and store in couchbase access document #

    # return token #

    pass
    
@app.route('/verify', methods=['GET'])
def verify_user():
    token = request.headers["Authorization"].split(" ")[1]

    # check if token is valid and not expired #
    pass

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)