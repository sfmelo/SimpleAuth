import os
import bcrypt
import datetime
import json
from flask import Flask, request, jsonify

DEBUG = os.getenv("DEBUG", False)
PASS_SALT = bcrypt.gensalt()

app = Flask(__name__)



class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), PASS_SALT)
        self.created = datetime.datetime.now()
        self.updated = self.created

    def to_json(self):
        return json.dumps({"username": self.username, "password": self.password.decode("utf-8")})


@app.route('/register', methods=['POST'])
def register_user():
    body = request.get_json()
    
    new_user = User(request.authorization.username, body["email"], request.authorization.password)

    # store user in couchbase #
    return new_user.to_json()

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
    app.run(host="0.0.0.0", port=8080, debug=DEBUG)