import json
import uuid
from datetime import timedelta, timezone, datetime

from couchbase.auth import PasswordAuthenticator
from couchbase.cluster import Cluster
from couchbase.exceptions import CouchbaseException
from couchbase.management.buckets import BucketSettings
from couchbase.management.collections import CollectionSpec
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

username = cb_data["username"]
password = cb_data["password"]
host = cb_data["host"]
bucket = cb_data["bucket"]
scope = cb_data["scope"]
profiles_collection = cb_data["profiles_collection"]
access_collection = cb_data["access_collection"]

PROFILE_COLLECTION = cb_data["profiles_collection"]
ACCESS_COLLECTION = cb_data["access_collection"]
TIMEZONE = timezone.utc

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
            print(error)
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

def create_bucket(cluster):
    try:
        # create bucket if it doesn't exist
        bucketSettings = BucketSettings(name=bucket, ram_quota_mb=256)
        cluster.buckets().create_bucket(bucketSettings)
    except CouchbaseException as e:
        print("Bucket already exists")
    except Exception as e:
        print(f"Error: {e}")

def create_scope(cluster):
    try:
        bkt = cluster.bucket(bucket)
        bkt.collections().create_scope(scope)
    except CouchbaseException as e:
        print("Scope already exists: " + e)
    except Exception as e:
        print(f"Error: {e}")

def create_collection(cluster, collection):
    try:
        colSpec = CollectionSpec(collection, scope_name=scope)
        bkt = cluster.bucket(bucket)
        bkt.collections().create_collection(colSpec)
    except CouchbaseException as e:
        print("Collection already exists: " + e)
    except Exception as e:
        print(f"Error: {e}")


def initialize_db():
    connection_str = "couchbase://" + host
    print("Initializing DB")
    cluster = Cluster(
        connection_str,
        ClusterOptions(PasswordAuthenticator(username, password))
    )

    # Create Bucket
    create_bucket(cluster)

    # Create Scope & Collection
    create_scope(cluster)
    create_collection(cluster, profiles_collection)
    create_collection(cluster, access_collection)

    print("Initializing DB complete")



if __name__ == "__main__":
    initialize_db()