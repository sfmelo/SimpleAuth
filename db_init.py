import json
import time
from datetime import timedelta

from couchbase.auth import PasswordAuthenticator
from couchbase.cluster import Cluster
from couchbase.exceptions import CouchbaseException
from couchbase.management.buckets import BucketSettings
from couchbase.management.collections import CollectionSpec
from couchbase.options import ClusterOptions

with open('couchbase.json') as f:
    data = json.load(f)

username = data["username"]
password = data["password"]
host = data["host"]
bucket = data["bucket"]
scope = data["scope"]
profiles_collection = data["profiles_collection"]
access_collection = data["access_collection"]


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