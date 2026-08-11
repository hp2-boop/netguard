"""
storage/mongo_client.py

Wraps the MongoDB connection. Tries to connect to a REAL MongoDB instance
(local, self-hosted, or MongoDB Atlas cloud cluster) using the connection
string in the MONGO_URI environment variable. If that fails or isn't set
(e.g., you're just running the demo without a Mongo server available),
it transparently falls back to `mongomock`, an in-memory drop-in
replacement with the identical pymongo API.

This means:
  - The exact same code (storage/alert_store.py, storage/log_store.py)
    works whether you're pointed at a real MongoDB Atlas cluster or just
    running a local demo.
  - You never have to change application code to switch between
    "real cloud storage" mode and "offline demo" mode -- only the
    MONGO_URI environment variable / config.py setting changes.

To use a REAL MongoDB Atlas cluster (recommended for your project):
  1. Create a free cluster at https://www.mongodb.com/cloud/atlas
  2. Get your connection string, e.g.:
     mongodb+srv://<user>:<password>@cluster0.xxxxx.mongodb.net/
  3. Set it as an environment variable before running:
     export MONGO_URI="mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/"
  4. Run the app normally -- it will detect and use the real cluster.
"""

import os

DEFAULT_DB_NAME = "netguard_iot"


def get_database(db_name: str = DEFAULT_DB_NAME):
    uri = os.environ.get("MONGO_URI")

    if uri:
        try:
            from pymongo import MongoClient
            import certifi
            client = MongoClient(uri, serverSelectionTimeoutMS=5000, tlsCAFile=certifi.where())
            client.server_info()  # forces a real connection attempt
            print(f"[storage] Connected to real MongoDB at configured MONGO_URI")
            return client[db_name], "real"
        except Exception as e:
            print(f"[storage] MONGO_URI set but connection failed ({e}); "
                  f"falling back to in-memory mongomock for this session.")
    else:
        print("[storage] MONGO_URI not set; using in-memory mongomock for this session. "
              "See storage/mongo_client.py docstring for how to connect a real MongoDB Atlas cluster.")

    import mongomock
    client = mongomock.MongoClient()
    return client[db_name], "mock"
