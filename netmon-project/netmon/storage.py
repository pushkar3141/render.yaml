"""File storage: Supabase Storage in the cloud, a local folder otherwise.

Set SUPABASE_URL, SUPABASE_SERVICE_KEY and (optionally) SUPABASE_BUCKET to use
Supabase. Without them, files go to ./storage and are served by Flask.
"""
from __future__ import annotations

import os
import urllib.parse
import urllib.request
import json


class LocalStorage:
    kind = "local"

    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = os.path.join(self.root, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return key

    def get(self, key: str) -> bytes:
        with open(os.path.join(self.root, key), "rb") as f:
            return f.read()

    def url(self, key: str) -> str:
        return "/files/" + urllib.parse.quote(key)


class SupabaseStorage:
    kind = "supabase"

    def __init__(self, url: str, key: str, bucket: str):
        self.base = url.rstrip("/") + "/storage/v1"
        self.key = key
        self.bucket = bucket

    def _req(self, method, path, data=None, content_type=None):
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.key}")
        req.add_header("apikey", self.key)
        if content_type:
            req.add_header("Content-Type", content_type)
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        self._req("POST", f"/object/{self.bucket}/{urllib.parse.quote(key)}", data, content_type)
        return key

    def get(self, key: str) -> bytes:
        return self._req("GET", f"/object/{self.bucket}/{urllib.parse.quote(key)}")

    def url(self, key: str, expires: int = 3600) -> str:
        body = json.dumps({"expiresIn": expires}).encode()
        out = json.loads(self._req("POST", f"/object/sign/{self.bucket}/{urllib.parse.quote(key)}",
                                   body, "application/json"))
        return self.base + out["signedURL"]


def make_storage(base_dir: str):
    url, key = os.environ.get("SUPABASE_URL"), os.environ.get("SUPABASE_SERVICE_KEY")
    if url and key:
        return SupabaseStorage(url, key, os.environ.get("SUPABASE_BUCKET", "reports"))
    return LocalStorage(os.path.join(base_dir, "storage"))
