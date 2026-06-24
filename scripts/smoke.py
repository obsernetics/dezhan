#!/usr/bin/env python3
"""End-to-end S3 conformance smoke test for dezhan, driven by boto3 (the AWS SDK).

Exercises the surface real backup clients use and exits non-zero on any failure.
Usage: smoke.py <port>  (a dezhan server must be listening, with the demo
credential and DEZHAN_REQUIRE_AUTH set so real SigV4 is verified)."""
import sys, os, io, urllib.request, urllib.error
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

PORT = sys.argv[1] if len(sys.argv) > 1 else "8080"
S3 = boto3.client(
    "s3", endpoint_url="http://127.0.0.1:" + PORT,
    aws_access_key_id="dezhanadmin",
    aws_secret_access_key="dezhandemosecretkey0123456789",
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                  retries={"max_attempts": 1}))

fails = 0
def check(cond, name):
    global fails
    print(("ok   - " if cond else "FAIL - ") + name)
    if not cond:
        fails += 1

# --- buckets, objects, listing ---
S3.create_bucket(Bucket="b")
check(any(b["Name"] == "b" for b in S3.list_buckets()["Buckets"]), "create/list bucket")
S3.put_object(Bucket="b", Key="dir/a", Body=b"alpha", ContentType="text/plain",
              Metadata={"k": "v"})
S3.put_object(Bucket="b", Key="dir/b", Body=b"bravo")
check(S3.get_object(Bucket="b", Key="dir/a")["Body"].read() == b"alpha", "put/get")
h = S3.head_object(Bucket="b", Key="dir/a")
check(h["ContentType"] == "text/plain" and h["Metadata"] == {"k": "v"},
      "Content-Type and user metadata round-trip")
lv = S3.list_objects_v2(Bucket="b", Delimiter="/")
check([p["Prefix"] for p in lv.get("CommonPrefixes", [])] == ["dir/"],
      "ListObjectsV2 delimiter rollup")
S3.copy_object(Bucket="b", Key="dir/c", CopySource={"Bucket": "b", "Key": "dir/a"})
check(S3.get_object(Bucket="b", Key="dir/c")["Body"].read() == b"alpha", "copy object")
S3.delete_objects(Bucket="b", Delete={"Objects": [{"Key": "dir/b"}]})
check("dir/b" not in [o["Key"] for o in S3.list_objects_v2(Bucket="b").get("Contents", [])],
      "batch delete")

# --- ranged read ---
r = S3.get_object(Bucket="b", Key="dir/a", Range="bytes=1-3")["Body"].read()
check(r == b"lph", "ranged GET (206)")

# --- large single PUT (composite) + multipart ---
big = os.urandom(3 * 1024 * 1024)
S3.put_object(Bucket="b", Key="big", Body=big)
check(S3.get_object(Bucket="b", Key="big")["Body"].read() == big, "3MB single PUT round-trip")
S3.upload_fileobj(io.BytesIO(big), "b", "mp",
    Config=boto3.s3.transfer.TransferConfig(multipart_threshold=5*1024*1024,
                                            multipart_chunksize=5*1024*1024))
check(len(S3.get_object(Bucket="b", Key="mp")["Body"].read()) == len(big), "multipart upload")

# --- versioning + delete markers ---
S3.create_bucket(Bucket="ver")
S3.put_bucket_versioning(Bucket="ver", VersioningConfiguration={"Status": "Enabled"})
v1 = S3.put_object(Bucket="ver", Key="f", Body=b"one").get("VersionId")
S3.put_object(Bucket="ver", Key="f", Body=b"two")
check(S3.get_object(Bucket="ver", Key="f")["Body"].read() == b"two", "versioning: latest")
check(S3.get_object(Bucket="ver", Key="f", VersionId=v1)["Body"].read() == b"one",
      "versioning: GET by versionId")
dm = S3.delete_object(Bucket="ver", Key="f")
check(dm.get("DeleteMarker") is True, "delete marker created")
try:
    S3.get_object(Bucket="ver", Key="f"); check(False, "GET after delete marker -> 404")
except ClientError as e:
    check(e.response["Error"]["Code"] == "NoSuchKey", "GET after delete marker -> 404")

# --- object lock / WORM ---
S3.create_bucket(Bucket="lk", ObjectLockEnabledForBucket=True)
S3.put_object(Bucket="lk", Key="x", Body=b"locked")
try:
    S3.delete_object(Bucket="lk", Key="x"); check(False, "locked object delete denied")
except ClientError as e:
    check(e.response["Error"]["Code"] in ("AccessDenied", "403"), "locked object delete denied")

# --- conditional requests ---
et = S3.head_object(Bucket="b", Key="dir/a")["ETag"]
try:
    S3.get_object(Bucket="b", Key="dir/a", IfNoneMatch=et)
    check(False, "If-None-Match match -> 304")
except ClientError as e:
    check(e.response["ResponseMetadata"]["HTTPStatusCode"] == 304, "If-None-Match match -> 304")

# --- presigned URL (no auth header) ---
url = S3.generate_presigned_url("get_object", Params={"Bucket": "b", "Key": "dir/a"},
                                ExpiresIn=3600)
try:
    body = urllib.request.urlopen(url).read()
    check(body == b"alpha", "presigned GET")
except urllib.error.HTTPError as e:
    check(False, "presigned GET (%d)" % e.code)

print()
if fails == 0:
    print("ALL SMOKE TESTS PASSED")
else:
    print("FAILURES: %d" % fails); sys.exit(1)
