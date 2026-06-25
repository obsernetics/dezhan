#!/usr/bin/env python3
# dezhan via the AWS SDK (boto3): put/get, versioning, and WORM/Object-Lock.
#   pip install boto3 ; python3 boto3_demo.py [endpoint]
import os, sys, datetime, boto3
from botocore.config import Config

endpoint = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DEZHAN_ENDPOINT", "http://localhost:8080")
s3 = boto3.client(
    "s3", endpoint_url=endpoint,
    aws_access_key_id=os.environ.get("DEZHAN_ACCESS_KEY", "dezhanadmin"),
    aws_secret_access_key=os.environ.get("DEZHAN_SECRET", "dezhandemosecretkey0123456789"),
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}, signature_version="s3v4"))

# Basic put/get
s3.create_bucket(Bucket="demo")
s3.put_object(Bucket="demo", Key="hello.txt", Body=b"hello dezhan",
              ContentType="text/plain", Metadata={"team": "platform"})
obj = s3.get_object(Bucket="demo", Key="hello.txt")
print("get:", obj["Body"].read(), obj["ContentType"], obj["Metadata"])

# Versioning: overwrites keep prior versions
s3.put_bucket_versioning(Bucket="demo", VersioningConfiguration={"Status": "Enabled"})
s3.put_object(Bucket="demo", Key="hello.txt", Body=b"v2")
print("versions:", [v["VersionId"] for v in s3.list_object_versions(Bucket="demo").get("Versions", [])])

# WORM: a locked bucket refuses early deletes
s3.create_bucket(Bucket="vault", ObjectLockEnabledForBucket=True)
s3.put_object(Bucket="vault", Key="ledger.bin", Body=b"immutable",
              ObjectLockMode="COMPLIANCE",
              ObjectLockRetainUntilDate=datetime.datetime.now() + datetime.timedelta(days=7))
try:
    s3.delete_object(Bucket="vault", Key="ledger.bin")
    print("delete: UNEXPECTEDLY allowed")
except Exception as e:
    print("delete denied (expected):", e.response["Error"]["Code"])

# Presigned GET URL
print("presigned:", s3.generate_presigned_url("get_object",
      Params={"Bucket": "demo", "Key": "hello.txt"}, ExpiresIn=300)[:80], "...")
