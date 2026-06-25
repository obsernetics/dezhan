#!/usr/bin/env python3
# Endpoint-agnostic S3 benchmark. Measures PUT/GET/LIST/DELETE throughput and
# latency percentiles at several object sizes, and emits one JSON result object.
# Usage: s3bench.py <label> <endpoint> <access_key> <secret_key> [out.json]
import sys, time, json, statistics, uuid
import boto3
from botocore.config import Config

label, endpoint, ak, sk = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
out = sys.argv[5] if len(sys.argv) > 5 else None

c = boto3.client("s3", endpoint_url=endpoint, aws_access_key_id=ak,
                 aws_secret_access_key=sk, region_name="us-east-1",
                 config=Config(s3={"addressing_style": "path"}, signature_version="s3v4",
                               retries={"max_attempts": 1}, max_pool_connections=32))

bucket = "bench-" + uuid.uuid4().hex[:8]
c.create_bucket(Bucket=bucket)

def pct(xs, p):
    xs = sorted(xs)
    return round(xs[min(len(xs)-1, int(len(xs)*p/100))]*1000, 3)  # ms

# (size_label, bytes, count)
WORKLOADS = [("1KiB", 1024, 200), ("256KiB", 256*1024, 80), ("4MiB", 4*1024*1024, 25)]
res = {"label": label, "endpoint": endpoint, "ts": int(time.time()), "sizes": {}}

for name, size, n in WORKLOADS:
    blob = b"x" * size
    keys = [f"{name}/{i}" for i in range(n)]
    # PUT
    put_lat = []
    t0 = time.time()
    for k in keys:
        s = time.time(); c.put_object(Bucket=bucket, Key=k, Body=blob); put_lat.append(time.time()-s)
    put_dur = time.time()-t0
    # GET
    get_lat = []
    t0 = time.time()
    for k in keys:
        s = time.time(); c.get_object(Bucket=bucket, Key=k)["Body"].read(); get_lat.append(time.time()-s)
    get_dur = time.time()-t0
    # LIST
    s = time.time(); c.list_objects_v2(Bucket=bucket, Prefix=name+"/"); list_ms = round((time.time()-s)*1000, 3)
    # DELETE
    t0 = time.time()
    for k in keys:
        c.delete_object(Bucket=bucket, Key=k)
    del_dur = time.time()-t0
    mb = size*n/1e6
    res["sizes"][name] = {
        "objects": n, "object_bytes": size,
        "put_objs_per_s": round(n/put_dur, 1), "put_MBps": round(mb/put_dur, 2),
        "put_p50_ms": pct(put_lat,50), "put_p95_ms": pct(put_lat,95), "put_p99_ms": pct(put_lat,99),
        "get_objs_per_s": round(n/get_dur, 1), "get_MBps": round(mb/get_dur, 2),
        "get_p50_ms": pct(get_lat,50), "get_p95_ms": pct(get_lat,95), "get_p99_ms": pct(get_lat,99),
        "list_ms": list_ms, "delete_objs_per_s": round(n/del_dur, 1),
    }

try:
    c.delete_bucket(Bucket=bucket)
except Exception:
    pass

text = json.dumps(res, indent=2)
print(text)
if out:
    open(out, "w").write(text)
