#!/usr/bin/env python3
# Render one grouped bar chart (log scale) of PUT/GET throughput across all
# benchmarked environments into an SVG. No external dependencies.
import json, math

ENVS = ["dezhan-k8s", "dezhan-longhorn", "dezhan-onprem", "minio-k8s"]
COLORS = {"dezhan-k8s": "#2a7ae2", "dezhan-longhorn": "#27ae60",
          "dezhan-onprem": "#8e44ad", "minio-k8s": "#e67e22"}
data = {e: json.load(open(f"results/{e}.json")) for e in ENVS}

GROUPS = [("PUT 1KiB", "put_objs_per_s", "1KiB"), ("PUT 256KiB", "put_objs_per_s", "256KiB"),
          ("PUT 4MiB", "put_objs_per_s", "4MiB"), ("GET 1KiB", "get_objs_per_s", "1KiB"),
          ("GET 256KiB", "get_objs_per_s", "256KiB"), ("GET 4MiB", "get_objs_per_s", "4MiB")]

W, H = 920, 470
L, R, T, B = 64, 188, 46, 78
pw, ph = W - L - R, H - T - B
YMIN, YMAX = 0.1, 1000.0
lo, hi = math.log10(YMIN), math.log10(YMAX)

def y(v):
    v = max(v, YMIN)
    return T + ph * (1 - (math.log10(v) - lo) / (hi - lo))

s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="system-ui,sans-serif" font-size="12">']
s.append(f'<rect width="{W}" height="{H}" fill="white"/>')
s.append(f'<text x="{L}" y="24" font-size="16" font-weight="bold">dezhan vs MinIO/Longhorn: S3 throughput (objects/s, log scale)</text>')
# gridlines + y labels
for gv in [0.1, 1, 10, 100, 1000]:
    yy = y(gv)
    s.append(f'<line x1="{L}" y1="{yy:.1f}" x2="{L+pw}" y2="{yy:.1f}" stroke="#e0e0e0"/>')
    s.append(f'<text x="{L-8}" y="{yy+4:.1f}" text-anchor="end" fill="#666">{gv:g}</text>')
gw = pw / len(GROUPS)
bw = gw * 0.8 / len(ENVS)
for gi, (label, metric, size) in enumerate(GROUPS):
    gx = L + gi * gw
    for ei, e in enumerate(ENVS):
        v = data[e]["sizes"][size][metric]
        bx = gx + gw * 0.1 + ei * bw
        by = y(v)
        s.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw-2:.1f}" height="{T+ph-by:.1f}" fill="{COLORS[e]}"/>')
        s.append(f'<text x="{bx+bw/2:.1f}" y="{by-3:.1f}" text-anchor="middle" font-size="9" fill="#333">{v:g}</text>')
    s.append(f'<text x="{gx+gw/2:.1f}" y="{T+ph+18:.1f}" text-anchor="middle" font-weight="bold">{label}</text>')
# axis
s.append(f'<line x1="{L}" y1="{T+ph:.1f}" x2="{L+pw}" y2="{T+ph:.1f}" stroke="#333"/>')
# legend
for i, e in enumerate(ENVS):
    ly = T + 10 + i * 22
    s.append(f'<rect x="{L+pw+20}" y="{ly}" width="14" height="14" fill="{COLORS[e]}"/>')
    s.append(f'<text x="{L+pw+40}" y="{ly+12}">{e}</text>')
s.append(f'<text x="{L+pw+20}" y="{T+ph+18:.0f}" font-size="11" fill="#666">3-node k3s + on-prem VM</text>')
s.append('</svg>')
open("dezhan-vs-others.svg", "w").write("\n".join(s))
print("wrote dezhan-vs-others.svg")
