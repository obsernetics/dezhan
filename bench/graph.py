#!/usr/bin/env python3
# Render dezhan's measured PUT/GET throughput (objects/s, log scale) into an SVG.
# No external dependencies. Single-node measurement on one VM; see
# results/COMPARISON.md for the numbers and the dezhan-vs-Veeam comparison.
import json, math

data = json.load(open("results/dezhan-vm.json"))
BAR = "#2a7ae2"

GROUPS = [("PUT 1KiB", "put_objs_per_s", "1KiB"), ("PUT 256KiB", "put_objs_per_s", "256KiB"),
          ("PUT 4MiB", "put_objs_per_s", "4MiB"), ("GET 1KiB", "get_objs_per_s", "1KiB"),
          ("GET 256KiB", "get_objs_per_s", "256KiB"), ("GET 4MiB", "get_objs_per_s", "4MiB")]

W, H = 920, 470
L, R, T, B = 64, 40, 46, 78
pw, ph = W - L - R, H - T - B
YMIN, YMAX = 0.1, 1000.0
lo, hi = math.log10(YMIN), math.log10(YMAX)

def y(v):
    v = max(v, YMIN)
    return T + ph * (1 - (math.log10(v) - lo) / (hi - lo))

s = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="system-ui,sans-serif" font-size="12">']
s.append(f'<rect width="{W}" height="{H}" fill="white"/>')
s.append(f'<text x="{L}" y="24" font-size="16" font-weight="bold">dezhan measured S3 throughput (objects/s, log scale)</text>')
for gv in [0.1, 1, 10, 100, 1000]:
    yy = y(gv)
    s.append(f'<line x1="{L}" y1="{yy:.1f}" x2="{L+pw}" y2="{yy:.1f}" stroke="#e0e0e0"/>')
    s.append(f'<text x="{L-8}" y="{yy+4:.1f}" text-anchor="end" fill="#666">{gv:g}</text>')
gw = pw / len(GROUPS)
bw = gw * 0.5
for gi, (label, metric, size) in enumerate(GROUPS):
    gx = L + gi * gw
    v = data["sizes"][size][metric]
    bx = gx + (gw - bw) / 2
    by = y(v)
    s.append(f'<rect x="{bx:.1f}" y="{by:.1f}" width="{bw:.1f}" height="{T+ph-by:.1f}" fill="{BAR}"/>')
    s.append(f'<text x="{bx+bw/2:.1f}" y="{by-4:.1f}" text-anchor="middle" font-size="11" fill="#333">{v:g}</text>')
    s.append(f'<text x="{gx+gw/2:.1f}" y="{T+ph+18:.1f}" text-anchor="middle" font-weight="bold">{label}</text>')
s.append(f'<line x1="{L}" y1="{T+ph:.1f}" x2="{L+pw}" y2="{T+ph:.1f}" stroke="#333"/>')
s.append(f'<text x="{L+pw:.0f}" y="{T+ph+40:.0f}" text-anchor="end" font-size="11" fill="#666">single VM, 4 vCPU, per-write fsync + ChaCha20 + Reed-Solomon</text>')
s.append('</svg>')
open("dezhan-vs-others.svg", "w").write("\n".join(s))
print("wrote dezhan-vs-others.svg")
