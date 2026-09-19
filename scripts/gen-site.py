#!/usr/bin/env python3
"""Generate the published landing page from the repository's own sources.

The landing page (deploy/site/index.html) is a hand-designed template. A few
values in it are facts that live elsewhere in the repo and used to be retyped by
hand, so they drifted from reality:

  * measured throughput numbers  -> bench/results/*.json
  * SPARK proof-check count      -> README.md badge
  * the release version          -> git tag (single source of truth), then
                                    deploy/charts/dezhan/Chart.yaml as fallback

This script reads those sources and injects the live values into the marked
`<span data-metric="KEY">fallback</span>` placeholders in the template, writing
the result to the output path. It only touches the marked spans and never
rewrites the design. If a value cannot be derived, the placeholder's existing
fallback text is left untouched, so the page can never show an invented number.

Pure text/JSON processing: no network, no cluster, Python 3 standard library
only. Run it locally from the repo root with no arguments to preview:

    python3 scripts/gen-site.py --output /tmp/index.html

The deploy workflow (.github/workflows/helm-release.yml) runs it at publish time.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    # scripts/gen-site.py -> repo root is one level up.
    return Path(__file__).resolve().parent.parent


def load_bench(path: Path) -> dict:
    """Return the per-size metrics dict from a bench results JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"gen-site: cannot read bench results {path}: {exc}", file=sys.stderr)
        return {}
    return data.get("sizes", {})


def fmt_num(value: float, decimals: int) -> str:
    """Format a number with a fixed number of decimals, trimming a trailing .0."""
    s = f"{value:.{decimals}f}"
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    return s


def bench_metrics(sizes: dict) -> dict:
    """Derive the display strings the template needs from raw bench numbers.

    Numbers are rounded the way the README prose already rounds them so the page
    and the README agree. A metric is only emitted when its source value exists.
    """
    out: dict[str, str] = {}

    def get(size: str, field: str):
        entry = sizes.get(size)
        if isinstance(entry, dict) and isinstance(entry.get(field), (int, float)):
            return entry[field]
        return None

    put_mbps_4mib = get("4MiB", "put_MBps")
    if put_mbps_4mib is not None:
        out["put_mbps_4mib"] = fmt_num(put_mbps_4mib, 1)

    get_mbps_4mib = get("4MiB", "get_MBps")
    if get_mbps_4mib is not None:
        out["get_mbps_4mib"] = fmt_num(get_mbps_4mib, 0)

    put_ops_1kib = get("1KiB", "put_objs_per_s")
    if put_ops_1kib is not None:
        out["put_ops_1kib"] = fmt_num(put_ops_1kib, 0)

    return out


def proof_metrics(readme: Path) -> dict:
    """Parse the SPARK proof-check counts from the README badge."""
    try:
        text = readme.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"gen-site: cannot read README {readme}: {exc}", file=sys.stderr)
        return {}
    m = re.search(r"SPARK%20proof-(\d+)%20checks%2C%20(\d+)%20unproved", text)
    if not m:
        return {}
    return {"proof_checks": m.group(1), "proof_unproved": m.group(2)}


def resolve_version(explicit: str | None, chart: Path) -> str | None:
    """Version resolution order: explicit arg, then git tag, then Chart.yaml.

    The git tag is the project's single source of truth for the release version
    (see scripts/stamp-version.sh). Returns a string like "v1.3.0", or None if
    nothing could be resolved (the placeholder then keeps its fallback).
    """
    candidate = explicit
    if not candidate:
        try:
            candidate = subprocess.run(
                ["git", "describe", "--tags", "--abbrev=0"],
                cwd=str(chart.parent),
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            candidate = None
    if not candidate:
        try:
            for line in chart.read_text(encoding="utf-8").splitlines():
                m = re.match(r'\s*appVersion:\s*"?([^"\s]+)"?', line)
                if m:
                    candidate = m.group(1)
                    break
        except OSError:
            candidate = None
    if not candidate:
        return None
    candidate = candidate.strip()
    if not candidate:
        return None
    return candidate if candidate.startswith("v") else f"v{candidate}"


def inject_metrics(html: str, metrics: dict) -> str:
    """Replace the inner text of each <span data-metric="KEY">...</span>.

    Only keys present in `metrics` are touched; every other placeholder keeps its
    fallback text verbatim.
    """
    for key, value in metrics.items():
        pattern = re.compile(
            r'(<span data-metric="' + re.escape(key) + r'">)(.*?)(</span>)',
            re.DOTALL,
        )
        html, n = pattern.subn(lambda m: m.group(1) + value + m.group(3), html)
        if n == 0:
            print(f"gen-site: warning: no placeholder for metric '{key}'", file=sys.stderr)
    return html


def apply_cache_bust(html: str, token: str) -> str:
    """Rewrite ?v=... cache-busting query strings on local css/js to `token`."""
    return re.sub(
        r'(assets/(?:css|js)/[^"?]+)\?v=[^"]*',
        lambda m: f"{m.group(1)}?v={token}",
        html,
    )


def main(argv: list[str]) -> int:
    root = repo_root()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--template", type=Path, default=root / "deploy/site/index.html")
    ap.add_argument("--bench", type=Path, default=root / "bench/results/dezhan-vm.json")
    ap.add_argument("--readme", type=Path, default=root / "README.md")
    ap.add_argument("--chart", type=Path, default=root / "deploy/charts/dezhan/Chart.yaml")
    ap.add_argument("--version", default=None, help="release version; overrides git tag / Chart.yaml")
    ap.add_argument("--cache-bust", default=None, help="token for ?v= on local css/js (e.g. commit sha)")
    ap.add_argument("--output", type=Path, default=root / "public/index.html")
    args = ap.parse_args(argv)

    try:
        html = args.template.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"gen-site: cannot read template {args.template}: {exc}", file=sys.stderr)
        return 1

    metrics: dict[str, str] = {}
    metrics.update(bench_metrics(load_bench(args.bench)))
    metrics.update(proof_metrics(args.readme))

    version = resolve_version(args.version, args.chart)
    if version:
        metrics["version"] = version

    html = inject_metrics(html, metrics)

    if args.cache_bust:
        html = apply_cache_bust(html, args.cache_bust)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html, encoding="utf-8")

    injected = ", ".join(f"{k}={v}" for k, v in sorted(metrics.items())) or "(none)"
    print(f"gen-site: wrote {args.output} with live values: {injected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
