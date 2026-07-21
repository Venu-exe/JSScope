#!/usr/bin/env python3
"""
JSScope - JavaScript endpoint, GraphQL & secret extractor for bug bounty recon.

Usage examples:
  python3 jsscope.py -u https://target.com/main.js
  python3 jsscope.py -u https://target.com --crawl
  python3 jsscope.py -l urls.txt -o results.json
  python3 jsscope.py -f ./downloaded_bundle.js

DISCLAIMER: Use only against targets you are authorized to test
(bug bounty programs you're enrolled in, or your own assets).
"""

import argparse
import concurrent.futures
import json
import re
import sys
from urllib.parse import urljoin, urlparse

import requests

requests.packages.urllib3.disable_warnings()

TIMEOUT = 12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (jsscope recon tool)"
}


# --------------------------------------------------------------------------
# Banner (24-bit true-color gradient)
# --------------------------------------------------------------------------
def gradient_text(text, start_rgb, end_rgb):
    length = max(len(text), 1)
    out = []
    for i, ch in enumerate(text):
        t = i / length
        r = int(start_rgb[0] + (end_rgb[0] - start_rgb[0]) * t)
        g = int(start_rgb[1] + (end_rgb[1] - start_rgb[1]) * t)
        b = int(start_rgb[2] + (end_rgb[2] - start_rgb[2]) * t)
        out.append(f"\033[38;2;{r};{g};{b}m{ch}")
    return "".join(out) + "\033[0m"


def print_banner():
    try:
        import pyfiglet
        art_lines = pyfiglet.figlet_format("JSSCOPE", font="ansi_shadow").split("\n")
    except ImportError:
        art_lines = ["JSSCOPE"]
    except Exception:
        # font missing / pyfiglet version mismatch / any figlet render error
        art_lines = ["JSSCOPE"]

    # Gradient sweeps from hot pink -> violet -> electric blue, top to bottom
    start_color = (255, 60, 160)   # hot pink
    end_color = (60, 130, 255)     # electric blue
    width = max((len(l) for l in art_lines), default=10) + 4
    border_color = (140, 80, 255)  # violet border, static

    def border(ch):
        r, g, b = border_color
        return f"\033[38;2;{r};{g};{b}m{ch}\033[0m"

    print(border("╔" + "═" * width + "╗"))
    print(border("║") + " " * width + border("║"))
    for i, line in enumerate(art_lines):
        if not line.strip():
            continue
        t = i / max(len(art_lines) - 1, 1)
        mix = tuple(int(start_color[c] + (end_color[c] - start_color[c]) * t) for c in range(3))
        colored = gradient_text(line, start_color, mix)
        pad = width - len(line) - 2
        print(border("║") + " " + colored + " " * max(pad, 0) + border("║"))
    print(border("║") + " " * width + border("║"))
    tagline = "JavaScript Endpoint & Secret Extractor for Bug Bounty"
    print(border("║") + gradient_text(tagline.center(width), (255, 210, 90), (255, 100, 180)) + border("║"))
    print(border("║") + " " * width + border("║"))
    credit = "Created by venu-exe"
    print(border("║") + gradient_text(credit.center(width), (150, 150, 150), (255, 255, 255)) + border("║"))
    print(border("║") + " " * width + border("║"))
    print(border("╚" + "═" * width + "╝"))
    print()


# --------------------------------------------------------------------------
# Extraction patterns
# --------------------------------------------------------------------------
# Endpoint / path regex (broad match for API-like paths, routes, files)
ENDPOINT_RE = re.compile(
    r"""
    (?:"|')
    (
        (?:/[a-zA-Z0-9_\-.%]+){1,}          # at least one /segment
        (?:\?[a-zA-Z0-9_\-.=&%]*)?           # optional query string
    )
    (?:"|')
    """,
    re.VERBOSE,
)

FULL_URL_RE = re.compile(r"""(?:"|')(https?://[a-zA-Z0-9\-._~%/?#\[\]@!$&'()*+,;=]+)(?:"|')""")

GRAPHQL_RE = re.compile(
    r"""(
        (?:query|mutation|subscription)\s+\w*\s*(?:\([^)]*\))?\s*\{ |
        /graphql[a-zA-Z0-9_\-/]* |
        gql`[^`]{0,20}
    )""",
    re.VERBOSE | re.IGNORECASE,
)

# Secret / key patterns (subset of widely published detection signatures)
SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws(.{0,20})?(secret|private)?.{0,3}key(.{0,3})?['\"]\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    "Generic API Key": re.compile(r"(?i)(api[_-]?key|apikey|access[_-]?token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,45}['\"]"),
    "Private Key Block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP)? ?PRIVATE KEY-----"),
    "Firebase URL": re.compile(r"[a-zA-Z0-9\-]+\.firebaseio\.com"),
}

SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""", re.IGNORECASE)

IGNORE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ttf", ".ico")


# --------------------------------------------------------------------------
# Core scanning
# --------------------------------------------------------------------------
def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            return r.text
    except requests.RequestException as e:
        print(f"\033[38;5;196m[!] failed to fetch {url}: {e}\033[0m", file=sys.stderr)
    return None


def discover_js_files(page_url):
    """Fetch an HTML page and return absolute URLs of linked .js files."""
    html = fetch(page_url)
    if not html:
        return []
    found = SCRIPT_SRC_RE.findall(html)
    return sorted({urljoin(page_url, src) for src in found})


def extract_from_content(content, source):
    endpoints = set()
    for m in ENDPOINT_RE.finditer(content):
        path = m.group(1)
        if path.endswith(IGNORE_EXT):
            continue
        if len(path) < 2 or len(path) > 200:
            continue
        endpoints.add(path)

    full_urls = set(FULL_URL_RE.findall(content))

    graphql_hits = set()
    for m in GRAPHQL_RE.finditer(content):
        snippet = m.group(1).strip().replace("\n", " ")
        graphql_hits.add(snippet[:80])

    secrets_found = []
    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(content):
            secrets_found.append({"type": label, "match": m.group(0)[:120]})

    return {
        "source": source,
        "endpoints": sorted(endpoints),
        "full_urls": sorted(full_urls),
        "graphql": sorted(graphql_hits),
        "secrets": secrets_found,
    }


def scan_target(url):
    content = fetch(url)
    if content is None:
        return None
    return extract_from_content(content, url)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def load_url_list(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="JSScope - JS endpoint / GraphQL / secret extractor")
    parser.add_argument("-u", "--url", help="single URL (a .js file, or a page when used with --crawl)")
    parser.add_argument("-l", "--list", help="file containing a list of URLs, one per line")
    parser.add_argument("-f", "--file", help="scan a local JS file instead of fetching a URL")
    parser.add_argument("--crawl", action="store_true", help="treat -u as an HTML page and auto-discover linked .js files")
    parser.add_argument("-o", "--output", help="write full results to this JSON file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="concurrent fetch threads (default: 10)")
    parser.add_argument("--no-banner", action="store_true", help="skip the banner")
    parser.add_argument("--no-secrets", action="store_true", help="skip secret scanning")
    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    targets = []

    if args.file:
        with open(args.file, "r", errors="ignore") as f:
            content = f.read()
        result = extract_from_content(content, args.file)
        report([result], args.no_secrets)
        if args.output:
            save(args.output, [result])
        return

    if args.url and args.crawl:
        print(f"\033[38;5;135m[*] discovering JS files linked from {args.url}\033[0m")
        targets = discover_js_files(args.url)
        if not targets:
            print("\033[38;5;196m[!] no linked .js files found\033[0m")
            return
        print(f"\033[38;5;154m[+] found {len(targets)} JS file(s)\033[0m\n")
    elif args.url:
        targets = [args.url]
    elif args.list:
        targets = load_url_list(args.list)
    else:
        parser.print_help()
        return

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_target, t): t for t in targets}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)

    report(results, args.no_secrets)
    if args.output:
        save(args.output, results)


def report(results, no_secrets):
    total_endpoints = 0
    total_graphql = 0
    total_secrets = 0

    for res in results:
        if not (res["endpoints"] or res["full_urls"] or res["graphql"] or res["secrets"]):
            continue
        print(f"\033[38;5;39m[source] {res['source']}\033[0m")

        for ep in res["endpoints"]:
            print(f"  \033[38;5;154m[endpoint]\033[0m {ep}")
            total_endpoints += 1

        for gq in res["graphql"]:
            print(f"  \033[38;5;213m[graphql]\033[0m  {gq}")
            total_graphql += 1

        if not no_secrets:
            for s in res["secrets"]:
                print(f"  \033[38;5;196m[secret]\033[0m   {s['type']}: {s['match']}")
                total_secrets += 1

        print()

    print(f"\033[38;5;220m[summary] {total_endpoints} endpoint(s) · {total_graphql} graphql match(es) · {total_secrets} secret(s)\033[0m")


def save(path, results):
    with open(path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\033[38;5;154m[+] results saved to {path}\033[0m")


if __name__ == "__main__":
    main()
