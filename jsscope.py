#!/usr/bin/env python3
"""
JSScope - JavaScript endpoint, GraphQL & secret extractor for bug bounty recon.

Point it at a .js file, an HTML page (with --crawl), a local file, or a list of
URLs. It pulls out API routes, absolute URLs, GraphQL operations, source map
references and leaked-looking secrets.

Usage examples:
  python3 jsscope.py -u https://target.com/static/main.js
  python3 jsscope.py -u https://target.com --crawl
  python3 jsscope.py -u https://target.com --crawl --depth 2
  python3 jsscope.py -l urls.txt -o results.json
  python3 jsscope.py -f ./downloaded_bundle.js
  cat urls.txt | python3 jsscope.py -l -

DISCLAIMER: Use only against targets you are authorized to test
(bug bounty programs you're enrolled in, or your own assets).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import math
import os
import re
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:  # keep self-signed / expired certs from spamming stderr
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover - urllib3 is a requests dependency
    pass


VERSION = "2.0.0"
PROJECT_URL = "https://github.com/Venu-exe/JSScope"
DEFAULT_TIMEOUT = 12
DEFAULT_THREADS = 10
MAX_SECRET_LEN = 160


# --------------------------------------------------------------------------
# Terminal colors
# --------------------------------------------------------------------------
_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

PINK = (255, 60, 160)
BLUE = (60, 130, 255)
VIOLET = (150, 90, 255)
GREEN = (120, 220, 120)
CYAN = (80, 200, 255)
YELLOW = (240, 200, 80)
RED = (255, 80, 80)
GREY = (150, 150, 150)
WHITE = (240, 240, 240)


def paint(text: str, rgb: tuple[int, int, int]) -> str:
    """Wrap text in a 24-bit foreground color when the terminal supports it."""
    if not _COLOR:
        return text
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"


def info(msg: str) -> None:
    print(paint("[*]", CYAN) + " " + msg)


def success(msg: str) -> None:
    print(paint("[+]", GREEN) + " " + msg)


def warn(msg: str) -> None:
    print(paint("[!]", RED) + " " + msg, file=sys.stderr)


def gradient_text(text: str, start_rgb: tuple[int, int, int], end_rgb: tuple[int, int, int]) -> str:
    length = max(len(text), 1)
    out = []
    for i, ch in enumerate(text):
        t = i / length
        rgb = tuple(int(start_rgb[c] + (end_rgb[c] - start_rgb[c]) * t) for c in range(3))
        out.append(paint(ch, rgb))
    return "".join(out)


def print_banner() -> None:
    try:
        import pyfiglet

        art_lines = pyfiglet.figlet_format("JSSCOPE", font="ansi_shadow").rstrip("\n").split("\n")
    except Exception:
        art_lines = ["JSSCOPE"]
    art_lines = [line for line in art_lines if line.strip()] or ["JSSCOPE"]

    tagline = "JavaScript Endpoint, GraphQL & Secret Extractor"
    credit = "by venu-exe  ·  github.com/Venu-exe/JSScope"

    width = max(len(line) for line in art_lines + [tagline, credit]) + 4
    border_char = paint("║", VIOLET)

    def border(ch: str) -> str:
        return paint(ch, VIOLET)

    print(border("╔" + "═" * width + "╗"))
    print(border_char + " " * width + border_char)
    for i, line in enumerate(art_lines):
        t = i / max(len(art_lines) - 1, 1)
        end = tuple(int(PINK[c] + (BLUE[c] - PINK[c]) * t) for c in range(3))
        colored = gradient_text(line, PINK, end)
        padding = width - len(line) - 2
        print(border_char + " " + colored + " " * max(padding, 0) + border_char)
    print(border_char + " " * width + border_char)
    print(border_char + gradient_text(tagline.center(width), YELLOW, PINK) + border_char)
    print(border_char + paint(credit.center(width), GREY) + border_char)
    print(border_char + " " * width + border_char)
    print(border("╚" + "═" * width + "╝"))
    print()


# --------------------------------------------------------------------------
# Extraction patterns
# --------------------------------------------------------------------------
# API-like paths inside quotes or template literals.
ENDPOINT_RE = re.compile(
    r"""["'`]((?:/[A-Za-z0-9_\-.~%{}:$]+){1,}(?:\?[A-Za-z0-9_\-.=&%\[\]$]*)?)["'`]"""
)

FULL_URL_RE = re.compile(
    r"""["'`](https?://[A-Za-z0-9\-._~%/?#\[\]@!$&()*+,;=]+)["'`]"""
)

GRAPHQL_RE = re.compile(
    r"""(?:query|mutation|subscription)\s+(?:[A-Za-z_]\w*\s*)?(?:\([^)]*\)\s*)?\{"""
    r"""|/graphql[A-Za-z0-9_\-/]*"""
    r"""|gql`[^`]{0,80}""",
    re.IGNORECASE,
)

SOURCE_MAP_RE = re.compile(r"""sourceMappingURL=([^\s'"*]+)""")

SCRIPT_TAG_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
SRC_ATTR_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
LINK_TAG_RE = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
LINK_HREF_RE = re.compile(r"""\bhref\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
LINK_REL_RE = re.compile(r"""\brel\s*=\s*["']([^"']+)["']""", re.IGNORECASE)

# Static JS imports (ES modules, dynamic import(), require(), importScripts()).
ES_IMPORT_RE = re.compile(
    r"""(?:^|[;\s])(?:import|export)\s+(?:[^;"'`]*?\sfrom\s*)?["']([^"']+)["']""",
    re.MULTILINE,
)
DYNAMIC_IMPORT_RE = re.compile(
    r"""(?:import|require|importScripts)\s*\(\s*["']([^"']+)["']\s*\)"""
)
JS_EXT_RE = re.compile(r"""\.(?:m?js|jsx|ts|tsx)(?:[?#]|$)""", re.IGNORECASE)

ASSET_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".bmp",
    ".css", ".map", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".ico",
    ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip", ".gz",
)
SCRIPT_EXT = (".js", ".mjs", ".jsx")
# Endpoints ending in a script or asset are noise; scripts are tracked separately.
IGNORE_EXT = ASSET_EXT + SCRIPT_EXT


# Secret signatures. These are intentionally conservative to limit noise;
# every hit should still be verified by hand before reporting it.
SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Key": re.compile(
        r"""(?i)aws.{0,20}(?:secret|private).{0,20}key['"]?\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]"""
    ),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Google OAuth Client ID": re.compile(r"\b[0-9]{10,}-[0-9a-z_]{32}\.apps\.googleusercontent\.com\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "GitHub Token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    "Stripe Key": re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}\b"),
    "SendGrid Key": re.compile(r"\bSG\.[\w\-]{16,}\.[\w\-]{16,}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "Mailgun Key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    "Private Key Block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "Firebase URL": re.compile(r"\b[a-zA-Z0-9\-]+\.firebaseio\.com\b"),
    "Basic Auth URL": re.compile(r"https?://[^/\s:@'\"`]+:[^/\s@'\"`]+@[^/\s'\"`]+"),
    "Generic Secret": re.compile(
        r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|"""
        r"""client[_-]?secret|password|passwd)\b['"]?\s*[:=]\s*['"]([0-9a-zA-Z\-_./+=]{12,80})['"]"""
    ),
}

# Values that look like secrets but are almost always documentation noise.
PLACEHOLDER_HINTS = (
    "xxxx", "your_", "your-", "example", "changeme", "change_me", "placeholder",
    "dummy", "sample", "todo", "redacted", "replace_me", "insert_", "${", "{{",
    "process.env", "import.meta",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(hint in low for hint in PLACEHOLDER_HINTS)


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
def _is_ignored_url(value: str) -> bool:
    return urlparse(value).path.lower().endswith(ASSET_EXT)


def extract_endpoints(content: str) -> list[str]:
    endpoints = set()
    for match in ENDPOINT_RE.finditer(content):
        path = match.group(1)
        if not 2 <= len(path) <= 300:
            continue
        if path.startswith("//"):  # protocol-relative URL, not an endpoint
            continue
        if path.lower().endswith(IGNORE_EXT):
            continue
        if any(ch in path for ch in ("<", ">", "\\", " ", "\n", "\t")):
            continue
        endpoints.add(path)
    return sorted(endpoints)


def extract_urls(content: str) -> list[str]:
    return sorted({url for url in FULL_URL_RE.findall(content) if not _is_ignored_url(url)})


def extract_graphql(content: str) -> list[str]:
    hits = set()
    for match in GRAPHQL_RE.finditer(content):
        snippet = " ".join(match.group(0).split())
        hits.add(snippet[:100])
    return sorted(hits)


def extract_secrets(content: str) -> list[dict]:
    found: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(content):
            value = match.group(1) if match.groups() else match.group(0)
            value = value.strip()
            if not value or len(value) < 8:
                continue
            if looks_like_placeholder(value):
                continue
            if label == "Generic Secret" and shannon_entropy(value) < 3.0:
                continue
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            found.append({"type": label, "match": value[:MAX_SECRET_LEN]})

    return found


def extract_sourcemaps(content: str, source: str) -> list[str]:
    maps = set()
    for match in SOURCE_MAP_RE.finditer(content):
        ref = match.group(1).strip()
        if ref.startswith("data:"):
            continue
        maps.add(urljoin(source, ref) if is_url(source) else ref)
    return sorted(maps)


def extract(content: str, source: str) -> dict:
    """Extract every finding type from a chunk of JavaScript."""
    return {
        "endpoints": extract_endpoints(content),
        "urls": extract_urls(content),
        "graphql": extract_graphql(content),
        "secrets": extract_secrets(content),
        "sourcemaps": extract_sourcemaps(content, source),
    }


def discover_imports(content: str, base: str) -> list[str]:
    """Find relative JS modules referenced by a script so they can be queued."""
    base_host = urlparse(base).netloc if is_url(base) else ""
    found: set[str] = set()

    for pattern in (ES_IMPORT_RE, DYNAMIC_IMPORT_RE):
        for match in pattern.finditer(content):
            spec = match.group(1).strip()
            if not spec or spec.startswith("//"):
                continue
            if not JS_EXT_RE.search(spec):
                continue
            if not (spec.startswith(".") or spec.startswith("/")):
                continue  # bare package specifier, not a same-origin asset
            target = urljoin(base, spec) if is_url(base) else spec
            if base_host and urlparse(target).netloc not in ("", base_host):
                continue
            found.add(target)
    return sorted(found)


def discover_page(html: str, base_url: str) -> tuple[list[str], list[str]]:
    """Return (linked script URLs, inline script bodies) for an HTML page."""
    scripts: set[str] = set()
    inline: list[str] = []

    for attrs, body in SCRIPT_TAG_RE.findall(html):
        src_match = SRC_ATTR_RE.search(attrs)
        if src_match:
            src = src_match.group(1).strip()
            if not src or src.startswith(("data:", "javascript:")):
                continue
            absolute = urljoin(base_url, src)
            if _is_ignored_url(absolute):
                continue
            scripts.add(absolute)
        elif body.strip():
            inline.append(body)

    # <link rel="modulepreload"> / <link rel="preload" as="script">
    for tag in LINK_TAG_RE.findall(html):
        rel_match = LINK_REL_RE.search(tag)
        href_match = LINK_HREF_RE.search(tag)
        if not (rel_match and href_match):
            continue
        rel = rel_match.group(1).lower()
        if "modulepreload" in rel or ("preload" in rel and "script" in tag.lower()):
            absolute = urljoin(base_url, href_match.group(1).strip())
            if JS_EXT_RE.search(urlparse(absolute).path):
                scripts.add(absolute)

    return sorted(scripts), inline


# --------------------------------------------------------------------------
# Networking
# --------------------------------------------------------------------------
def is_url(value: str) -> bool:
    return value.startswith(("http://", "https://"))


class Fetcher:
    """Thread-aware HTTP client with retries, optional proxy and rate limiting."""

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        verify: bool = False,
        headers: Iterable[str] = (),
        proxy: str | None = None,
        delay: float = 0.0,
    ) -> None:
        self.timeout = timeout
        self.verify = verify
        self.proxy = proxy
        self.delay = delay
        self.headers = {"User-Agent": f"JSScope/{VERSION} (+{PROJECT_URL})"}
        for raw in headers:
            if ":" not in raw:
                warn(f"ignoring malformed header (expected 'Name: value'): {raw}")
                continue
            name, value = raw.split(":", 1)
            self.headers[name.strip()] = value.strip()
        self._local = threading.local()

    def _session(self) -> requests.Session:
        session = getattr(self._local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self.headers)
            retry = Retry(
                total=2,
                backoff_factor=0.4,
                status_forcelist=(429, 500, 502, 503, 504),
                allowed_methods=frozenset(["GET"]),
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retry, pool_connections=8, pool_maxsize=8)
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            if self.proxy:
                session.proxies.update({"http": self.proxy, "https": self.proxy})
            self._local.session = session
        return session

    def get(self, url: str) -> str | None:
        try:
            if self.delay:
                time.sleep(self.delay)
            response = self._session().get(
                url,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=True,
            )
            if response.status_code >= 400:
                warn(f"failed to fetch {url} (HTTP {response.status_code})")
                return None
            response.encoding = response.encoding or "utf-8"
            return response.text
        except requests.RequestException as exc:
            warn(f"failed to fetch {url}: {exc}")
            return None


# --------------------------------------------------------------------------
# Result model
# --------------------------------------------------------------------------
@dataclass
class ScanResult:
    source: str
    endpoints: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    graphql: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    sourcemaps: list[str] = field(default_factory=list)
    content: str = field(default="", repr=False, compare=False)

    @classmethod
    def from_content(cls, content: str, source: str) -> "ScanResult":
        return cls(source=source, content=content, **extract(content, source))

    def has_findings(self) -> bool:
        return bool(self.endpoints or self.urls or self.graphql or self.secrets or self.sourcemaps)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "endpoints": self.endpoints,
            "urls": self.urls,
            "graphql": self.graphql,
            "secrets": self.secrets,
            "sourcemaps": self.sourcemaps,
        }


def scan_url(fetcher: Fetcher, url: str) -> ScanResult | None:
    content = fetcher.get(url)
    if content is None:
        return None
    return ScanResult.from_content(content, url)


def scan_many(fetcher: Fetcher, urls: list[str], threads: int) -> list[ScanResult]:
    if not urls:
        return []
    results: list[ScanResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futures = {pool.submit(scan_url, fetcher, url): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
            except Exception as exc:  # defensive: never lose the whole run
                warn(f"scan failed for {futures[future]}: {exc}")
                continue
            if result is not None:
                results.append(result)
    return results


def run_scan(fetcher: Fetcher, targets: list[str], threads: int, depth: int) -> list[ScanResult]:
    """Scan targets, optionally following relative JS imports up to `depth` levels."""
    results: list[ScanResult] = []
    seen: set[str] = set()
    frontier = [url for url in dict.fromkeys(targets) if url not in seen]
    level = 0

    while frontier:
        seen.update(frontier)
        batch = scan_many(fetcher, frontier, threads)
        results.extend(batch)
        if level >= depth:
            break
        level += 1
        next_frontier = set()
        for result in batch:
            next_frontier.update(discover_imports(result.content, result.source))
        frontier = sorted(next_frontier - seen)

    return results


# --------------------------------------------------------------------------
# Filtering, redaction, reporting
# --------------------------------------------------------------------------
def redact(value: str) -> str:
    if len(value) <= 10:
        return "*" * len(value)
    return f"{value[:5]}...{value[-4:]}"


def filter_result(result: ScanResult, include: re.Pattern | None, exclude: re.Pattern | None) -> ScanResult:
    def keep(value: str) -> bool:
        if include and not include.search(value):
            return False
        if exclude and exclude.search(value):
            return False
        return True

    return ScanResult(
        source=result.source,
        endpoints=[e for e in result.endpoints if keep(e)],
        urls=[u for u in result.urls if keep(u)],
        graphql=[g for g in result.graphql if keep(g)],
        secrets=result.secrets,
        sourcemaps=[s for s in result.sourcemaps if keep(s)],
        content=result.content,
    )


def report(results: list[ScanResult], args: argparse.Namespace) -> tuple[int, int, int, int, int]:
    totals = {"endpoints": 0, "urls": 0, "graphql": 0, "secrets": 0, "sourcemaps": 0}

    for result in results:
        if not result.has_findings():
            continue
        print(paint(f"[source] {result.source}", CYAN))

        for endpoint in result.endpoints:
            print(f"  {paint('[endpoint]', GREEN)}  {endpoint}")
            totals["endpoints"] += 1

        for url in result.urls:
            print(f"  {paint('[url]', BLUE)}       {url}")
            totals["urls"] += 1

        for gql in result.graphql:
            print(f"  {paint('[graphql]', VIOLET)}   {gql}")
            totals["graphql"] += 1

        if not args.no_secrets:
            for secret in result.secrets:
                value = redact(secret["match"]) if args.redact else secret["match"]
                print(f"  {paint('[secret]', RED)}    {secret['type']}: {value}")
                totals["secrets"] += 1

        for sourcemap in result.sourcemaps:
            print(f"  {paint('[sourcemap]', YELLOW)} {sourcemap}")
            totals["sourcemaps"] += 1

        print()

    summary = (
        f"{totals['endpoints']} endpoint(s) · {totals['urls']} url(s) · "
        f"{totals['graphql']} graphql hit(s) · {totals['secrets']} secret(s) · "
        f"{totals['sourcemaps']} sourcemap(s)"
    )
    print(paint(f"[summary] {summary}", YELLOW))
    return (
        totals["endpoints"],
        totals["urls"],
        totals["graphql"],
        totals["secrets"],
        totals["sourcemaps"],
    )


def save(path: str, results: list[ScanResult]) -> None:
    payload = [result.to_dict() for result in results]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    success(f"results saved to {path}")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def load_url_list(path: str) -> list[str]:
    if path == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            lines = handle.read().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="jsscope",
        description="JSScope - JavaScript endpoint, GraphQL & secret extractor.",
        epilog="Use only against systems you are authorized to test.",
    )
    parser.add_argument("-u", "--url", help="single URL (.js file, or an HTML page with --crawl)")
    parser.add_argument("-l", "--list", help="file of URLs, one per line ('-' reads stdin)")
    parser.add_argument("-f", "--file", help="scan a local JS file instead of fetching a URL")
    parser.add_argument("--crawl", action="store_true", help="treat -u as an HTML page and discover its scripts")
    parser.add_argument(
        "--depth",
        type=int,
        default=0,
        metavar="N",
        help="follow relative JS imports N levels deep (default: 0)",
    )
    parser.add_argument("-o", "--output", help="write structured results to this JSON file")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="concurrent fetches (default: 10)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="request timeout in seconds (default: 12)")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SEC", help="sleep between requests (default: 0)")
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="'Name: value'",
        help="extra request header (repeatable)",
    )
    parser.add_argument("--proxy", help="route requests through a proxy, e.g. http://127.0.0.1:8080")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="enforce TLS certificate verification (off by default, for self-signed targets)",
    )
    parser.add_argument("--filter", metavar="REGEX", help="only keep endpoints/urls/graphql matching REGEX")
    parser.add_argument("--exclude", metavar="REGEX", help="drop endpoints/urls/graphql matching REGEX")
    parser.add_argument("--redact", action="store_true", help="mask secret values in console output")
    parser.add_argument("--no-secrets", action="store_true", help="skip secret scanning output")
    parser.add_argument("--no-banner", action="store_true", help="skip the startup banner")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"JSScope {VERSION}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    global _COLOR

    args = parse_args(argv)
    if args.no_color or not sys.stdout.isatty() or "NO_COLOR" in os.environ:
        _COLOR = False

    if not args.no_banner:
        print_banner()

    if args.url and args.list:
        warn("use either -u/--url or -l/--list, not both")
        return 2
    if args.depth < 0:
        warn("--depth must be >= 0")
        return 2
    if args.threads < 1:
        warn("--threads must be >= 1")
        return 2

    include = re.compile(args.filter) if args.filter else None
    exclude = re.compile(args.exclude) if args.exclude else None

    # Local file mode: no network, no import following.
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as handle:
                content = handle.read()
        except OSError as exc:
            warn(f"could not read {args.file}: {exc}")
            return 2
        info(f"scanning local file {args.file}")
        results = [ScanResult.from_content(content, args.file)]
        if args.no_secrets:
            for result in results:
                result.secrets = []
        results = [filter_result(r, include, exclude) for r in results]
        report(results, args)
        if args.output:
            save(args.output, results)
        return 0

    headers = list(args.header)
    fetcher = Fetcher(
        timeout=args.timeout,
        verify=args.verify,
        headers=headers,
        proxy=args.proxy,
        delay=args.delay,
    )

    precomputed: list[ScanResult] = []
    targets: list[str] = []

    if args.url and args.crawl:
        info(f"discovering scripts on {args.url}")
        html = fetcher.get(args.url)
        if not html:
            warn("could not fetch the target page")
            return 1
        scripts, inline = discover_page(html, args.url)
        if not scripts and not inline:
            warn("no linked or inline scripts found")
            return 0
        success(f"found {len(scripts)} script(s) and {len(inline)} inline block(s)")
        print()
        targets = scripts
        for index, body in enumerate(inline, start=1):
            precomputed.append(ScanResult.from_content(body, f"{args.url}#inline-{index}"))
    elif args.url:
        targets = [args.url]
    elif args.list:
        try:
            targets = load_url_list(args.list)
        except OSError as exc:
            warn(f"could not read {args.list}: {exc}")
            return 2
        if not targets:
            warn("the URL list is empty")
            return 1
    else:
        parse_args(["--help"])

    info(f"scanning {len(targets)} target(s) with {args.threads} thread(s)" + (f", depth {args.depth}" if args.depth else ""))
    print()

    results = precomputed + run_scan(fetcher, targets, args.threads, args.depth)
    results = [result for result in results if result.has_findings()]
    results = [filter_result(result, include, exclude) for result in results]
    results.sort(key=lambda result: result.source)

    if not results:
        warn("no findings")

    report(results, args)
    if args.output:
        save(args.output, results)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        warn("interrupted")
        sys.exit(130)
