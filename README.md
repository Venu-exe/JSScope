<div align="center">
  <h1>🔍 JSScope</h1>
  <p><b>JavaScript endpoint, GraphQL, and secret extractor for bug bounty recon.</b></p>

  <p>
    <a href="https://github.com/Venu-exe/JSScope/stargazers"><img src="https://img.shields.io/github/stars/Venu-exe/JSScope?style=for-the-badge&color=yellow" alt="Stars"></a>
    <a href="https://github.com/Venu-exe/JSScope/network/members"><img src="https://img.shields.io/github/forks/Venu-exe/JSScope?style=for-the-badge&color=blue" alt="Forks"></a>
    <a href="https://github.com/Venu-exe/JSScope/actions/workflows/tests.yml"><img src="https://img.shields.io/github/actions/workflow/status/Venu-exe/JSScope/tests.yml?style=for-the-badge&label=tests" alt="Tests"></a>
    <a href="https://github.com/Venu-exe/JSScope/blob/master/LICENSE"><img src="https://img.shields.io/github/license/Venu-exe/JSScope?style=for-the-badge&color=red" alt="License"></a>
  </p>

  <p>
    <b>⭐️ If JSScope saves you time during recon, leave a star and tell me what to improve! ⭐️</b>
  </p>
</div>

---

Point JSScope at a `.js` file, an HTML page (with `--crawl`), a local file, or a
list of URLs. It pulls out:

- **Endpoints / routes** — `/api/v1/users/{id}`, `/admin/config.json`, template-literal paths
- **Absolute URLs** embedded in scripts
- **GraphQL operations** — `query`, `mutation`, `subscription`, `/graphql` paths, `gql` tags
- **Leaked secrets** — AWS, Google, GitHub, Slack, Stripe, SendGrid, Twilio, Mailgun, JWTs, private key blocks, Firebase URLs, basic-auth URLs, generic API keys
- **Source map references** — resolved to absolute URLs so you can fetch the original code

Scans run in parallel, and `--depth` follows relative `import` / `require` /
`importScripts` chains so lazy-loaded bundles don't get missed.

## Install

Requires Python 3.9+.

```bash
git clone https://github.com/Venu-exe/JSScope.git
cd JSScope
pip install -r requirements.txt
```

Or install it as a command with [pipx](https://pipx.pypa.io/):

```bash
pipx install .
jsscope --help
```

## Quick start

Scan a single JS file:

```bash
python3 jsscope.py -u https://target.com/static/js/main.js
```

Crawl a page, discover its scripts, and follow one level of imports:

```bash
python3 jsscope.py -u https://target.com --crawl --depth 1
```

Scan a list of URLs and save structured results:

```bash
python3 jsscope.py -l urls.txt -o results.json
```

Read URLs from stdin (great for piping from other recon tools):

```bash
cat urls.txt | python3 jsscope.py -l - --redact
```

Scan a local or de-minified bundle:

```bash
python3 jsscope.py -f ./bundle.js
```

Filter noise and only keep API routes:

```bash
python3 jsscope.py -u https://target.com/main.js --filter '/api/' --exclude '\.(svg|png)$'
```

## Options

| Flag | Description |
|---|---|
| `-u, --url` | single URL (`.js` file, or a page with `--crawl`) |
| `-l, --list` | file of URLs, one per line (`#` comments, `-` for stdin) |
| `-f, --file` | scan a local file instead of fetching a URL |
| `--crawl` | treat `-u` as HTML and discover linked + inline scripts |
| `--depth N` | follow relative JS imports `N` levels deep (default: `0`) |
| `-o, --output` | write structured JSON results to this path |
| `-t, --threads` | concurrent fetches (default: `10`) |
| `--timeout` | request timeout in seconds (default: `12`) |
| `--delay SEC` | sleep between requests for rate-limited targets |
| `-H, --header` | extra request header, e.g. `-H 'Cookie: session=...'` (repeatable) |
| `--proxy` | send traffic through a proxy, e.g. Burp at `http://127.0.0.1:8080` |
| `--verify` | enforce TLS verification (off by default for self-signed targets) |
| `--filter REGEX` | only keep endpoints/URLs/GraphQL matching `REGEX` |
| `--exclude REGEX` | drop endpoints/URLs/GraphQL matching `REGEX` |
| `--redact` | mask secret values in console output (safe for screenshots) |
| `--no-secrets` | hide secret findings |
| `--no-banner` | skip the startup banner |
| `--no-color` | disable ANSI colors (also honors `NO_COLOR`) |
| `--version` | print the version and exit |

## Output

The console groups findings per source file and ends with a summary line. Use
`-o results.json` to also save the full structured data:

```json
[
  {
    "source": "https://target.com/main.js",
    "endpoints": ["/api/v1/users/{id}", "/admin/config.json"],
    "urls": ["https://api.target.com/graphql"],
    "graphql": ["/graphql", "query GetUser($id: ID!) {"],
    "secrets": [{"type": "JWT", "match": "eyJhbGciOi..."}],
    "sourcemaps": ["https://target.com/static/main.js.map"]
  }
]
```

Every result object has the same keys, so `jq` works cleanly:

```bash
jq -r '.[].endpoints[]' results.json | sort -u
jq -r '.[] | select(.secrets | length > 0) | .source' results.json
```

## How it works

1. **Fetch** — threaded HTTP client with retries, optional proxy/custom headers,
   and rate limiting.
2. **Discover** — with `--crawl`, parse `<script src>`, inline `<script>` bodies,
   and `<link rel="modulepreload">` / `preload as="script">` tags. With
   `--depth`, queue relative imports found inside each script.
3. **Extract** — regex signatures for paths, absolute URLs, GraphQL operations,
   source maps, and known secret formats.
4. **Filter & report** — deduplicate, apply `--filter` / `--exclude`, redact if
   requested, and emit console + optional JSON output.

## Detection notes

- Secret detection is signature-based (plus a Shannon-entropy check and a
  placeholder blocklist for generic keys). It will still produce false
  positives and false negatives. **Verify before reporting.**
- Endpoint regexes match quoted strings, including template literals, so
  interpolated paths show up as `/api/users/${id}`.
- TLS verification is off by default because bug bounty targets often use
  self-signed or expired certificates. Add `--verify` to turn it back on.

## Development

```bash
pip install -r requirements.txt pytest
pytest -q
```

Tests cover endpoint/URL/GraphQL extraction, secret handling, source maps,
import discovery, HTML crawling, filters, and redaction. CI runs them on every
push against Python 3.9, 3.11, and 3.13.

## Contributing

Bug reports, feature requests, and feedback are welcome in the
[Issues tab](https://github.com/Venu-exe/JSScope/issues/new/choose). If you send
a PR, keep changes consistent with the existing single-file structure and add a
test for new extraction behavior.

## ⚠️ Disclaimer

Only use JSScope against targets you are authorized to test — programs you're
enrolled in on a bug bounty platform, or assets you own. Scanning systems
without permission may be illegal in your jurisdiction. You are responsible for
how you use this tool.

## License

[MIT](LICENSE)
