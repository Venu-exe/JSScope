<div align="center">
  <h1>🔍 JSScope</h1>
  <p><b>JavaScript endpoint, GraphQL, and secret extractor for bug bounty recon.</b></p>
  
  <p>
    <a href="https://github.com/Venu-exe/JSScope/stargazers"><img src="https://img.shields.io/github/stars/Venu-exe/JSScope?style=for-the-badge&color=yellow" alt="Stars"></a>
    <a href="https://github.com/Venu-exe/JSScope/network/members"><img src="https://img.shields.io/github/forks/Venu-exe/JSScope?style=for-the-badge&color=blue" alt="Forks"></a>
    <a href="https://github.com/Venu-exe/JSScope/issues"><img src="https://img.shields.io/github/issues/Venu-exe/JSScope?style=for-the-badge&color=green" alt="Issues"></a>
    <a href="https://github.com/Venu-exe/JSScope/blob/master/LICENSE"><img src="https://img.shields.io/github/license/Venu-exe/JSScope?style=for-the-badge&color=red" alt="License"></a>
  </p>

  <p>
    <b>⭐️ If you find this tool useful, please leave a star and share your feedback! ⭐️</b>
  </p>
</div>

---

Point JSScope at a `.js` file, a page (with `--crawl` to auto-discover linked scripts),
or a list of URLs, and it will pull out:

- **Endpoints / routes** — `/api/v1/users/{id}`, `/admin/config.json`, etc.
- **Full URLs** embedded in the JS
- **GraphQL** operations (`query`, `mutation`, `subscription`, `/graphql` paths, `gql` tags)
- **Leaked secrets** — AWS keys, Google API keys, Slack tokens, JWTs, generic API keys, private key blocks, Firebase URLs

Fetching is multi-threaded so scanning a list of JS files is fast.

## 🤝 Feedback & Reviews
Your feedback is incredibly valuable! After you've used JSScope in your recon process, please [leave a review or feature request in the Issues tab](https://github.com/Venu-exe/JSScope/issues/new/choose). 

## ⚠️ Disclaimer

Only use this against targets you are authorized to test — programs you're
enrolled in on a bug bounty platform, or assets you own. Scanning systems
without permission may be illegal in your jurisdiction.

## Install

```bash
pip install -r requirements.txt
```

## Usage

Scan a single JS file by URL:
```bash
python3 jsscope.py -u https://target.com/static/js/main.js
```

Crawl a page for linked `.js` files and scan all of them:
```bash
python3 jsscope.py -u https://target.com --crawl
```

Scan a list of URLs (one per line, `#` for comments):
```bash
python3 jsscope.py -l urls.txt -o results.json
```

Scan a local JS file (e.g. already downloaded, or de-minified):
```bash
python3 jsscope.py -f ./bundle.js
```

## Options

| Flag | Description |
|---|---|
| `-u, --url` | single URL (a `.js` file, or a page when used with `--crawl`) |
| `-l, --list` | file with a list of URLs, one per line |
| `-f, --file` | scan a local file instead of fetching a URL |
| `--crawl` | treat `-u` as an HTML page and auto-discover linked `.js` files |
| `-o, --output` | write full JSON results to this path |
| `-t, --threads` | concurrent fetch threads (default: 10) |
| `--no-banner` | skip the startup banner |
| `--no-secrets` | skip secret scanning (endpoints/graphql only) |

## Output

Console output is grouped per source file, plus a summary line. Pass
`-o results.json` to also save the full structured results:

```json
[
  {
    "source": "https://target.com/main.js",
    "endpoints": ["/api/v1/users/{id}", "/admin/config.json"],
    "full_urls": ["https://api.target.com/graphql"],
    "graphql": ["/graphql", "mutation UpdateUser {"],
    "secrets": [{"type": "JWT", "match": "eyJ..."}]
  }
]
```

## Notes

- Secret detection uses pattern matching (regex) on known key formats —
  it will have false positives/negatives like any static signature approach.
  Always manually verify a "secret" before reporting it.
- Respect the scope and rate limits of the program you're testing against;
  `--threads` defaults to 10, lower it if a target is rate-limiting you.
