import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import jsscope  # noqa: E402


SAMPLE_JS = """
const API = "/api/v1/users/{id}";
const ADMIN = '/admin/config.json';
const ASSET = "/static/logo.png";
const CDN = "https://cdn.example.com/lib.js";
const BASE = "//cdn.example.com/protocol-relative";
const doc = "https://docs.example.org/guide";
const image = "https://cdn.example.com/hero.webp";

const QUERY = `query GetUser($id: ID!) { user(id: $id) { email } }`;
const MUTATION = gql`mutation UpdateUser { updateUser { id } }`;
const URL_GQL = "/graphql/v2";

//# sourceMappingURL=app.bundle.js.map
"""


def test_extracts_endpoints_and_filters_assets():
    endpoints = jsscope.extract_endpoints(SAMPLE_JS)
    assert "/api/v1/users/{id}" in endpoints
    assert "/admin/config.json" in endpoints
    assert "/graphql/v2" in endpoints
    assert "/static/logo.png" not in endpoints
    assert not any(e.startswith("//") for e in endpoints)


def test_extracts_full_urls_only():
    urls = jsscope.extract_urls(SAMPLE_JS)
    assert "https://docs.example.org/guide" in urls
    assert "https://cdn.example.com/lib.js" in urls
    assert "https://cdn.example.com/hero.webp" not in urls


def test_extracts_graphql_operations():
    hits = " ".join(jsscope.extract_graphql(SAMPLE_JS))
    assert "mutation UpdateUser" in hits
    assert "query GetUser" in hits
    assert "/graphql/v2" in hits


def test_detects_known_secret_formats():
    content = """
    const aws = "AKIAABCDEFGHIJKLMNOP";
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ";
    const slack = "xoxb-12345678901-abcdefghij";
    """
    found = {item["type"] for item in jsscope.extract_secrets(content)}
    assert "AWS Access Key" in found
    assert "JWT" in found
    assert "Slack Token" in found


def test_skips_placeholders_and_low_entropy():
    content = """
    const a = { apiKey: "your_api_key_here" };
    const b = { apiKey: "aaaaaaaaaaaaaaaaaaaa" };
    const c = { apiKey: "aB3xK9mQ2pL7vR5t" };
    """
    values = [item["match"] for item in jsscope.extract_secrets(content)]
    assert "your_api_key_here" not in values
    assert "aaaaaaaaaaaaaaaaaaaa" not in values
    assert "aB3xK9mQ2pL7vR5t" in values


def test_secrets_are_deduplicated():
    content = 'const key = "AIza' + "a" * 35 + '";\nconst again = "AIza' + "a" * 35 + '";'
    found = jsscope.extract_secrets(content)
    assert len([item for item in found if item["type"] == "Google API Key"]) == 1


def test_sourcemap_reference_is_resolved():
    maps = jsscope.extract_sourcemaps("//# sourceMappingURL=app.js.map", "https://target.com/static/main.js")
    assert maps == ["https://target.com/static/app.js.map"]


def test_discover_imports_only_relative_scripts():
    content = """
    import { api } from "./api/client.js";
    export * from './utils/helpers.mjs';
    const lazy = import("./chunks/admin.js");
    import React from "react";
    import styles from "./styles.css";
    import remote from "https://other.example.com/x.js";
    """
    imports = jsscope.discover_imports(content, "https://target.com/static/main.js")
    assert "https://target.com/static/api/client.js" in imports
    assert "https://target.com/static/utils/helpers.mjs" in imports
    assert "https://target.com/static/chunks/admin.js" in imports
    assert not any("styles.css" in item for item in imports)
    assert not any("react" in item for item in imports)
    assert not any("other.example.com" in item for item in imports)


def test_discover_page_finds_scripts_inline_and_preloads():
    html = """
    <html><head>
      <link rel="modulepreload" href="/assets/vendor.js">
      <script src="/static/main.js"></script>
      <script src="https://cdn.example.com/lib.js?v=2"></script>
      <script src="/static/logo.png"></script>
    </head><body>
      <script>window.__CONFIG__ = { api: "/api/internal" };</script>
    </body></html>
    """
    scripts, inline = jsscope.discover_page(html, "https://target.com/app/home")
    assert "https://target.com/static/main.js" in scripts
    assert "https://cdn.example.com/lib.js?v=2" in scripts
    assert "https://target.com/assets/vendor.js" in scripts
    assert not any("logo.png" in item for item in scripts)
    assert len(inline) == 1
    assert "/api/internal" in inline[0]


def test_redact_hides_secret_middle():
    redacted = jsscope.redact("AKIAABCDEFGHIJKLMNOP")
    assert redacted.startswith("AKIA")
    assert redacted.endswith("MNOP")
    assert "..." in redacted
    assert jsscope.redact("short") == "*" * len("short")


def test_filter_result_applies_include_and_exclude():
    result = jsscope.ScanResult(
        source="x.js",
        endpoints=["/api/users", "/admin/panel", "/api/orders"],
        urls=["https://api.example.com/v1"],
        graphql=[],
        secrets=[],
        sourcemaps=[],
    )
    filtered = jsscope.filter_result(result, re.compile(r"api"), re.compile(r"orders"))
    assert filtered.endpoints == ["/api/users"]
    assert filtered.urls == ["https://api.example.com/v1"]


def test_extract_returns_every_category():
    data = jsscope.extract(SAMPLE_JS, "https://target.com/main.js")
    assert set(data) == {"endpoints", "urls", "graphql", "secrets", "sourcemaps"}


def test_fetcher_parses_custom_headers():
    fetcher = jsscope.Fetcher(headers=["X-Test: hello", "Authorization: Bearer abc"])
    assert fetcher.headers["X-Test"] == "hello"
    assert fetcher.headers["Authorization"] == "Bearer abc"
