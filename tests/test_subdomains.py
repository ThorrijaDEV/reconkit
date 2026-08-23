from __future__ import annotations

import json

from reconkit.subdomains import parse_ctsh_json

SAMPLE = json.dumps([
    {"name_value": f"www.example.com\nexample.com", "common_name": "www.example.com"},
    {"name_value": "*.api.example.com", "common_name": "*.api.example.com"},
    {"name_value": "api.example.com", "common_name": "api.example.com"},
    {"name_value": "example.com.evil.net", "common_name": "example.com.evil.net"},
    {"name_value": "notexample.com", "common_name": "notexample.com"},
])


class TestParseCtsh:
    def test_keeps_exact_domain_and_subdomains(self):
        names = set(parse_ctsh_json(SAMPLE, "example.com"))
        assert names == {
            "www.example.com",
            "example.com",
            "api.example.com",
        }

    def test_rejects_suffix_squatting(self):
        names = set(parse_ctsh_json(SAMPLE, "example.com"))
        # A sibling domain and an unrelated look-alike must never match.
        assert "example.com.evil.net" not in names
        assert "notexample.com" not in names

    def test_case_insensitive_dedupe(self):
        data = json.dumps([
            {"name_value": "WWW.Example.com"},
            {"name_value": "www.example.com"},
        ])
        assert parse_ctsh_json(data, "example.com") == ["www.example.com"]
