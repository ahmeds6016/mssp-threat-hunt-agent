"""Tests for FeedIngester — CSV, STIX, and JSON parsing."""

from __future__ import annotations

import json

import pytest

from mssp_hunt_agent.intel.feed_ingester import FeedIngester, detect_ioc_type
from mssp_hunt_agent.intel.models import FeedSource, FeedType


@pytest.fixture
def ingester() -> FeedIngester:
    return FeedIngester()


# ── detect_ioc_type ──────────────────────────────────────────────────


class TestDetectIOCType:
    def test_ipv4(self) -> None:
        assert detect_ioc_type("1.2.3.4") == "ip"
        assert detect_ioc_type("192.168.1.1") == "ip"
        assert detect_ioc_type("255.255.255.255") == "ip"

    def test_domain(self) -> None:
        assert detect_ioc_type("evil.example.com") == "domain"
        assert detect_ioc_type("sub.domain.co.uk") == "domain"

    def test_md5(self) -> None:
        assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash_md5"

    def test_sha256(self) -> None:
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect_ioc_type(h) == "hash_sha256"

    def test_url(self) -> None:
        assert detect_ioc_type("https://evil.com/payload") == "url"
        assert detect_ioc_type("http://bad.site/c2") == "url"

    def test_email(self) -> None:
        assert detect_ioc_type("attacker@evil.com") == "email"

    def test_unknown(self) -> None:
        assert detect_ioc_type("not-an-ioc") is None
        assert detect_ioc_type("") is None


# ── CSV ingestion ────────────────────────────────────────────────────


class TestCSVIngestion:
    def test_basic_csv(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="test-csv", url="http://example.com/feed.csv")
        csv_content = (
            "indicator,type,tags,confidence\n"
            "1.2.3.4,ip,c2,0.9\n"
            "evil.com,domain,phishing,0.7\n"
        )
        result = ingester.ingest(source, csv_content)

        assert result.feed_name == "test-csv"
        assert result.total_parsed == 2
        assert result.valid == 2
        assert result.invalid == 0
        assert len(result.new_iocs) == 2
        assert result.new_iocs[0].ioc_type == "ip"
        assert result.new_iocs[0].value == "1.2.3.4"
        assert result.new_iocs[0].confidence == 0.9

    def test_csv_auto_detect_type(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="auto-csv", url="http://x.com")
        csv_content = "indicator\n192.168.1.1\nevil-domain.com\n"
        result = ingester.ingest(source, csv_content)

        assert result.valid == 2
        assert result.new_iocs[0].ioc_type == "ip"
        assert result.new_iocs[1].ioc_type == "domain"

    def test_csv_deduplicate(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="dup-csv", url="http://x.com")
        csv_content = "indicator\n1.2.3.4\n1.2.3.4\n1.2.3.4\n"
        result = ingester.ingest(source, csv_content)

        assert result.total_parsed == 3
        assert result.valid == 1
        assert result.duplicates == 2

    def test_csv_empty_rows(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="empty-csv", url="http://x.com")
        # DictReader skips blank lines; use rows with empty indicator column
        csv_content = "indicator,type\n,ip\n,domain\n"
        result = ingester.ingest(source, csv_content)

        assert result.total_parsed == 2  # 2 data rows with empty indicator
        assert result.valid == 0
        assert result.invalid == 2

    def test_csv_source_tags_propagated(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="tagged", url="http://x.com", tags=["intel-feed"])
        csv_content = "indicator,tags\n1.2.3.4,extra-tag\n"
        result = ingester.ingest(source, csv_content)

        assert "intel-feed" in result.new_iocs[0].tags
        assert "extra-tag" in result.new_iocs[0].tags

    def test_csv_undetectable_type(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="bad-csv", url="http://x.com")
        csv_content = "indicator\nnot_an_ioc\n"
        result = ingester.ingest(source, csv_content)

        assert result.total_parsed == 1
        assert result.invalid == 1
        assert result.valid == 0


# ── STIX ingestion ───────────────────────────────────────────────────


class TestSTIXIngestion:
    def test_stix_basic(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="stix-feed", url="http://x.com", feed_type=FeedType.STIX)
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[ipv4-addr:value = '10.0.0.1']",
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-06-01T00:00:00Z",
                    "labels": ["malicious-activity"],
                    "confidence": 80,
                },
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "pattern": "[domain-name:value = 'evil.com']",
                    "created": "2024-02-01T00:00:00Z",
                    "confidence": 60,
                },
            ],
        }
        result = ingester.ingest(source, json.dumps(bundle))

        assert result.valid == 2
        assert result.new_iocs[0].ioc_type == "ip"
        assert result.new_iocs[0].value == "10.0.0.1"
        assert result.new_iocs[0].confidence == 0.8
        assert "malicious-activity" in result.new_iocs[0].tags
        assert result.new_iocs[1].ioc_type == "domain"

    def test_stix_skips_non_indicator(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="stix", url="http://x.com", feed_type=FeedType.STIX)
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "malware", "id": "malware--1", "name": "EvilStuff"},
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "pattern": "[ipv4-addr:value = '1.1.1.1']",
                },
            ],
        }
        result = ingester.ingest(source, json.dumps(bundle))

        assert result.total_parsed == 1  # only the indicator
        assert result.valid == 1

    def test_stix_invalid_json(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="stix-bad", url="http://x.com", feed_type=FeedType.STIX)
        result = ingester.ingest(source, "not json")

        assert result.valid == 0
        assert len(result.errors) >= 1

    def test_stix_unparseable_pattern(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="stix", url="http://x.com", feed_type=FeedType.STIX)
        bundle = {
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "pattern": "unparseable pattern",
                },
            ],
        }
        result = ingester.ingest(source, json.dumps(bundle))

        assert result.total_parsed == 1
        assert result.invalid == 1


# ── JSON ingestion ───────────────────────────────────────────────────


class TestJSONIngestion:
    def test_json_list(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="json-feed", url="http://x.com", feed_type=FeedType.JSON)
        data = [
            {"indicator": "1.2.3.4", "type": "ip", "confidence": 0.9},
            {"indicator": "bad.com", "type": "domain"},
        ]
        result = ingester.ingest(source, json.dumps(data))

        assert result.valid == 2
        assert result.new_iocs[0].value == "1.2.3.4"

    def test_json_object_with_indicators_key(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="json-obj", url="http://x.com", feed_type=FeedType.JSON)
        data = {
            "indicators": [
                {"value": "10.0.0.1", "type": "ip"},
            ]
        }
        result = ingester.ingest(source, json.dumps(data))

        assert result.valid == 1

    def test_json_invalid(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="json-bad", url="http://x.com", feed_type=FeedType.JSON)
        result = ingester.ingest(source, "not json")

        assert result.valid == 0
        assert len(result.errors) >= 1

    def test_json_auto_detect(self, ingester: FeedIngester) -> None:
        source = FeedSource(name="json-auto", url="http://x.com", feed_type=FeedType.JSON)
        data = [{"value": "192.168.1.1"}, {"value": "evil.example.com"}]
        result = ingester.ingest(source, json.dumps(data))

        assert result.valid == 2
        assert result.new_iocs[0].ioc_type == "ip"
        assert result.new_iocs[1].ioc_type == "domain"
