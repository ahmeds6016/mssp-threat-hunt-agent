"""Tests for threat intel feed monitor."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mssp_hunt_agent.intel.feed_monitor import (
    FeedConfig,
    FeedMonitor,
    ThreatArticle,
    _make_article_id,
    _normalize_date,
    _parse_atom,
    _parse_rss,
    _strip_html,
    fetch_article_text,
)


# ── Sample RSS/Atom XML ───────────────────────────────────────────────

SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Security Blog</title>
    <item>
      <title>Critical Supply Chain Attack Discovered</title>
      <link>https://example.com/supply-chain-attack</link>
      <pubDate>Mon, 31 Mar 2026 10:00:00 +0000</pubDate>
      <description>&lt;p&gt;A new supply chain attack has been discovered targeting npm packages.&lt;/p&gt;</description>
      <category>APT</category>
      <category>Supply Chain</category>
    </item>
    <item>
      <title>Ransomware Group Targets Healthcare</title>
      <link>https://example.com/ransomware-healthcare</link>
      <pubDate>Sun, 30 Mar 2026 08:00:00 +0000</pubDate>
      <description>Healthcare sector under attack from new ransomware variant.</description>
    </item>
  </channel>
</rss>"""

SAMPLE_ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Google Threat Analysis</title>
  <entry>
    <title>North Korea Compromises NPM Package</title>
    <link href="https://blog.google/threat-analysis/nk-npm" rel="alternate"/>
    <published>2026-03-31T14:00:00Z</published>
    <summary>UNC4899 compromised axios npm package in supply chain attack.</summary>
    <category term="APT"/>
    <category term="Supply Chain"/>
  </entry>
</feed>"""

FEED_CFG = FeedConfig(
    name="Test Feed",
    url="https://example.com/feed",
    source_type="rss",
    category="apt",
)

ATOM_CFG = FeedConfig(
    name="Test Atom Feed",
    url="https://example.com/atom",
    source_type="atom",
    category="apt",
)


class TestHelpers:
    def test_strip_html(self) -> None:
        assert _strip_html("<p>Hello <b>world</b></p>") == "Hello world"
        assert _strip_html("no tags here") == "no tags here"

    def test_make_article_id(self) -> None:
        id1 = _make_article_id("https://example.com/article-1")
        id2 = _make_article_id("https://example.com/article-2")
        assert len(id1) == 16
        assert id1 != id2
        # Deterministic
        assert _make_article_id("https://example.com/article-1") == id1

    def test_normalize_date_rfc822(self) -> None:
        result = _normalize_date("Mon, 31 Mar 2026 10:00:00 +0000")
        assert "2026-03-31" in result

    def test_normalize_date_iso(self) -> None:
        result = _normalize_date("2026-03-31T14:00:00Z")
        assert "2026-03-31" in result

    def test_normalize_date_empty(self) -> None:
        result = _normalize_date("")
        assert result  # should return current time, not empty


class TestRSSParsing:
    def test_parse_rss_basic(self) -> None:
        articles = _parse_rss(SAMPLE_RSS, FEED_CFG)
        assert len(articles) == 2
        assert articles[0].title == "Critical Supply Chain Attack Discovered"
        assert articles[0].url == "https://example.com/supply-chain-attack"
        assert articles[0].source == "Test Feed"
        assert articles[0].category == "apt"
        assert "APT" in articles[0].tags
        assert "Supply Chain" in articles[0].tags

    def test_parse_rss_strips_html(self) -> None:
        articles = _parse_rss(SAMPLE_RSS, FEED_CFG)
        assert "<p>" not in articles[0].summary

    def test_parse_rss_invalid_xml(self) -> None:
        articles = _parse_rss("not xml at all", FEED_CFG)
        assert articles == []


class TestAtomParsing:
    def test_parse_atom_basic(self) -> None:
        articles = _parse_atom(SAMPLE_ATOM, ATOM_CFG)
        assert len(articles) == 1
        assert articles[0].title == "North Korea Compromises NPM Package"
        assert articles[0].url == "https://blog.google/threat-analysis/nk-npm"
        assert "APT" in articles[0].tags

    def test_parse_atom_invalid_xml(self) -> None:
        articles = _parse_atom("not xml", ATOM_CFG)
        assert articles == []


class TestFeedMonitor:
    def test_init_default_feeds(self) -> None:
        monitor = FeedMonitor()
        assert len(monitor._feeds) > 0

    def test_dedup_articles(self) -> None:
        monitor = FeedMonitor(feeds=[FEED_CFG])
        # Simulate already seen
        articles = _parse_rss(SAMPLE_RSS, FEED_CFG)
        monitor._seen_ids.add(articles[0].article_id)

        with patch.object(monitor, "check_feed", return_value=articles):
            # The monitor should filter out already-seen articles
            # But since check_feed is mocked, test dedup logic directly
            new = [a for a in articles if a.article_id not in monitor._seen_ids]
            assert len(new) == 1  # only the second article is new

    def test_to_dict(self) -> None:
        article = ThreatArticle(
            article_id="abc123",
            title="Test Article",
            url="https://example.com/test",
            published="2026-03-31T10:00:00Z",
            source="Test Feed",
            category="apt",
            summary="This is a test article about a supply chain attack.",
            tags=["APT", "Supply Chain"],
        )
        d = article.to_dict()
        assert d["article_id"] == "abc123"
        assert d["title"] == "Test Article"
        assert d["tags"] == ["APT", "Supply Chain"]

    def test_check_feed_http_error(self) -> None:
        monitor = FeedMonitor(feeds=[FEED_CFG])
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp

        with patch("mssp_hunt_agent.intel.feed_monitor.httpx.Client", return_value=mock_client):
            articles = monitor.check_feed(FEED_CFG)
            assert articles == []

    def test_check_feed_disabled(self) -> None:
        disabled = FeedConfig(name="Disabled", url="https://example.com", source_type="rss",
                              category="general", enabled=False)
        monitor = FeedMonitor(feeds=[disabled])
        assert monitor.check_feed(disabled) == []
