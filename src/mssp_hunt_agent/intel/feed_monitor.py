"""Threat Intel Feed Monitor — checks RSS/Atom feeds for new reports.

Monitors security research blogs, CERT advisories, and threat intel sources
for new publications. Tracks last-seen timestamps per feed to avoid
re-processing. Stores raw articles in blob storage for downstream processing.

Supported feeds:
    - RSS 2.0 (most blogs, CISA, US-CERT)
    - Atom (Google blogs, some research outlets)

Usage:
    monitor = FeedMonitor(blob_store=store)
    new_articles = monitor.check_all_feeds()
    # Returns list of ThreatArticle objects for newly discovered reports
"""

from __future__ import annotations

import hashlib
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ── Feed Configuration ────────────────────────────────────────────────

@dataclass
class FeedConfig:
    """Configuration for a single threat intel RSS/Atom feed."""
    name: str
    url: str
    source_type: str  # "rss" or "atom"
    category: str  # "apt", "vulnerability", "advisory", "supply_chain", "general"
    enabled: bool = True
    priority: int = 1  # 1=highest, 3=lowest


# Default feeds — free, no API keys required
DEFAULT_FEEDS: list[FeedConfig] = [
    # ── Tier 1: Major Threat Intel Vendors ─────────────────────────
    FeedConfig(
        name="Google Threat Analysis Group",
        url="https://blog.google/threat-analysis-group/rss/",
        source_type="rss",
        category="apt",
        priority=1,
    ),
    FeedConfig(
        name="Microsoft Security Blog",
        url="https://www.microsoft.com/en-us/security/blog/feed/",
        source_type="rss",
        category="general",
        priority=1,
    ),
    FeedConfig(
        name="SentinelOne Labs",
        url="https://www.sentinelone.com/labs/feed/",
        source_type="rss",
        category="apt",
        priority=1,
    ),
    FeedConfig(
        name="Palo Alto Unit 42",
        url="https://unit42.paloaltonetworks.com/feed/",
        source_type="rss",
        category="apt",
        priority=1,
    ),
    # ── Tier 2: Security Research ──────────────────────────────────
    FeedConfig(
        name="The DFIR Report",
        url="https://thedfirreport.com/feed/",
        source_type="rss",
        category="apt",
        priority=2,
    ),
    FeedConfig(
        name="ESET Research",
        url="https://www.welivesecurity.com/en/rss/feed/",
        source_type="rss",
        category="apt",
        priority=2,
    ),
    FeedConfig(
        name="Elastic Security Labs",
        url="https://www.elastic.co/security-labs/rss/feed.xml",
        source_type="rss",
        category="apt",
        priority=2,
    ),
    FeedConfig(
        name="Recorded Future / The Record",
        url="https://therecord.media/feed/",
        source_type="rss",
        category="apt",
        priority=2,
    ),
    FeedConfig(
        name="Securelist by Kaspersky",
        url="https://securelist.com/feed/",
        source_type="rss",
        category="apt",
        priority=2,
    ),
    FeedConfig(
        name="CrowdStrike Blog",
        url="https://www.crowdstrike.com/blog/feed/",
        source_type="rss",
        category="apt",
        priority=2,
    ),
    # ── Tier 3: News & General ─────────────────────────────────────
    FeedConfig(
        name="Krebs on Security",
        url="https://krebsonsecurity.com/feed/",
        source_type="rss",
        category="general",
        priority=3,
    ),
    FeedConfig(
        name="BleepingComputer",
        url="https://www.bleepingcomputer.com/feed/",
        source_type="rss",
        category="general",
        priority=3,
    ),
    FeedConfig(
        name="The Hacker News",
        url="https://feeds.feedburner.com/TheHackersNews",
        source_type="rss",
        category="general",
        priority=3,
    ),
    FeedConfig(
        name="Dark Reading",
        url="https://www.darkreading.com/rss.xml",
        source_type="rss",
        category="general",
        priority=3,
    ),
]


# ── Data Models ───────────────────────────────────────────────────────

@dataclass
class ThreatArticle:
    """A single threat intelligence article parsed from a feed."""
    article_id: str  # SHA256 of URL for dedup
    title: str
    url: str
    published: str  # ISO-8601
    source: str  # feed name
    category: str
    summary: str  # first ~2000 chars of description/content
    full_text: str = ""  # full article text if fetched
    tags: list[str] = field(default_factory=list)
    relevance_score: float = 0.0  # set by relevance scorer later
    processed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "article_id": self.article_id,
            "title": self.title,
            "url": self.url,
            "published": self.published,
            "source": self.source,
            "category": self.category,
            "summary": self.summary[:2000],
            "tags": self.tags,
            "relevance_score": self.relevance_score,
            "processed": self.processed,
        }


# ── Feed Parser ───────────────────────────────────────────────────────

def _make_article_id(url: str) -> str:
    """Generate a stable article ID from URL."""
    return hashlib.sha256(url.encode()).hexdigest()[:16]


def _strip_html(text: str) -> str:
    """Remove HTML tags from text."""
    return re.sub(r"<[^>]+>", "", text).strip()


def _parse_rss(xml_text: str, feed_config: FeedConfig) -> list[ThreatArticle]:
    """Parse RSS 2.0 feed XML into ThreatArticle objects."""
    articles = []
    try:
        root = ET.fromstring(xml_text)
        channel = root.find("channel")
        if channel is None:
            return articles

        for item in channel.findall("item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub_date = (item.findtext("pubDate") or "").strip()
            description = _strip_html(item.findtext("description") or "")

            # Extract categories/tags
            tags = [cat.text for cat in item.findall("category") if cat.text]

            if not link:
                continue

            articles.append(ThreatArticle(
                article_id=_make_article_id(link),
                title=title,
                url=link,
                published=_normalize_date(pub_date),
                source=feed_config.name,
                category=feed_config.category,
                summary=description[:2000],
                tags=tags,
            ))
    except ET.ParseError as exc:
        logger.warning("RSS parse error for %s: %s", feed_config.name, exc)

    return articles


def _parse_atom(xml_text: str, feed_config: FeedConfig) -> list[ThreatArticle]:
    """Parse Atom feed XML into ThreatArticle objects."""
    articles = []
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    try:
        root = ET.fromstring(xml_text)

        for entry in root.findall("atom:entry", ns):
            title = (entry.findtext("atom:title", namespaces=ns) or "").strip()

            # Atom links use <link href="..." rel="alternate"/>
            link = ""
            for link_el in entry.findall("atom:link", ns):
                rel = link_el.get("rel", "alternate")
                if rel == "alternate":
                    link = link_el.get("href", "")
                    break
            if not link:
                # Fallback to first link
                link_el = entry.find("atom:link", ns)
                if link_el is not None:
                    link = link_el.get("href", "")

            published = (entry.findtext("atom:published", namespaces=ns)
                         or entry.findtext("atom:updated", namespaces=ns) or "").strip()

            # Content or summary
            content = _strip_html(
                entry.findtext("atom:content", namespaces=ns)
                or entry.findtext("atom:summary", namespaces=ns)
                or ""
            )

            tags = [cat.get("term", "") for cat in entry.findall("atom:category", ns)
                    if cat.get("term")]

            if not link:
                continue

            articles.append(ThreatArticle(
                article_id=_make_article_id(link),
                title=title,
                url=link,
                published=_normalize_date(published),
                source=feed_config.name,
                category=feed_config.category,
                summary=content[:2000],
                tags=tags,
            ))
    except ET.ParseError as exc:
        logger.warning("Atom parse error for %s: %s", feed_config.name, exc)

    return articles


def _normalize_date(date_str: str) -> str:
    """Try to normalize various date formats to ISO-8601."""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()

    # Common RSS date formats
    for fmt in [
        "%a, %d %b %Y %H:%M:%S %z",  # RFC 822
        "%a, %d %b %Y %H:%M:%S %Z",
        "%Y-%m-%dT%H:%M:%S%z",  # ISO 8601
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]:
        try:
            dt = datetime.strptime(date_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue

    return date_str  # return as-is if can't parse


# ── Article Full-Text Fetcher ─────────────────────────────────────────

def fetch_article_text(url: str, timeout: int = 20) -> str:
    """Fetch article content from URL, preserving structure for LLM extraction.

    Removes navigation/scripts/styles but preserves code blocks, tables,
    and list structure so GPT-5.3 can extract IOCs from formatted content.
    Returns up to 15000 chars.
    """
    try:
        client = httpx.Client(timeout=timeout, follow_redirects=True)
        resp = client.get(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml",
        })
        client.close()

        if resp.status_code != 200:
            logger.warning("Failed to fetch %s: HTTP %d", url, resp.status_code)
            return ""

        html = resp.content.decode("utf-8", errors="replace")

        # Remove non-content blocks
        html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<nav[^>]*>.*?</nav>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<header[^>]*>.*?</header>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<footer[^>]*>.*?</footer>", "", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<!--.*?-->", "", html, flags=re.DOTALL)

        # Convert structural HTML to text markers that GPT can read
        # Preserve code blocks
        html = re.sub(r"<pre[^>]*>(.*?)</pre>", r"\n```\n\1\n```\n", html, flags=re.DOTALL | re.IGNORECASE)
        html = re.sub(r"<code[^>]*>(.*?)</code>", r"`\1`", html, flags=re.DOTALL | re.IGNORECASE)

        # Preserve table structure
        html = re.sub(r"<tr[^>]*>", "\n| ", html, flags=re.IGNORECASE)
        html = re.sub(r"<t[dh][^>]*>(.*?)</t[dh]>", r"\1 | ", html, flags=re.DOTALL | re.IGNORECASE)

        # Preserve list items
        html = re.sub(r"<li[^>]*>", "\n- ", html, flags=re.IGNORECASE)

        # Preserve headings
        html = re.sub(r"<h[1-6][^>]*>(.*?)</h[1-6]>", r"\n## \1\n", html, flags=re.DOTALL | re.IGNORECASE)

        # Preserve paragraphs as line breaks
        html = re.sub(r"<p[^>]*>", "\n", html, flags=re.IGNORECASE)
        html = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)

        # Strip remaining HTML tags
        text = _strip_html(html)

        # Collapse excessive whitespace but keep structure
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]+", " ", text)
        text = text.strip()

        return text[:15000]

    except Exception as exc:
        logger.warning("Failed to fetch article text from %s: %s", url, exc)
        return ""


# ── Feed Monitor ──────────────────────────────────────────────────────

class FeedMonitor:
    """Monitors threat intel RSS/Atom feeds for new articles.

    Tracks seen article IDs to avoid re-processing. Persists state
    to blob storage for durability across restarts.
    """

    def __init__(
        self,
        feeds: list[FeedConfig] | None = None,
        blob_store: Any | None = None,
    ) -> None:
        self._feeds = feeds or DEFAULT_FEEDS
        self._blob = blob_store
        self._seen_ids: set[str] = set()
        self._load_seen_ids()

    def _load_seen_ids(self) -> None:
        """Load previously seen article IDs from blob storage."""
        if not self._blob:
            return
        try:
            data = self._blob._download_json("intel-feeds/seen_ids.json")
            if data and isinstance(data.get("ids"), list):
                self._seen_ids = set(data["ids"])
                logger.info("Loaded %d seen article IDs", len(self._seen_ids))
        except Exception as exc:
            logger.debug("No existing seen IDs: %s", exc)

    def _save_seen_ids(self) -> None:
        """Persist seen article IDs to blob storage."""
        if not self._blob:
            return
        try:
            # Keep last 5000 IDs to prevent unbounded growth
            ids = list(self._seen_ids)[-5000:]
            self._blob._upload_json("intel-feeds/seen_ids.json", {
                "ids": ids,
                "count": len(ids),
                "updated": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as exc:
            logger.warning("Failed to save seen IDs: %s", exc)

    def check_feed(self, feed: FeedConfig) -> list[ThreatArticle]:
        """Check a single feed for new articles."""
        if not feed.enabled:
            return []

        logger.info("Checking feed: %s (%s)", feed.name, feed.url)
        try:
            client = httpx.Client(timeout=20, follow_redirects=True)
            resp = client.get(feed.url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
            })
            client.close()

            if resp.status_code != 200:
                logger.warning("Feed %s returned HTTP %d", feed.name, resp.status_code)
                return []

            # Use bytes decoding to avoid Windows charmap issues
            xml_text = resp.content.decode("utf-8", errors="replace")

            # Verify we got XML, not HTML (some feeds return HTML on error)
            if xml_text.lstrip().startswith("<!doctype html") or xml_text.lstrip().startswith("<!DOCTYPE html"):
                logger.warning("Feed %s returned HTML instead of XML", feed.name)
                return []

            # Parse based on feed type — try both parsers if primary fails
            if feed.source_type == "atom":
                articles = _parse_atom(xml_text, feed)
                if not articles:
                    articles = _parse_rss(xml_text, feed)
            else:
                articles = _parse_rss(xml_text, feed)
                if not articles:
                    articles = _parse_atom(xml_text, feed)

            # Filter to only new articles
            new_articles = []
            for article in articles:
                if article.article_id not in self._seen_ids:
                    new_articles.append(article)
                    self._seen_ids.add(article.article_id)

            logger.info(
                "Feed %s: %d total, %d new articles",
                feed.name, len(articles), len(new_articles),
            )
            return new_articles

        except Exception as exc:
            logger.warning("Failed to check feed %s: %s", feed.name, exc)
            return []

    def check_all_feeds(self, fetch_full_text: bool = False) -> list[ThreatArticle]:
        """Check all enabled feeds for new articles.

        Args:
            fetch_full_text: If True, fetch the full article text for each new article.
                            Adds ~1-3 seconds per article but gives LLM better context.

        Returns:
            List of new ThreatArticle objects, sorted by priority then date.
        """
        all_new: list[ThreatArticle] = []

        for feed in self._feeds:
            new_articles = self.check_feed(feed)
            all_new.extend(new_articles)

        # Fetch full text if requested
        if fetch_full_text:
            for article in all_new:
                article.full_text = fetch_article_text(article.url)

        # Save seen IDs to blob
        self._save_seen_ids()

        # Save raw articles to blob
        if self._blob and all_new:
            self._save_articles(all_new)

        # Sort by feed priority, then by published date (newest first)
        feed_priority = {f.name: f.priority for f in self._feeds}
        all_new.sort(key=lambda a: (feed_priority.get(a.source, 99), a.published), reverse=False)

        logger.info("Feed monitor complete: %d new articles across %d feeds", len(all_new), len(self._feeds))
        return all_new

    def _save_articles(self, articles: list[ThreatArticle]) -> None:
        """Save raw articles to blob storage for audit trail."""
        if not self._blob:
            return
        try:
            ts = datetime.now(timezone.utc).strftime("%Y%m%d")
            batch = {
                "date": ts,
                "count": len(articles),
                "articles": [a.to_dict() for a in articles],
            }
            self._blob._upload_json(f"intel-feeds/batches/{ts}.json", batch)
            logger.info("Saved %d articles to blob", len(articles))
        except Exception as exc:
            logger.warning("Failed to save articles to blob: %s", exc)

    def get_recent_articles(self, days: int = 7) -> list[ThreatArticle]:
        """Load recent articles from blob storage."""
        if not self._blob:
            return []
        try:
            from datetime import timedelta
            articles = []
            now = datetime.now(timezone.utc)
            for day_offset in range(days):
                date = (now - timedelta(days=day_offset)).strftime("%Y%m%d")
                data = self._blob._download_json(f"intel-feeds/batches/{date}.json")
                if data and data.get("articles"):
                    for a in data["articles"]:
                        articles.append(ThreatArticle(
                            article_id=a["article_id"],
                            title=a["title"],
                            url=a["url"],
                            published=a["published"],
                            source=a["source"],
                            category=a["category"],
                            summary=a["summary"],
                            tags=a.get("tags", []),
                            relevance_score=a.get("relevance_score", 0),
                            processed=a.get("processed", False),
                        ))
            return articles
        except Exception as exc:
            logger.warning("Failed to load recent articles: %s", exc)
            return []
