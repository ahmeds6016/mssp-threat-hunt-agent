"""Tests for IOC validation, normalization, and deduplication."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.models.ioc_models import IOCEntry, IOCType
from mssp_hunt_agent.pipeline.ioc_intake import defang, process_iocs


class TestDefang:
    def test_defang_domain(self) -> None:
        assert defang("evil[.]com") == "evil.com"

    def test_defang_url(self) -> None:
        assert defang("hxxps://evil[.]com/path") == "https://evil.com/path"

    def test_defang_email(self) -> None:
        assert defang("user[@]evil[.]com") == "user@evil.com"

    def test_no_defang_needed(self) -> None:
        assert defang("10.0.0.1") == "10.0.0.1"


class TestIOCValidation:
    def test_valid_ipv4(self) -> None:
        batch = process_iocs([IOCEntry(value="10.0.0.1", ioc_type=IOCType.IP)])
        assert len(batch.valid) == 1
        assert batch.valid[0].normalized_value == "10.0.0.1"

    def test_valid_ipv6(self) -> None:
        batch = process_iocs([IOCEntry(value="::1", ioc_type=IOCType.IP)])
        assert len(batch.valid) == 1

    def test_invalid_ip(self) -> None:
        batch = process_iocs([IOCEntry(value="not-an-ip", ioc_type=IOCType.IP)])
        assert len(batch.invalid) == 1
        assert not batch.invalid[0].is_valid

    def test_valid_domain(self) -> None:
        batch = process_iocs([IOCEntry(value="evil.example.com", ioc_type=IOCType.DOMAIN)])
        assert len(batch.valid) == 1
        assert batch.valid[0].normalized_value == "evil.example.com"

    def test_domain_normalizes_lowercase(self) -> None:
        batch = process_iocs([IOCEntry(value="Evil.Example.COM", ioc_type=IOCType.DOMAIN)])
        assert batch.valid[0].normalized_value == "evil.example.com"

    def test_defanged_domain(self) -> None:
        batch = process_iocs([IOCEntry(value="evil[.]example[.]com", ioc_type=IOCType.DOMAIN)])
        assert len(batch.valid) == 1
        assert batch.valid[0].normalized_value == "evil.example.com"

    def test_invalid_domain(self) -> None:
        batch = process_iocs([IOCEntry(value="notadomain", ioc_type=IOCType.DOMAIN)])
        assert len(batch.invalid) == 1

    def test_valid_md5(self) -> None:
        batch = process_iocs([
            IOCEntry(value="d41d8cd98f00b204e9800998ecf8427e", ioc_type=IOCType.HASH_MD5)
        ])
        assert len(batch.valid) == 1

    def test_valid_sha256(self) -> None:
        h = "a" * 64
        batch = process_iocs([IOCEntry(value=h, ioc_type=IOCType.HASH_SHA256)])
        assert len(batch.valid) == 1

    def test_invalid_hash_wrong_length(self) -> None:
        batch = process_iocs([IOCEntry(value="abc123", ioc_type=IOCType.HASH_MD5)])
        assert len(batch.invalid) == 1

    def test_valid_email(self) -> None:
        batch = process_iocs([IOCEntry(value="attacker@evil.com", ioc_type=IOCType.EMAIL)])
        assert len(batch.valid) == 1
        assert batch.valid[0].normalized_value == "attacker@evil.com"

    def test_invalid_email(self) -> None:
        batch = process_iocs([IOCEntry(value="not-an-email", ioc_type=IOCType.EMAIL)])
        assert len(batch.invalid) == 1

    def test_valid_url(self) -> None:
        batch = process_iocs([IOCEntry(value="https://evil.com/payload", ioc_type=IOCType.URL)])
        assert len(batch.valid) == 1

    def test_defanged_url(self) -> None:
        batch = process_iocs([
            IOCEntry(value="hxxps://evil[.]com/payload", ioc_type=IOCType.URL)
        ])
        assert len(batch.valid) == 1
        assert batch.valid[0].normalized_value == "https://evil.com/payload"

    def test_invalid_url(self) -> None:
        batch = process_iocs([IOCEntry(value="ftp://something", ioc_type=IOCType.URL)])
        assert len(batch.invalid) == 1

    def test_valid_user_agent(self) -> None:
        batch = process_iocs([
            IOCEntry(value="python-requests/2.31.0", ioc_type=IOCType.USER_AGENT)
        ])
        assert len(batch.valid) == 1


class TestIOCDedup:
    def test_deduplicates_exact_match(self) -> None:
        entries = [
            IOCEntry(value="10.0.0.1", ioc_type=IOCType.IP),
            IOCEntry(value="10.0.0.1", ioc_type=IOCType.IP),
        ]
        batch = process_iocs(entries)
        assert len(batch.valid) == 1
        assert batch.dedup_removed == 1

    def test_different_types_not_deduped(self) -> None:
        entries = [
            IOCEntry(value="example.com", ioc_type=IOCType.DOMAIN),
            IOCEntry(value="example.com", ioc_type=IOCType.USER_AGENT),
        ]
        batch = process_iocs(entries)
        assert len(batch.valid) == 2
        assert batch.dedup_removed == 0


class TestIOCBatchTypeCounts:
    def test_type_counts(self) -> None:
        entries = [
            IOCEntry(value="10.0.0.1", ioc_type=IOCType.IP),
            IOCEntry(value="10.0.0.2", ioc_type=IOCType.IP),
            IOCEntry(value="evil.com", ioc_type=IOCType.DOMAIN),
        ]
        batch = process_iocs(entries)
        assert batch.type_counts["ip"] == 2
        assert batch.type_counts["domain"] == 1


class TestMixedValidInvalid:
    def test_mixed_batch(self) -> None:
        entries = [
            IOCEntry(value="10.0.0.1", ioc_type=IOCType.IP),
            IOCEntry(value="not-valid", ioc_type=IOCType.IP),
            IOCEntry(value="evil.com", ioc_type=IOCType.DOMAIN),
            IOCEntry(value="abc", ioc_type=IOCType.HASH_MD5),
        ]
        batch = process_iocs(entries)
        assert len(batch.valid) == 2
        assert len(batch.invalid) == 2
