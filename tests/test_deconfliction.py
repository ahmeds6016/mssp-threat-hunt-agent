"""Tests for IOC deconfliction logic."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.intel.deconfliction import deconflict
from mssp_hunt_agent.intel.models import NormalizedIOC


def _make_ioc(value: str, ioc_type: str = "ip", **kwargs) -> NormalizedIOC:
    return NormalizedIOC(
        ioc_type=ioc_type,
        value=value,
        source_feed=kwargs.get("source_feed", "test-feed"),
        first_seen=kwargs.get("first_seen", "2024-01-01T00:00:00Z"),
        last_seen=kwargs.get("last_seen", "2024-06-01T00:00:00Z"),
        tags=kwargs.get("tags", []),
        confidence=kwargs.get("confidence", 0.5),
    )


class TestDeconfliction:
    def test_all_new(self) -> None:
        new = [_make_ioc("1.1.1.1"), _make_ioc("2.2.2.2")]
        result = deconflict(new)

        assert result.total_input == 2
        assert len(result.new) == 2
        assert len(result.updated) == 0
        assert len(result.suppressed) == 0
        assert len(result.duplicate_values) == 0

    def test_duplicates_within_batch(self) -> None:
        new = [_make_ioc("1.1.1.1"), _make_ioc("1.1.1.1"), _make_ioc("1.1.1.1")]
        result = deconflict(new)

        assert len(result.new) == 1
        assert len(result.duplicate_values) == 2

    def test_known_benign_suppression(self) -> None:
        new = [_make_ioc("8.8.8.8"), _make_ioc("1.1.1.1")]
        benign = {"8.8.8.8"}
        result = deconflict(new, known_benign=benign)

        assert len(result.suppressed) == 1
        assert "8.8.8.8" in result.suppressed
        assert len(result.new) == 1
        assert result.new[0].value == "1.1.1.1"

    def test_existing_ioc_updated(self) -> None:
        existing = [_make_ioc("1.1.1.1", tags=["old-tag"], confidence=0.3)]
        new = [_make_ioc("1.1.1.1", tags=["new-tag"], confidence=0.8,
                         last_seen="2024-12-01T00:00:00Z")]
        result = deconflict(new, existing_iocs=existing)

        assert len(result.new) == 0
        assert len(result.updated) == 1
        updated = result.updated[0]
        assert updated.value == "1.1.1.1"
        assert updated.confidence == 0.8  # took the higher
        assert "old-tag" in updated.tags
        assert "new-tag" in updated.tags
        assert updated.last_seen == "2024-12-01T00:00:00Z"
        assert updated.first_seen == "2024-01-01T00:00:00Z"  # kept original

    def test_mixed_scenario(self) -> None:
        existing = [_make_ioc("2.2.2.2")]
        benign = {"3.3.3.3"}
        new = [
            _make_ioc("1.1.1.1"),  # new
            _make_ioc("2.2.2.2"),  # update
            _make_ioc("3.3.3.3"),  # suppressed
            _make_ioc("1.1.1.1"),  # duplicate in batch
        ]
        result = deconflict(new, existing_iocs=existing, known_benign=benign)

        assert len(result.new) == 1
        assert len(result.updated) == 1
        assert len(result.suppressed) == 1
        assert len(result.duplicate_values) == 1

    def test_empty_input(self) -> None:
        result = deconflict([])

        assert result.total_input == 0
        assert len(result.new) == 0

    def test_all_suppressed(self) -> None:
        new = [_make_ioc("10.0.0.1"), _make_ioc("10.0.0.2")]
        benign = {"10.0.0.1", "10.0.0.2"}
        result = deconflict(new, known_benign=benign)

        assert len(result.new) == 0
        assert len(result.suppressed) == 2

    def test_whitespace_handling(self) -> None:
        new = [_make_ioc("1.1.1.1"), _make_ioc(" 1.1.1.1 ")]
        # The second has whitespace in the value itself
        # (NormalizedIOC stores as-is, but deconflict strips)
        result = deconflict(new)

        # Both values strip to "1.1.1.1" in deconflict
        assert len(result.new) == 1
        assert len(result.duplicate_values) == 1
