"""Tests for per-client tuning CRUD and exclusion logic."""

from __future__ import annotations

import pytest

from mssp_hunt_agent.analytics.tuning import TuningStore
from mssp_hunt_agent.persistence.database import HuntDatabase


@pytest.fixture
def tuning_store() -> TuningStore:
    db = HuntDatabase(":memory:")
    db.ensure_client("TestCorp")
    return TuningStore(db)


class TestTuningCRUD:
    def test_add_exclusion_rule(self, tuning_store: TuningStore) -> None:
        rule = tuning_store.add_rule(
            client_name="TestCorp",
            rule_type="exclusion",
            pattern="ip:8.8.8.8",
            reason="Google DNS — benign",
        )

        assert rule.rule_id.startswith("TUNE-")
        assert rule.rule_type == "exclusion"
        assert rule.pattern == "ip:8.8.8.8"
        assert rule.reason == "Google DNS — benign"
        assert rule.created_at  # non-empty

    def test_add_benign_pattern(self, tuning_store: TuningStore) -> None:
        rule = tuning_store.add_rule(
            client_name="TestCorp",
            rule_type="benign_pattern",
            pattern="user:svc_*",
            reason="Service accounts",
        )

        assert rule.rule_type == "benign_pattern"

    def test_list_rules(self, tuning_store: TuningStore) -> None:
        tuning_store.add_rule("TestCorp", "exclusion", "ip:1.1.1.1")
        tuning_store.add_rule("TestCorp", "exclusion", "ip:2.2.2.2")
        tuning_store.add_rule("TestCorp", "benign_pattern", "user:svc_*")

        rules = tuning_store.list_rules("TestCorp")
        assert len(rules) == 3

    def test_remove_rule(self, tuning_store: TuningStore) -> None:
        rule = tuning_store.add_rule("TestCorp", "exclusion", "ip:1.1.1.1")
        assert tuning_store.remove_rule(rule.rule_id) is True
        assert len(tuning_store.list_rules("TestCorp")) == 0

    def test_remove_nonexistent(self, tuning_store: TuningStore) -> None:
        assert tuning_store.remove_rule("TUNE-nonexist") is False

    def test_get_config(self, tuning_store: TuningStore) -> None:
        tuning_store.add_rule("TestCorp", "exclusion", "ip:1.1.1.1")
        tuning_store.add_rule("TestCorp", "exclusion", "ip:2.2.2.2")
        tuning_store.add_rule("TestCorp", "benign_pattern", "user:svc_backup")

        config = tuning_store.get_config("TestCorp")

        assert config.client_name == "TestCorp"
        assert len(config.exclusions) == 2
        assert len(config.benign_patterns) == 1

    def test_get_config_empty_client(self, tuning_store: TuningStore) -> None:
        config = tuning_store.get_config("NobodyCorp")

        assert config.client_name == "NobodyCorp"
        assert len(config.exclusions) == 0
        assert len(config.benign_patterns) == 0


class TestExclusionValues:
    def test_get_exclusion_values(self, tuning_store: TuningStore) -> None:
        tuning_store.add_rule("TestCorp", "exclusion", "ip:8.8.8.8")
        tuning_store.add_rule("TestCorp", "exclusion", "domain:google.com")
        tuning_store.add_rule("TestCorp", "benign_pattern", "user:svc_*")

        exclusions = tuning_store.get_exclusion_values("TestCorp")

        assert exclusions == {"ip:8.8.8.8", "domain:google.com"}
        # benign_pattern is NOT included in exclusion values
        assert "user:svc_*" not in exclusions

    def test_empty_exclusions(self, tuning_store: TuningStore) -> None:
        exclusions = tuning_store.get_exclusion_values("TestCorp")
        assert exclusions == set()


class TestClientIsolation:
    def test_rules_scoped_to_client(self, tuning_store: TuningStore) -> None:
        tuning_store.add_rule("TestCorp", "exclusion", "ip:1.1.1.1")
        tuning_store.add_rule("OtherCorp", "exclusion", "ip:2.2.2.2")

        tc_rules = tuning_store.list_rules("TestCorp")
        oc_rules = tuning_store.list_rules("OtherCorp")

        assert len(tc_rules) == 1
        assert tc_rules[0].pattern == "ip:1.1.1.1"
        assert len(oc_rules) == 1
        assert oc_rules[0].pattern == "ip:2.2.2.2"
