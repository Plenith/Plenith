"""Tests for the optional multi-tenancy module."""
from pathlib import Path

import pytest

from plenith.multitenancy import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_READ_ONLY,
    Tenant,
    TenantRegistry,
    filter_engagements_by_tenant,
    state_path_for,
)

# ---------------------------------------------------------------------------
# Registry config parsing
# ---------------------------------------------------------------------------

class TestRegistry:
    def test_disabled_by_default(self):
        reg = TenantRegistry.from_config(None)
        assert reg.enabled is False
        assert reg.tenants == {}

    def test_explicit_disabled_stays_off(self):
        reg = TenantRegistry.from_config({"multitenancy": {"enabled": False}})
        assert reg.enabled is False

    def test_two_tenants_parsed(self):
        cfg = {
            "multitenancy": {
                "enabled": True,
                "tenants": [
                    {
                        "id": "acme",
                        "deployment_id": "dep-acme-001",
                        "state_subdir": "acme/",
                        "tokens": [
                            {"value": "tok-acme-1", "role": "admin"},
                            {"value": "tok-acme-2", "role": "analyst"},
                        ],
                    },
                    {
                        "id": "globex",
                        "deployment_id": "dep-globex-001",
                        "tokens": [
                            {"value": "tok-globex-1", "role": "read_only"},
                        ],
                    },
                ],
            },
        }
        reg = TenantRegistry.from_config(cfg)
        assert reg.enabled is True
        assert set(reg.list_tenants()) == {"acme", "globex"}
        assert reg.get_tenant("acme").deployment_id == "dep-acme-001"

    def test_skips_tokens_without_value(self):
        cfg = {"multitenancy": {"enabled": True, "tenants": [
            {"id": "x", "tokens": [{"role": "admin"}]},
        ]}}
        reg = TenantRegistry.from_config(cfg)
        assert reg.tenants["x"].tokens == []

    def test_skips_invalid_roles(self):
        cfg = {"multitenancy": {"enabled": True, "tenants": [
            {"id": "x", "tokens": [
                {"value": "a", "role": "godmode"},
                {"value": "b", "role": "analyst"},
            ]},
        ]}}
        reg = TenantRegistry.from_config(cfg)
        assert len(reg.tenants["x"].tokens) == 1
        assert reg.tenants["x"].tokens[0].role == "analyst"

    def test_skips_tenants_without_id(self):
        cfg = {"multitenancy": {"enabled": True, "tenants": [
            {"deployment_id": "no-id"},
        ]}}
        reg = TenantRegistry.from_config(cfg)
        assert reg.tenants == {}

    def test_default_state_subdir_uses_id(self):
        cfg = {"multitenancy": {"enabled": True, "tenants": [
            {"id": "x", "tokens": [{"value": "tok", "role": "admin"}]},
        ]}}
        reg = TenantRegistry.from_config(cfg)
        assert reg.tenants["x"].state_subdir == "x/"

# ---------------------------------------------------------------------------
# Token lookup
# ---------------------------------------------------------------------------

class TestTokenLookup:
    @pytest.fixture
    def reg(self):
        return TenantRegistry.from_config({"multitenancy": {
            "enabled": True,
            "tenants": [
                {"id": "acme", "tokens": [
                    {"value": "tok-acme-admin", "role": "admin"},
                    {"value": "tok-acme-soc", "role": "analyst"},
                ]},
                {"id": "globex", "tokens": [
                    {"value": "tok-globex-ro", "role": "read_only"},
                ]},
            ],
        }})

    def test_valid_token_returns_record(self, reg):
        rec = reg.lookup("tok-acme-admin")
        assert rec is not None
        assert rec.tenant_id == "acme"
        assert rec.role == "admin"

    def test_invalid_token_returns_none(self, reg):
        assert reg.lookup("not-a-token") is None
        assert reg.lookup("") is None

    def test_lookup_no_partial_match(self, reg):
        """Constant-time-compare means no partial / prefix matches."""
        assert reg.lookup("tok-acme") is None
        assert reg.lookup("tok-acme-admin-extra") is None

    def test_lookup_disabled_registry_always_none(self):
        reg = TenantRegistry.from_config(None)
        assert reg.lookup("anything") is None

# ---------------------------------------------------------------------------
# Role permits
# ---------------------------------------------------------------------------

class TestRolePermits:
    def test_admin_can_everything(self):
        assert TenantRegistry.can(ROLE_ADMIN, "read")
        assert TenantRegistry.can(ROLE_ADMIN, "action")
        assert TenantRegistry.can(ROLE_ADMIN, "admin")

    def test_analyst_can_read_and_action_only(self):
        assert TenantRegistry.can(ROLE_ANALYST, "read")
        assert TenantRegistry.can(ROLE_ANALYST, "action")
        assert not TenantRegistry.can(ROLE_ANALYST, "admin")

    def test_read_only_can_only_read(self):
        assert TenantRegistry.can(ROLE_READ_ONLY, "read")
        assert not TenantRegistry.can(ROLE_READ_ONLY, "action")
        assert not TenantRegistry.can(ROLE_READ_ONLY, "admin")

    def test_invalid_role_can_nothing(self):
        assert not TenantRegistry.can("godmode", "read")

# ---------------------------------------------------------------------------
# State-path namespacing
# ---------------------------------------------------------------------------

class TestStatePathNamespacing:
    def test_no_tenant_returns_unchanged(self, tmp_path):
        p = state_path_for(None, tmp_path, "192.0.2.99__jdoe.json")
        assert p == tmp_path / "192.0.2.99__jdoe.json"

    def test_tenant_inserts_subdir(self, tmp_path):
        tenant = Tenant(id="acme", state_subdir="acme/")
        p = state_path_for(tenant, tmp_path, "192.0.2.99__jdoe.json")
        assert p == tmp_path / "acme" / "192.0.2.99__jdoe.json"

# ---------------------------------------------------------------------------
# Engagement filtering
# ---------------------------------------------------------------------------

class TestEngagementFiltering:
    def test_no_tenant_returns_all(self):
        engs = [{"engagement_id": "a"}, {"engagement_id": "b"}]
        result = filter_engagements_by_tenant(engs, None)
        assert result == engs

    def test_tenant_filters_by_tag(self):
        engs = [
            {"engagement_id": "a", "_tenant_id": "acme"},
            {"engagement_id": "b", "_tenant_id": "globex"},
            {"engagement_id": "c", "_tenant_id": "acme"},
        ]
        tenant = Tenant(id="acme")
        result = filter_engagements_by_tenant(engs, tenant)
        assert {e["engagement_id"] for e in result} == {"a", "c"}

    def test_no_tenant_tag_excluded_when_filtering(self):
        engs = [{"engagement_id": "a"}]   # no _tenant_id
        tenant = Tenant(id="acme")
        result = filter_engagements_by_tenant(engs, tenant)
        # Untagged engagements aren't visible to any tenant
        assert result == []
