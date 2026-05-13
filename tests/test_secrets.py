"""Tests for the secrets resolver.

Covers:
  - URI parsing (scheme / spec / params / fragment / defaults)
  - Each built-in provider end-to-end (env / file)
  - Lazy import behavior for vault / aws-sm (no hard dep)
  - `resolve()` recursion across nested dicts + lists
  - Plaintext values pass through unchanged
  - Unknown schemes are treated as plaintext (NOT errors)
  - SecretResolutionError carries the field path
  - `default=` query parameter triggers fallback
  - `find_references` enumeration
  - `redact` masking heuristic
  - `register_provider` accepts + dispatches custom schemes
  - `secrets_check.py` CLI: list mode + resolve mode + JSON
  - Integration: yaml.safe_load → resolve → dict shape preserved
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from unittest import mock

import pytest
import yaml

from plenith.secrets import (
    SecretResolutionError,
    find_references,
    redact,
    register_provider,
    registered_schemes,
    resolve,
    _parse_reference,
    _provider_env,
    _provider_file,
)


# ---------------------------------------------------------------------------
# URI parsing
# ---------------------------------------------------------------------------

class TestParseReference:
    def test_simple_env(self):
        scheme, spec, params = _parse_reference("env://MY_VAR")
        assert scheme == "env"
        assert spec == "MY_VAR"
        assert params == {}

    def test_with_query_param(self):
        scheme, spec, params = _parse_reference("env://MY_VAR?default=foo")
        assert scheme == "env"
        assert spec == "MY_VAR"
        assert params == {"default": ["foo"]}

    def test_with_fragment(self):
        scheme, spec, params = _parse_reference(
            "vault://secret/data/x#token"
        )
        assert scheme == "vault"
        assert spec == "secret/data/x"
        assert params == {"_fragment": ["token"]}

    def test_with_query_and_fragment(self):
        scheme, spec, params = _parse_reference(
            "vault://path?default=foo#key"
        )
        assert scheme == "vault"
        assert spec == "path"
        assert params == {"default": ["foo"], "_fragment": ["key"]}

    def test_plaintext_returns_none(self):
        assert _parse_reference("just a string") is None
        assert _parse_reference("sk-real-token-not-a-reference") is None

    def test_unknown_scheme_returns_none(self):
        """An http URL is not a secret reference; we let it pass."""
        assert _parse_reference("https://example.com/api") is None
        assert _parse_reference("redis://localhost:6379") is None

    def test_aws_sm_dash_in_scheme(self):
        """aws-sm has a hyphen — make sure the scheme regex accepts it."""
        scheme, spec, _ = _parse_reference("aws-sm://prod/secret#key")
        assert scheme == "aws-sm"
        assert spec == "prod/secret"


# ---------------------------------------------------------------------------
# Built-in: env://
# ---------------------------------------------------------------------------

class TestEnvProvider:
    def test_resolves_set_var(self, monkeypatch):
        monkeypatch.setenv("PLENITH_TEST_KEY", "shh-secret")
        assert resolve("env://PLENITH_TEST_KEY") == "shh-secret"

    def test_unset_var_raises(self, monkeypatch):
        monkeypatch.delenv("PLENITH_NOPE", raising=False)
        with pytest.raises(SecretResolutionError, match="not set"):
            resolve("env://PLENITH_NOPE")

    def test_default_fallback(self, monkeypatch):
        monkeypatch.delenv("PLENITH_NOPE", raising=False)
        assert resolve("env://PLENITH_NOPE?default=fallback") == "fallback"

    def test_set_var_wins_over_default(self, monkeypatch):
        monkeypatch.setenv("PLENITH_TEST_K", "from-env")
        assert resolve("env://PLENITH_TEST_K?default=fallback") == "from-env"

    def test_error_includes_field_path(self, monkeypatch):
        monkeypatch.delenv("PLENITH_NOPE", raising=False)
        with pytest.raises(SecretResolutionError) as exc:
            resolve({"llm": {"api_key": "env://PLENITH_NOPE"}})
        assert "llm.api_key" in str(exc.value)


# ---------------------------------------------------------------------------
# Built-in: file://
# ---------------------------------------------------------------------------

class TestFileProvider:
    def test_reads_file(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("hunter2\n", encoding="utf-8")
        # Use POSIX path even on Windows for URI legibility
        assert resolve(f"file://{secret}") == "hunter2"

    def test_strips_single_trailing_newline_by_default(self, tmp_path):
        f = tmp_path / "s"
        f.write_text("value\n", encoding="utf-8")
        assert resolve(f"file://{f}") == "value"

    def test_strip_false_preserves_newlines(self, tmp_path):
        f = tmp_path / "s"
        f.write_text("value\n", encoding="utf-8")
        assert resolve(f"file://{f}?strip=false") == "value\n"

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(SecretResolutionError, match="could not read"):
            resolve(f"file://{tmp_path}/nope")

    def test_missing_file_with_default(self, tmp_path):
        assert resolve(f"file://{tmp_path}/nope?default=fb") == "fb"


# ---------------------------------------------------------------------------
# Lazy-import behavior: vault / aws-sm without their libs
# ---------------------------------------------------------------------------

class TestLazyImports:
    """The big claim of this module: you don't need hvac or boto3 unless
    you actually use them. These tests assert that the error message is
    helpful (not a bare ImportError) when the lib isn't installed."""

    def test_vault_without_hvac_returns_clear_error(self, monkeypatch):
        """If hvac isn't installed, calling vault:// must raise a
        SecretResolutionError that names the missing package."""
        # Simulate hvac import failing
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name == "hvac":
                raise ImportError("No module named 'hvac'")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(SecretResolutionError, match="hvac"):
            resolve("vault://secret/data/foo#k")

    def test_aws_sm_without_boto3_returns_clear_error(self, monkeypatch):
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *a, **kw):
            if name in ("boto3", "botocore", "botocore.exceptions"):
                raise ImportError(f"No module named {name!r}")
            return real_import(name, *a, **kw)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(SecretResolutionError, match="boto3"):
            resolve("aws-sm://prod/foo#k")


# ---------------------------------------------------------------------------
# Vault provider — mock the hvac client
# ---------------------------------------------------------------------------

class TestVaultProvider:
    def _install_fake_hvac(self, monkeypatch, *, response):
        """Make `import hvac` produce a stub that returns `response`
        from kv.v2.read_secret_version."""
        fake_module = mock.MagicMock()
        fake_client = mock.MagicMock()
        fake_client.secrets.kv.v2.read_secret_version.return_value = response
        fake_module.Client.return_value = fake_client
        monkeypatch.setitem(sys.modules, "hvac", fake_module)
        return fake_client

    def test_resolves_field(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
        monkeypatch.setenv("VAULT_TOKEN", "test-token")
        self._install_fake_hvac(monkeypatch, response={
            "data": {"data": {"token": "real-splunk-token"}},
        })
        out = resolve("vault://secret/data/plenith/splunk#token")
        assert out == "real-splunk-token"

    def test_missing_fragment_raises(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "http://v")
        monkeypatch.setenv("VAULT_TOKEN", "t")
        self._install_fake_hvac(monkeypatch, response={
            "data": {"data": {"token": "x"}},
        })
        with pytest.raises(SecretResolutionError, match="fragment"):
            resolve("vault://secret/data/foo")

    def test_missing_env_vars_raises(self, monkeypatch):
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)
        self._install_fake_hvac(monkeypatch, response={})
        with pytest.raises(SecretResolutionError, match="VAULT_ADDR"):
            resolve("vault://path#k")

    def test_missing_key_in_secret(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "http://v")
        monkeypatch.setenv("VAULT_TOKEN", "t")
        self._install_fake_hvac(monkeypatch, response={
            "data": {"data": {"other_key": "x"}},
        })
        with pytest.raises(SecretResolutionError, match="not found"):
            resolve("vault://path#missing_key")


# ---------------------------------------------------------------------------
# AWS Secrets Manager — mock boto3
# ---------------------------------------------------------------------------

class TestAwsSmProvider:
    def _install_fake_boto3(self, monkeypatch, *, response):
        fake_boto3 = mock.MagicMock()
        fake_client = mock.MagicMock()
        fake_client.get_secret_value.return_value = response
        fake_boto3.client.return_value = fake_client
        # Install both boto3 and a stub botocore.exceptions
        monkeypatch.setitem(sys.modules, "boto3", fake_boto3)
        fake_botocore = mock.MagicMock()
        fake_botocore.exceptions.BotoCoreError = Exception
        fake_botocore.exceptions.ClientError = Exception
        monkeypatch.setitem(sys.modules, "botocore", fake_botocore)
        monkeypatch.setitem(sys.modules, "botocore.exceptions",
                              fake_botocore.exceptions)
        return fake_client

    def test_resolves_plain_string_secret(self, monkeypatch):
        self._install_fake_boto3(monkeypatch, response={
            "SecretString": "plain-token-value",
        })
        assert resolve("aws-sm://prod/plenith/api") == "plain-token-value"

    def test_resolves_keyed_json_secret(self, monkeypatch):
        self._install_fake_boto3(monkeypatch, response={
            "SecretString": '{"token": "from-json", "other": "ignored"}',
        })
        out = resolve("aws-sm://prod/plenith/splunk#token")
        assert out == "from-json"

    def test_missing_json_key(self, monkeypatch):
        self._install_fake_boto3(monkeypatch, response={
            "SecretString": '{"only": "value"}',
        })
        with pytest.raises(SecretResolutionError, match="not in"):
            resolve("aws-sm://prod/foo#missing")

    def test_binary_secret_rejected(self, monkeypatch):
        self._install_fake_boto3(monkeypatch, response={
            # No SecretString — binary only
            "SecretBinary": b"\x00\x01\x02",
        })
        with pytest.raises(SecretResolutionError, match="binary secrets"):
            resolve("aws-sm://prod/foo")


# ---------------------------------------------------------------------------
# resolve() — tree walk
# ---------------------------------------------------------------------------

class TestResolveWalk:
    def test_dict_recursion(self, monkeypatch):
        monkeypatch.setenv("X", "x-value")
        cfg = {"a": {"b": "env://X", "c": "plain"}}
        out = resolve(cfg)
        assert out == {"a": {"b": "x-value", "c": "plain"}}

    def test_list_recursion(self, monkeypatch):
        monkeypatch.setenv("T1", "t1")
        monkeypatch.setenv("T2", "t2")
        cfg = {"tokens": ["env://T1", "plain", "env://T2"]}
        out = resolve(cfg)
        assert out == {"tokens": ["t1", "plain", "t2"]}

    def test_does_not_mutate_input(self, monkeypatch):
        monkeypatch.setenv("X", "x")
        cfg = {"a": "env://X", "b": ["env://X", "static"]}
        snapshot = json.dumps(cfg, sort_keys=True)
        resolve(cfg)
        assert json.dumps(cfg, sort_keys=True) == snapshot

    def test_non_string_scalars_pass_through(self):
        cfg = {"n": 42, "f": 3.14, "b": True, "z": None}
        assert resolve(cfg) == cfg

    def test_plaintext_only_no_changes(self):
        cfg = {"foo": "bar", "deep": {"baz": "qux"}}
        assert resolve(cfg) == cfg

    def test_https_url_not_treated_as_reference(self):
        """A field that looks like a URL but isn't a registered scheme
        should pass through plaintext."""
        cfg = {"endpoint": "https://example.com/api/v1"}
        assert resolve(cfg) == cfg

    def test_cache_avoids_duplicate_backend_calls(self, monkeypatch):
        """If the same URI appears twice, the provider should be called
        only once. Without caching, Vault / AWS would be hit
        unnecessarily."""
        calls = []

        def counting_provider(spec, params):
            calls.append(spec)
            return "v"

        register_provider("xtest1", counting_provider)
        try:
            cfg = {"a": "xtest1://foo", "b": "xtest1://foo"}
            out = resolve(cfg)
            assert out == {"a": "v", "b": "v"}
            assert calls == ["foo"]    # one call, not two
        finally:
            register_provider("xtest1",
                                lambda s, p: (_ for _ in ()).throw(
                                    RuntimeError("removed")))


# ---------------------------------------------------------------------------
# find_references
# ---------------------------------------------------------------------------

class TestFindReferences:
    def test_returns_field_path_and_uri_pairs(self):
        cfg = {
            "llm": {"api_key": "env://LLM_KEY"},
            "connectors": [
                {"hec_token": "vault://x#k"},
            ],
            "static": "plain",
        }
        refs = find_references(cfg)
        assert ("llm.api_key", "env://LLM_KEY") in refs
        # Lists use bracket notation
        assert ("connectors[0].hec_token", "vault://x#k") in refs
        # Plaintext not included
        assert all("plain" not in r[1] for r in refs)

    def test_empty_config(self):
        assert find_references({}) == []

    def test_does_not_resolve(self, monkeypatch):
        """find_references must NOT call into provider backends — that's
        the point of having a list mode separate from resolve mode."""
        monkeypatch.delenv("MISSING", raising=False)
        cfg = {"a": "env://MISSING"}
        # Should not raise even though env var is unset
        refs = find_references(cfg)
        assert refs == [("a", "env://MISSING")]


# ---------------------------------------------------------------------------
# redact
# ---------------------------------------------------------------------------

class TestRedact:
    def test_masks_token_field(self):
        out = redact({"api_token": "real-token-value"})
        assert out == {"api_token": "***REDACTED***"}

    def test_masks_password_field(self):
        out = redact({"password": "hunter2"})
        assert out == {"password": "***REDACTED***"}

    def test_does_not_mask_non_sensitive(self):
        out = redact({"hostname": "real-host.example"})
        assert out == {"hostname": "real-host.example"}

    def test_recurses_into_nested(self):
        out = redact({"llm": {"api_key": "x"}, "host": "y"})
        assert out == {"llm": {"api_key": "***REDACTED***"}, "host": "y"}

    def test_reference_form_not_redacted(self):
        """env://VAR isn't the secret value — the env var name is fine
        to surface in logs."""
        out = redact({"api_key": "env://LLM_KEY"})
        assert out["api_key"] == "env://LLM_KEY"


# ---------------------------------------------------------------------------
# Custom provider registration
# ---------------------------------------------------------------------------

class TestRegisterProvider:
    def test_register_and_resolve(self):
        def myprov(spec, params):
            return f"got-{spec}"
        register_provider("xtest2", myprov)
        try:
            assert resolve("xtest2://hello") == "got-hello"
            assert "xtest2" in registered_schemes()
        finally:
            register_provider("xtest2",
                                lambda s, p: (_ for _ in ()).throw(
                                    RuntimeError("removed")))

    def test_invalid_scheme_rejected(self):
        with pytest.raises(ValueError, match="invalid scheme"):
            register_provider("BAD UPPER", lambda s, p: "")
        with pytest.raises(ValueError, match="invalid scheme"):
            register_provider("with_underscore", lambda s, p: "")

    def test_provider_exception_wrapped_with_path(self):
        def boom(spec, params):
            raise RuntimeError("kaboom")
        register_provider("xtest3", boom)
        try:
            with pytest.raises(SecretResolutionError, match="provider error"):
                resolve({"deeply": {"nested": "xtest3://x"}})
        finally:
            register_provider("xtest3",
                                lambda s, p: (_ for _ in ()).throw(
                                    RuntimeError("removed")))


# ---------------------------------------------------------------------------
# CLI: tools/secrets_check.py
# ---------------------------------------------------------------------------

def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "secrets_check_cli",
        Path(__file__).resolve().parent.parent / "tools" / "secrets_check.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestSecretsCheckCLI:
    def test_list_mode_no_backend_calls(self, tmp_path, capsys):
        """The default (list-only) mode does not touch backends, so it
        works even if env vars are unset."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.safe_dump({
            "llm": {"api_key": "env://UNSET_VAR"},
            "plain": "value",
        }), encoding="utf-8")
        cli = _load_cli()
        rc = cli.main(["--config", str(cfg), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        assert out["reference_count"] == 1
        assert out["references"][0]["path"] == "llm.api_key"

    def test_resolve_mode_succeeds(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("CHECK_TEST_VAR", "value")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.safe_dump({
            "llm": {"api_key": "env://CHECK_TEST_VAR"},
        }), encoding="utf-8")
        cli = _load_cli()
        rc = cli.main(["--config", str(cfg), "--resolve", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        assert out["resolved"] == 1
        assert out["failed"] == 0

    def test_resolve_mode_fails_loud(self, tmp_path, capsys, monkeypatch):
        monkeypatch.delenv("MISSING_TEST_VAR", raising=False)
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.safe_dump({
            "llm": {"api_key": "env://MISSING_TEST_VAR"},
        }), encoding="utf-8")
        cli = _load_cli()
        rc = cli.main(["--config", str(cfg), "--resolve", "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_RESOLVE_FAILURES
        assert out["failed"] == 1

    def test_missing_config_file(self, tmp_path, capsys):
        cli = _load_cli()
        rc = cli.main(["--config", str(tmp_path / "nope.yaml")])
        err = capsys.readouterr().err
        assert rc == cli.EXIT_BAD_ARGS
        assert "not found" in err

    def test_bad_yaml(self, tmp_path, capsys):
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: valid: yaml: [", encoding="utf-8")
        cli = _load_cli()
        rc = cli.main(["--config", str(bad)])
        err = capsys.readouterr().err
        assert rc == cli.EXIT_BAD_ARGS
        assert "could not parse" in err

    def test_show_redacted_mode(self, tmp_path, capsys, monkeypatch):
        monkeypatch.setenv("CHECK_REDACT_VAR", "real-secret-value")
        cfg = tmp_path / "config.yaml"
        cfg.write_text(yaml.safe_dump({
            "llm": {"api_key": "env://CHECK_REDACT_VAR"},
        }), encoding="utf-8")
        cli = _load_cli()
        rc = cli.main([
            "--config", str(cfg),
            "--resolve", "--show-redacted", "--json",
        ])
        out = json.loads(capsys.readouterr().out)
        assert rc == cli.EXIT_OK
        redacted = out["redacted_resolved_config"]
        assert redacted["llm"]["api_key"] == "***REDACTED***"


# ---------------------------------------------------------------------------
# Integration: yaml.safe_load → resolve → preserved shape
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_yaml_roundtrip(self, monkeypatch):
        monkeypatch.setenv("A", "alpha")
        monkeypatch.setenv("B", "beta")
        raw = yaml.safe_load("""
        llm:
          base_url: http://localhost:1234/v1
          api_key: env://A
          temperature: 0.3
        api:
          tokens:
            - env://A
            - env://B
            - static-fallback
        """)
        out = resolve(raw)
        assert out["llm"]["api_key"] == "alpha"
        assert out["llm"]["base_url"] == "http://localhost:1234/v1"
        assert out["llm"]["temperature"] == 0.3
        assert out["api"]["tokens"] == ["alpha", "beta", "static-fallback"]
