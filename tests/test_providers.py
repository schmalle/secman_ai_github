import pytest

from secscan.config import ConfigError
from secscan.providers import (
    COPILOT_BASE_URL,
    KIMI_BASE_URL,
    OPENROUTER_BASE_URL,
    ProviderEnv,
    model_hint,
    resolve_model,
    resolve_provider,
)


def test_auto_is_anthropic_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    p = resolve_provider("auto")
    assert p.name == "anthropic"
    assert p.env == {}


def test_auto_is_openrouter_with_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    p = resolve_provider("auto")
    assert p.name == "openrouter"
    assert p.env["ANTHROPIC_BASE_URL"] == OPENROUTER_BASE_URL
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "sk-or-abc"
    assert p.env["ANTHROPIC_API_KEY"] == ""  # inherited Anthropic key neutralized


def test_forced_openrouter_without_key_raises(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        resolve_provider("openrouter")


def test_auto_is_kimi_with_key_and_no_openrouter_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi-abc")
    p = resolve_provider("auto")
    assert p.name == "kimi"
    assert p.env["ANTHROPIC_BASE_URL"] == KIMI_BASE_URL
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "sk-kimi-abc"
    assert p.env["ANTHROPIC_API_KEY"] == ""


def test_auto_prefers_openrouter_over_kimi_when_both_set(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi-abc")
    p = resolve_provider("auto")
    assert p.name == "openrouter"


def test_forced_kimi_without_key_raises(monkeypatch):
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        resolve_provider("kimi")


def test_kimi_base_url_override(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi-abc")
    monkeypatch.setenv("KIMI_BASE_URL", "https://api.moonshot.cn/anthropic")
    p = resolve_provider("kimi")
    assert p.env["ANTHROPIC_BASE_URL"] == "https://api.moonshot.cn/anthropic"


def test_forced_anthropic_ignores_kimi_key(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi-abc")
    p = resolve_provider("anthropic")
    assert p.name == "anthropic"
    assert p.env == {}


def test_copilot_defaults_without_any_key(monkeypatch):
    monkeypatch.delenv("COPILOT_BASE_URL", raising=False)
    monkeypatch.delenv("COPILOT_API_KEY", raising=False)
    p = resolve_provider("copilot")
    assert p.name == "copilot"
    assert p.env["ANTHROPIC_BASE_URL"] == COPILOT_BASE_URL
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "dummy"
    assert p.env["ANTHROPIC_API_KEY"] == ""


def test_copilot_env_overrides(monkeypatch):
    monkeypatch.setenv("COPILOT_BASE_URL", "http://localhost:5555")
    monkeypatch.setenv("COPILOT_API_KEY", "real-token")
    p = resolve_provider("copilot")
    assert p.env["ANTHROPIC_BASE_URL"] == "http://localhost:5555"
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "real-token"


def test_copilot_never_auto_selected(monkeypatch):
    # Even with a Copilot key set, "auto" only opts into openrouter/kimi —
    # copilot has no dedicated required secret to detect.
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    monkeypatch.setenv("COPILOT_API_KEY", "real-token")
    p = resolve_provider("auto")
    assert p.name == "anthropic"


def test_forced_anthropic_ignores_openrouter_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    p = resolve_provider("anthropic")
    assert p.name == "anthropic"
    assert p.env == {}


def test_unknown_provider_raises():
    with pytest.raises(ConfigError):
        resolve_provider("gemini")


def test_usecc_ignores_openrouter_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    p = resolve_provider("usecc")
    assert p.name == "usecc"
    assert p.env["ANTHROPIC_API_KEY"] == ""


def test_usecc_ignores_kimi_key(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi-abc")
    p = resolve_provider("usecc")
    assert p.name == "usecc"
    assert p.env["ANTHROPIC_API_KEY"] == ""


def test_usecc_neutralizes_inherited_anthropic_auth_env(monkeypatch):
    # Simulates a shell that still exports OpenRouter-pointing vars from earlier
    # use; "usecc" must strip them so the Claude Code subprocess falls back to
    # the local claude.ai login instead of treating them as another auth source.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-abc")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", OPENROUTER_BASE_URL)
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "sk-or-abc")
    p = resolve_provider("usecc")
    assert p.name == "usecc"
    assert p.env == {
        "ANTHROPIC_API_KEY": "",
        "ANTHROPIC_BASE_URL": "",
        "ANTHROPIC_AUTH_TOKEN": "",
    }


def test_model_hint_for_openrouter_alias():
    p = ProviderEnv(name="openrouter", env={})
    assert "slug" in model_hint(p, "sonnet")


def test_model_hint_silent_for_slug_and_anthropic():
    assert model_hint(ProviderEnv(name="openrouter", env={}), "anthropic/claude-sonnet-4.5") is None
    assert model_hint(ProviderEnv(name="anthropic"), "sonnet") is None


def test_resolve_model_maps_sonnet_alias_to_openrouter_slug():
    # The default --model is the bare "sonnet" alias; OpenRouter has no such
    # alias, so map it to the equivalent full slug (currently Sonnet 5).
    p = ProviderEnv(name="openrouter", env={})
    assert resolve_model(p, "sonnet") == "anthropic/claude-sonnet-5"


def test_resolve_model_leaves_explicit_slug_untouched():
    p = ProviderEnv(name="openrouter", env={})
    assert resolve_model(p, "anthropic/claude-sonnet-4.5") == "anthropic/claude-sonnet-4.5"


def test_resolve_model_leaves_anthropic_alias_untouched():
    # "sonnet" already resolves to the latest Sonnet on direct Anthropic auth.
    assert resolve_model(ProviderEnv(name="anthropic"), "sonnet") == "sonnet"


def test_model_hint_for_kimi_non_kimi_model():
    p = ProviderEnv(name="kimi", env={})
    assert "Moonshot" in model_hint(p, "anthropic/claude-sonnet-4.5")


def test_model_hint_silent_for_kimi_model():
    assert model_hint(ProviderEnv(name="kimi", env={}), "kimi-k2.7-code") is None


def test_resolve_model_maps_sonnet_alias_to_kimi_model_id():
    p = ProviderEnv(name="kimi", env={})
    assert resolve_model(p, "sonnet") == "kimi-k2.7-code"


def test_resolve_model_leaves_explicit_kimi_model_untouched():
    p = ProviderEnv(name="kimi", env={})
    assert resolve_model(p, "kimi-k3") == "kimi-k3"


def test_model_hint_for_copilot_default_sonnet():
    p = ProviderEnv(name="copilot", env={})
    assert "proxy" in model_hint(p, "sonnet")


def test_model_hint_silent_for_copilot_explicit_model():
    assert model_hint(ProviderEnv(name="copilot", env={}), "gpt-4.1") is None


def test_resolve_model_leaves_copilot_model_untouched():
    # Copilot proxies have no fixed alias mapping; --model must match what
    # the proxy itself exposes, so resolve_model passes it through as-is.
    p = ProviderEnv(name="copilot", env={})
    assert resolve_model(p, "sonnet") == "sonnet"
