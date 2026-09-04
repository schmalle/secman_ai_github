import pytest

from secscan.config import ConfigError
from secscan.providers import (
    COPILOT_BASE_URL,
    COPILOT_PLACEHOLDER_TOKEN,
    KIMI_BASE_URL,
    OPENROUTER_BASE_URL,
    ProviderEnv,
    model_hint,
    resolve_model,
    resolve_provider,
)

# Every env var provider resolution reads. Cleared for each test so a developer's
# own shell (or a leftover .env) can't flip which provider a test resolves to.
_PROVIDER_ENV_VARS = (
    "OPENROUTER_API_KEY",
    "MOONSHOT_API_KEY",
    "KIMI_API_KEY",
    "KIMI_BASE_URL",
    "KIMI_MODEL",
    "COPILOT_API_KEY",
    "GITHUB_COPILOT_API_KEY",
    "COPILOT_BASE_URL",
    "COPILOT_MODEL",
)


@pytest.fixture(autouse=True)
def _clean_provider_env(monkeypatch):
    for var in _PROVIDER_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_auto_is_anthropic_without_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    p = resolve_provider("auto")
    assert p.name == "anthropic"
    assert p.env == {}


def test_auto_is_openrouter_with_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    p = resolve_provider("auto")
    assert p.name == "openrouter"
    assert p.env["ANTHROPIC_BASE_URL"] == OPENROUTER_BASE_URL
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "sk-or-abc"
    assert p.env["ANTHROPIC_API_KEY"] == ""  # inherited Anthropic key neutralized


def test_forced_openrouter_without_key_raises(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        resolve_provider("openrouter")


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


# --- Kimi (Moonshot) --------------------------------------------------------


def test_kimi_uses_moonshot_anthropic_endpoint(monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-abc")
    p = resolve_provider("kimi")
    assert p.name == "kimi"
    assert p.env["ANTHROPIC_BASE_URL"] == KIMI_BASE_URL
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "sk-moon-abc"
    assert p.env["ANTHROPIC_API_KEY"] == ""  # inherited Anthropic key neutralized
    assert p.endpoint == KIMI_BASE_URL


def test_kimi_accepts_kimi_api_key_alias(monkeypatch):
    monkeypatch.setenv("KIMI_API_KEY", "sk-kimi-abc")
    assert resolve_provider("kimi").env["ANTHROPIC_AUTH_TOKEN"] == "sk-kimi-abc"


def test_kimi_base_url_is_overridable(monkeypatch):
    # e.g. the mainland-China host, or a self-hosted gateway.
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-abc")
    monkeypatch.setenv("KIMI_BASE_URL", "https://api.moonshot.cn/anthropic")
    p = resolve_provider("kimi")
    assert p.env["ANTHROPIC_BASE_URL"] == "https://api.moonshot.cn/anthropic"


def test_forced_kimi_without_key_raises():
    with pytest.raises(ConfigError):
        resolve_provider("kimi")


def test_auto_is_kimi_when_only_moonshot_key_is_set(monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-abc")
    assert resolve_provider("auto").name == "kimi"


def test_auto_prefers_openrouter_over_kimi(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-abc")
    assert resolve_provider("auto").name == "openrouter"


def test_forced_anthropic_ignores_moonshot_key(monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-abc")
    p = resolve_provider("anthropic")
    assert p.name == "anthropic"
    assert p.env == {}


def test_usecc_ignores_moonshot_key(monkeypatch):
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-moon-abc")
    p = resolve_provider("usecc")
    assert p.name == "usecc"
    assert p.env["ANTHROPIC_BASE_URL"] == ""


def test_resolve_model_maps_aliases_to_kimi_ids():
    p = ProviderEnv(name="kimi", env={})
    assert resolve_model(p, "sonnet") == "kimi-k2.7-code"
    assert resolve_model(p, "opus") == "kimi-k3"


def test_resolve_model_kimi_env_override_wins_for_aliases(monkeypatch):
    monkeypatch.setenv("KIMI_MODEL", "kimi-k2.6")
    p = ProviderEnv(name="kimi", env={})
    assert resolve_model(p, "sonnet") == "kimi-k2.6"
    # An explicitly requested model is never overridden.
    assert resolve_model(p, "kimi-k3") == "kimi-k3"


def test_model_hint_for_non_kimi_model():
    assert "kimi-k2.7-code" in model_hint(ProviderEnv(name="kimi", env={}), "haiku")
    assert model_hint(ProviderEnv(name="kimi", env={}), "kimi-k3") is None


# --- GitHub Copilot ---------------------------------------------------------


def test_copilot_defaults_to_local_bridge():
    p = resolve_provider("copilot")
    assert p.name == "copilot"
    assert p.env["ANTHROPIC_BASE_URL"] == COPILOT_BASE_URL
    # A placeholder token keeps the agent from sending a real Anthropic
    # credential (or starting a login) against the local bridge.
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == COPILOT_PLACEHOLDER_TOKEN
    assert p.env["ANTHROPIC_API_KEY"] == ""


def test_copilot_honours_base_url_and_token(monkeypatch):
    monkeypatch.setenv("COPILOT_BASE_URL", "http://127.0.0.1:4000")
    monkeypatch.setenv("COPILOT_API_KEY", "bridge-token")
    p = resolve_provider("copilot")
    assert p.env["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:4000"
    assert p.env["ANTHROPIC_AUTH_TOKEN"] == "bridge-token"
    assert p.endpoint == "http://127.0.0.1:4000"


def test_copilot_is_never_auto_selected(monkeypatch):
    # The bridge is a local process, not a key — auto must not assume it's up.
    monkeypatch.setenv("COPILOT_API_KEY", "bridge-token")
    assert resolve_provider("auto").name == "anthropic"


def test_forced_copilot_ignores_openrouter_key(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-abc")
    assert resolve_provider("copilot").name == "copilot"


def test_resolve_model_maps_sonnet_alias_to_copilot_id():
    assert resolve_model(ProviderEnv(name="copilot", env={}), "sonnet") == "claude-sonnet-4.5"


def test_resolve_model_copilot_env_override_wins_for_aliases(monkeypatch):
    monkeypatch.setenv("COPILOT_MODEL", "gpt-4.1")
    p = ProviderEnv(name="copilot", env={})
    assert resolve_model(p, "sonnet") == "gpt-4.1"
    assert resolve_model(p, "claude-sonnet-4.5") == "claude-sonnet-4.5"


def test_model_hint_for_unmapped_copilot_alias():
    assert "gpt-4.1" in model_hint(ProviderEnv(name="copilot", env={}), "haiku")
    assert model_hint(ProviderEnv(name="copilot", env={}), "claude-sonnet-4.5") is None


# --- gateway model pinning ------------------------------------------------------------------


def test_gateway_model_env_pins_every_model_for_openrouter(monkeypatch):
    from secscan.providers import ProviderEnv, gateway_model_env, with_model_env

    monkeypatch.delenv("OPENROUTER_SMALL_MODEL", raising=False)
    env = gateway_model_env(ProviderEnv(name="openrouter"), "anthropic/claude-sonnet-5")
    assert env["ANTHROPIC_MODEL"] == "anthropic/claude-sonnet-5"
    assert env["ANTHROPIC_DEFAULT_SONNET_MODEL"] == "anthropic/claude-sonnet-5"
    assert env["ANTHROPIC_DEFAULT_OPUS_MODEL"] == "anthropic/claude-sonnet-5"
    assert env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] == "anthropic/claude-haiku-4.5"
    assert env["ANTHROPIC_SMALL_FAST_MODEL"] == "anthropic/claude-haiku-4.5"
    assert env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"

    monkeypatch.setenv("OPENROUTER_SMALL_MODEL", "anthropic/claude-haiku-5")
    assert gateway_model_env(ProviderEnv(name="openrouter"), "m")["ANTHROPIC_SMALL_FAST_MODEL"] == "anthropic/claude-haiku-5"

    merged = with_model_env(ProviderEnv(name="openrouter", env={"ANTHROPIC_AUTH_TOKEN": "t"}, endpoint="e"), "m")
    assert merged.env["ANTHROPIC_AUTH_TOKEN"] == "t" and merged.env["ANTHROPIC_MODEL"] == "m"
    assert merged.endpoint == "e"


def test_gateway_model_env_uses_main_model_as_small_model_for_kimi():
    from secscan.providers import ProviderEnv, gateway_model_env

    env = gateway_model_env(ProviderEnv(name="kimi"), "kimi-k2.7-code")
    assert env["ANTHROPIC_SMALL_FAST_MODEL"] == "kimi-k2.7-code"


def test_gateway_model_env_is_empty_for_anthropic_and_usecc():
    from secscan.providers import ProviderEnv, gateway_model_env, with_model_env

    for name in ("anthropic", "usecc"):
        assert gateway_model_env(ProviderEnv(name=name), "sonnet") == {}
        pe = ProviderEnv(name=name)
        assert with_model_env(pe, "sonnet") is pe
