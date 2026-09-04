"""LLM provider selection for the Claude Code reviewer.

The reviewer is always Claude Code (via the Claude Agent SDK); this module only
decides which API endpoint bills the tokens. Every non-Anthropic provider here
works the same way: it exposes an Anthropic-compatible `/v1/messages` endpoint,
so routing through it is just a matter of pointing the Claude Code subprocess at
a different base URL with that provider's token.

Providers:
- "anthropic": the default — the SDK uses ANTHROPIC_API_KEY (or a logged-in
  Claude subscription) untouched. Note this only leaves inherited env alone; it
  does not strip an inherited ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN pointing
  elsewhere (e.g. left over from OpenRouter use in the same shell) — use
  "usecc" for that.
- "openrouter": requires OPENROUTER_API_KEY; model names must be OpenRouter slugs
  (e.g. "anthropic/claude-sonnet-4.5").
- "kimi": Moonshot AI's Anthropic-compatible endpoint. Requires MOONSHOT_API_KEY
  (KIMI_API_KEY is accepted as an alias); model names are Kimi model IDs
  (e.g. "kimi-k2.7-code"). Override the endpoint with KIMI_BASE_URL for the
  mainland-China host (https://api.moonshot.cn/anthropic) or a gateway.
- "copilot": GitHub Copilot. Copilot itself speaks the OpenAI API, so this
  provider expects a local Anthropic-compatible Copilot bridge (e.g.
  `npx copilot-api@latest start`, which listens on http://localhost:4141);
  point COPILOT_BASE_URL at it if it isn't on the default port. Model names are
  Copilot model IDs (e.g. "claude-sonnet-4.5", "gpt-4.1").
- "auto": openrouter iff OPENROUTER_API_KEY is set, else kimi iff a Moonshot key
  is set, else anthropic. Setting the key is the opt-in; --provider anthropic
  forces Anthropic even when several keys are present. "copilot" is never
  auto-selected because it needs a bridge process running locally.
- "usecc": force the locally authenticated Claude Code session. Ignores every
  provider key and explicitly neutralizes any inherited
  ANTHROPIC_API_KEY/ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN, since the Claude
  Code CLI treats any of those as "another auth source" and disables the
  claude.ai-login-backed connectors otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import ConfigError, _env

OPENROUTER_BASE_URL = "https://openrouter.ai/api"
KIMI_BASE_URL = "https://api.moonshot.ai/anthropic"
COPILOT_BASE_URL = "http://localhost:4141"

# Copilot bridges run on the user's own machine and generally accept any bearer
# token. We still send one so the Claude Code subprocess never falls back to a
# real Anthropic credential (or an interactive login) against a local endpoint.
COPILOT_PLACEHOLDER_TOKEN = "copilot"

_PROVIDERS = ("anthropic", "openrouter", "kimi", "copilot", "auto", "usecc")

# Bare model aliases the Claude Code CLI understands against Anthropic itself.
# No other provider has an equivalent, so they get mapped per-provider below.
_ANTHROPIC_ALIASES = ("sonnet", "opus", "haiku")


@dataclass(frozen=True)
class ProviderEnv:
    """A resolved provider and the env overrides to pass to the review agent."""

    name: str
    env: dict[str, str] = field(default_factory=dict)
    endpoint: str = ""  # base URL reviews are routed to ("" = Anthropic's default)


def _gateway_env(name: str, base_url: str, token: str) -> ProviderEnv:
    """Point the Claude Code subprocess at an Anthropic-compatible gateway."""
    return ProviderEnv(
        name=name,
        env={
            "ANTHROPIC_BASE_URL": base_url,
            "ANTHROPIC_AUTH_TOKEN": token,
            "ANTHROPIC_API_KEY": "",  # neutralize any inherited Anthropic key
        },
        endpoint=base_url,
    )


def _moonshot_key() -> str | None:
    return _env("MOONSHOT_API_KEY") or _env("KIMI_API_KEY")


def resolve_provider(provider: str = "auto") -> ProviderEnv:
    """Resolve the provider choice against the environment."""
    if provider not in _PROVIDERS:
        raise ConfigError(f"provider must be one of {', '.join(_PROVIDERS)}; got {provider!r}")

    if provider == "usecc":
        return ProviderEnv(
            name="usecc",
            env={
                "ANTHROPIC_API_KEY": "",
                "ANTHROPIC_BASE_URL": "",
                "ANTHROPIC_AUTH_TOKEN": "",
            },
        )

    openrouter_key = _env("OPENROUTER_API_KEY")
    if provider == "auto":
        if openrouter_key:
            provider = "openrouter"
        elif _moonshot_key():
            provider = "kimi"
        else:
            provider = "anthropic"

    if provider == "anthropic":
        return ProviderEnv(name="anthropic")

    if provider == "openrouter":
        if not openrouter_key:
            raise ConfigError("OPENROUTER_API_KEY is required for --provider openrouter")
        return _gateway_env("openrouter", OPENROUTER_BASE_URL, openrouter_key)

    if provider == "kimi":
        key = _moonshot_key()
        if not key:
            raise ConfigError("MOONSHOT_API_KEY (or KIMI_API_KEY) is required for --provider kimi")
        return _gateway_env("kimi", _env("KIMI_BASE_URL") or KIMI_BASE_URL, key)

    # copilot: a local bridge translates Anthropic /v1/messages to the Copilot API.
    return _gateway_env(
        "copilot",
        _env("COPILOT_BASE_URL") or COPILOT_BASE_URL,
        _env("COPILOT_API_KEY") or _env("GITHUB_COPILOT_API_KEY") or COPILOT_PLACEHOLDER_TOKEN,
    )


# The bare Anthropic aliases ("sonnet", "opus", ...) that the CLI understands
# directly have no equivalent on the other providers; map the one we default to
# so `--model` left unset still resolves to a working model everywhere.
_MODEL_ALIASES = {
    "openrouter": {
        "sonnet": "anthropic/claude-sonnet-5",
    },
    "kimi": {
        "sonnet": "kimi-k2.7-code",  # Moonshot's coding-agent tier
        "opus": "kimi-k3",  # Moonshot's flagship
    },
    "copilot": {
        "sonnet": "claude-sonnet-4.5",
    },
}

# Model lineups on these providers move faster than this table; let the
# environment override which model a bare alias resolves to.
_MODEL_ENV_OVERRIDES = {"kimi": "KIMI_MODEL", "copilot": "COPILOT_MODEL"}


def resolve_model(provider_env: ProviderEnv, model: str) -> str:
    """Map a bare Anthropic alias to the equivalent model on the routed provider.

    Explicit model names are always passed through untouched.
    """
    if model not in _ANTHROPIC_ALIASES:
        return model

    override_var = _MODEL_ENV_OVERRIDES.get(provider_env.name)
    if override_var:
        override = _env(override_var)
        if override:
            return override

    return _MODEL_ALIASES.get(provider_env.name, {}).get(model, model)


# Claude Code makes calls with more than one model: the main model for the
# conversation, and a "small fast" model (Haiku by default) for background work
# such as summarising tool output. Against Anthropic those resolve by alias; through
# a gateway the aliases do not exist, and the background calls fail with an
# unknown-model error unless every one of them is pinned to a slug the gateway
# serves. `--model` pins the main model; these pin the rest. The haiku-class slug
# is separately overridable because it is the one most likely to move.
_SMALL_MODEL_ENV = {"openrouter": "OPENROUTER_SMALL_MODEL", "kimi": None, "copilot": "COPILOT_SMALL_MODEL"}
_SMALL_MODEL_DEFAULT = {"openrouter": "anthropic/claude-haiku-4.5"}


def gateway_model_env(provider_env: ProviderEnv, model: str) -> dict[str, str]:
    """Extra env pinning every model the Claude Code CLI may pick to `model`.

    Empty for the Anthropic-direct providers, where the CLI's own aliases work.
    Also switches off the CLI's non-essential traffic (update checks, telemetry),
    which a third-party gateway does not serve.
    """
    if provider_env.name not in _MODEL_ALIASES:
        return {}
    small_var = _SMALL_MODEL_ENV.get(provider_env.name)
    small = (_env(small_var) if small_var else None) or _SMALL_MODEL_DEFAULT.get(provider_env.name) or model
    return {
        "ANTHROPIC_MODEL": model,
        "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
        "ANTHROPIC_DEFAULT_OPUS_MODEL": model,
        "ANTHROPIC_DEFAULT_HAIKU_MODEL": small,
        "ANTHROPIC_SMALL_FAST_MODEL": small,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }


def with_model_env(provider_env: ProviderEnv, model: str) -> ProviderEnv:
    """`provider_env` with `gateway_model_env` merged into its env overrides."""
    extra = gateway_model_env(provider_env, model)
    if not extra:
        return provider_env
    return ProviderEnv(
        name=provider_env.name, env={**provider_env.env, **extra}, endpoint=provider_env.endpoint
    )


def model_hint(provider_env: ProviderEnv, model: str) -> str | None:
    """Non-fatal usability hint when the model name doesn't fit the provider."""
    if provider_env.name == "openrouter" and "/" not in model:
        return (
            f"hint: OpenRouter expects model slugs like 'anthropic/claude-sonnet-4.5' "
            f"(got {model!r})"
        )
    if provider_env.name == "kimi" and not model.startswith("kimi"):
        return (
            f"hint: Kimi expects Moonshot model IDs like 'kimi-k2.7-code' (got {model!r}); "
            f"set KIMI_MODEL to change what the default alias resolves to"
        )
    if provider_env.name == "copilot" and model in _ANTHROPIC_ALIASES:
        return (
            f"hint: GitHub Copilot expects Copilot model IDs like 'claude-sonnet-4.5' "
            f"or 'gpt-4.1' (got {model!r}); set COPILOT_MODEL to change what the "
            f"default alias resolves to"
        )
    return None
