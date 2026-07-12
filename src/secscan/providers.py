"""LLM provider selection for the Claude Code reviewer.

The reviewer is always Claude Code (via the Claude Agent SDK); this module only
decides which API endpoint bills the tokens. OpenRouter exposes an
Anthropic-compatible endpoint, so routing through it is just a matter of pointing
the Claude Code subprocess at a different base URL with an OpenRouter key.

Providers:
- "anthropic": the default — the SDK uses ANTHROPIC_API_KEY (or a logged-in
  Claude subscription) untouched. Note this only leaves inherited env alone; it
  does not strip an inherited ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN pointing
  elsewhere (e.g. left over from OpenRouter use in the same shell) — use
  "usecc" for that.
- "openrouter": requires OPENROUTER_API_KEY; model names must be OpenRouter slugs
  (e.g. "anthropic/claude-sonnet-4.5").
- "auto": openrouter iff OPENROUTER_API_KEY is set, else anthropic. Setting the
  key is the opt-in; --provider anthropic forces Anthropic even when both keys
  are present.
- "usecc": force the locally authenticated Claude Code session. Ignores
  OPENROUTER_API_KEY and explicitly neutralizes any inherited
  ANTHROPIC_API_KEY/ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN, since the Claude
  Code CLI treats any of those as "another auth source" and disables the
  claude.ai-login-backed connectors otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import ConfigError, _env

OPENROUTER_BASE_URL = "https://openrouter.ai/api"

_PROVIDERS = ("anthropic", "openrouter", "auto", "usecc")


@dataclass(frozen=True)
class ProviderEnv:
    """A resolved provider and the env overrides to pass to the review agent."""

    name: str
    env: dict[str, str] = field(default_factory=dict)


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

    key = _env("OPENROUTER_API_KEY")
    if provider == "auto":
        provider = "openrouter" if key else "anthropic"

    if provider == "anthropic":
        return ProviderEnv(name="anthropic")

    if not key:
        raise ConfigError("OPENROUTER_API_KEY is required for --provider openrouter")
    return ProviderEnv(
        name="openrouter",
        env={
            "ANTHROPIC_BASE_URL": OPENROUTER_BASE_URL,
            "ANTHROPIC_AUTH_TOKEN": key,
            "ANTHROPIC_API_KEY": "",  # neutralize any inherited Anthropic key
        },
    )


# The bare Anthropic aliases ("sonnet", "opus", ...) that the CLI understands
# directly have no OpenRouter equivalent; map the one we default to so
# `--model` left unset still resolves to a working model on either provider.
_OPENROUTER_MODEL_ALIASES = {
    "sonnet": "anthropic/claude-sonnet-5",
}


def resolve_model(provider_env: ProviderEnv, model: str) -> str:
    """Map a bare Anthropic alias to its OpenRouter slug when routing through OpenRouter."""
    if provider_env.name == "openrouter":
        return _OPENROUTER_MODEL_ALIASES.get(model, model)
    return model


def model_hint(provider_env: ProviderEnv, model: str) -> str | None:
    """Non-fatal usability hint when the model name doesn't fit the provider."""
    if provider_env.name == "openrouter" and "/" not in model:
        return (
            f"hint: OpenRouter expects model slugs like 'anthropic/claude-sonnet-4.5' "
            f"(got {model!r})"
        )
    return None
