"""LLM provider selection for the Claude Code reviewer.

The reviewer is always Claude Code (via the Claude Agent SDK); this module only
decides which API endpoint bills the tokens. OpenRouter, Moonshot's Kimi
platform, and Anthropic-compatible GitHub Copilot proxies all expose an
Anthropic Messages-compatible endpoint, so routing through any of them is just
a matter of pointing the Claude Code subprocess at a different base URL with
the right key — same mechanism, different provider.

Providers:
- "anthropic": the default — the SDK uses ANTHROPIC_API_KEY (or a logged-in
  Claude subscription) untouched. Note this only leaves inherited env alone; it
  does not strip an inherited ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN pointing
  elsewhere (e.g. left over from OpenRouter use in the same shell) — use
  "usecc" for that.
- "openrouter": requires OPENROUTER_API_KEY; model names must be OpenRouter slugs
  (e.g. "anthropic/claude-sonnet-4.5").
- "kimi": requires KIMI_API_KEY (a Moonshot AI / platform.kimi.ai API key);
  routes through Moonshot's documented Claude Code-compatible endpoint
  (KIMI_BASE_URL, default "https://api.moonshot.ai/anthropic"). Model names
  must be Moonshot model ids (e.g. "kimi-k2.7-code"); see
  https://platform.kimi.ai/docs/models — Moonshot rotates model ids/aliases
  fairly often, so check there if a model id starts getting rejected.
- "copilot": routes through a local Anthropic-compatible GitHub Copilot proxy
  (e.g. https://github.com/ericc-ch/copilot-api run as
  `npx copilot-api@latest start`), which authenticates against your own GitHub
  Copilot subscription. COPILOT_BASE_URL defaults to "http://localhost:4141";
  COPILOT_API_KEY is optional since these proxies typically accept any
  non-empty bearer token (defaults to "dummy" if unset) and do the real
  auth via a separate device-login step against GitHub. Model names must match
  what the proxy exposes (whatever it was started with).
- "auto": openrouter iff OPENROUTER_API_KEY is set, else kimi iff KIMI_API_KEY
  is set, else anthropic. Setting a key is the opt-in; --provider anthropic
  forces Anthropic even when other keys are present. "copilot" is never
  auto-selected — it has no dedicated required secret to detect, so it must be
  chosen explicitly with --provider copilot.
- "usecc": force the locally authenticated Claude Code session. Ignores
  OPENROUTER_API_KEY/KIMI_API_KEY and explicitly neutralizes any inherited
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

_PROVIDERS = ("anthropic", "openrouter", "kimi", "copilot", "auto", "usecc")


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

    openrouter_key = _env("OPENROUTER_API_KEY")
    kimi_key = _env("KIMI_API_KEY")
    if provider == "auto":
        if openrouter_key:
            provider = "openrouter"
        elif kimi_key:
            provider = "kimi"
        else:
            provider = "anthropic"

    if provider == "anthropic":
        return ProviderEnv(name="anthropic")

    if provider == "openrouter":
        if not openrouter_key:
            raise ConfigError("OPENROUTER_API_KEY is required for --provider openrouter")
        return ProviderEnv(
            name="openrouter",
            env={
                "ANTHROPIC_BASE_URL": OPENROUTER_BASE_URL,
                "ANTHROPIC_AUTH_TOKEN": openrouter_key,
                "ANTHROPIC_API_KEY": "",  # neutralize any inherited Anthropic key
            },
        )

    if provider == "kimi":
        if not kimi_key:
            raise ConfigError("KIMI_API_KEY is required for --provider kimi")
        return ProviderEnv(
            name="kimi",
            env={
                "ANTHROPIC_BASE_URL": _env("KIMI_BASE_URL", KIMI_BASE_URL),
                "ANTHROPIC_AUTH_TOKEN": kimi_key,
                "ANTHROPIC_API_KEY": "",  # neutralize any inherited Anthropic key
            },
        )

    # provider == "copilot": no required secret — auth happens out-of-band
    # against the local proxy (a GitHub device-login flow), which typically
    # accepts any non-empty bearer token on the Anthropic-compatible endpoint.
    return ProviderEnv(
        name="copilot",
        env={
            "ANTHROPIC_BASE_URL": _env("COPILOT_BASE_URL", COPILOT_BASE_URL),
            "ANTHROPIC_AUTH_TOKEN": _env("COPILOT_API_KEY", "dummy"),
            "ANTHROPIC_API_KEY": "",  # neutralize any inherited Anthropic key
        },
    )


# The bare Anthropic aliases ("sonnet", "opus", ...) that the CLI understands
# directly have no OpenRouter/Kimi equivalent; map the one we default to so
# `--model` left unset still resolves to a working model on either provider.
_OPENROUTER_MODEL_ALIASES = {
    "sonnet": "anthropic/claude-sonnet-5",
}
_KIMI_MODEL_ALIASES = {
    "sonnet": "kimi-k2.7-code",
}


def resolve_model(provider_env: ProviderEnv, model: str) -> str:
    """Map a bare Anthropic alias to the equivalent model id for the resolved provider."""
    if provider_env.name == "openrouter":
        return _OPENROUTER_MODEL_ALIASES.get(model, model)
    if provider_env.name == "kimi":
        return _KIMI_MODEL_ALIASES.get(model, model)
    return model


def model_hint(provider_env: ProviderEnv, model: str) -> str | None:
    """Non-fatal usability hint when the model name doesn't fit the provider."""
    if provider_env.name == "openrouter" and "/" not in model:
        return (
            f"hint: OpenRouter expects model slugs like 'anthropic/claude-sonnet-4.5' "
            f"(got {model!r})"
        )
    if provider_env.name == "kimi" and not model.lower().startswith("kimi"):
        return (
            f"hint: Kimi expects a Moonshot model id like 'kimi-k2.7-code' "
            f"(got {model!r}); see https://platform.kimi.ai/docs/models"
        )
    if provider_env.name == "copilot" and model == "sonnet":
        return (
            "hint: --model must match a model your Copilot-compatible proxy exposes "
            "(the bare 'sonnet' alias is Anthropic-only) — pass --model explicitly"
        )
    return None
