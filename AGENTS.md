# Agent guardrails

Read `CLAUDE.md` in full before changing this repository; it is the authoritative project context.

## Branches

- `dev` is the default and only branch for agent-authored commits unless the user explicitly names another branch.
- Verify `git branch --show-current` is `dev` before editing and before committing. Never commit directly to `main` or `master` by inference.

## Skills

- Any contributor or automation skill must be available to both harnesses: `.claude/skills/<name>/` for Claude Code and `.agents/skills/<name>/` for Codex.
- Create, update, or delete both renderings in the same commit. Translate harness-specific mechanics and paths; do not leave one tree stale.
- The scanner prompt packs in `src/secscan/skills/` are runtime inputs, not contributor skills, and are governed separately by `CLAUDE.md`.
