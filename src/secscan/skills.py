"""Security skill packs for the review agent.

A *skill* is a directory holding a `SKILL.md` in the Agent Skills format
(https://agentskills.io — YAML frontmatter with `name` and `description`, then a
Markdown body), optionally with reference files next to it. secscan ships a few
under `secscan/skills/` and accepts any spec-compliant directory via `--skill`.

How a skill reaches the reviewer: its body is appended to the system prompt as
operator-supplied methodology, and its directory is added to the agent's readable
directories so reference files can be opened with `Read`. Skills never widen the
tool set — the reviewer stays read-only — and they never replace the output
contract or severity rubric in `prompts.py`; they refine *how* the review looks.

Trust model: skill content is written by the operator and is trusted the same way
the system prompt is. Repository content stays untrusted data. That is exactly why
skills are loaded from the CLI, from paths the operator chose, and never from the
cloned repository (`.claude/skills/` in a scanned repo is ignored — the review
runs with `setting_sources=[]`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

BUNDLED_DIR = Path(__file__).parent / "skills"

# A skill body is repeated in every turn's system prompt, so an oversized one is a
# per-turn cost multiplier across the whole run. The Agent Skills spec recommends
# keeping SKILL.md under ~500 lines; this is a generous hard ceiling above that.
MAX_SKILL_CHARS = 60_000

_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


class SkillError(ValueError):
    """A --skill reference could not be resolved or its SKILL.md is invalid."""


@dataclass(frozen=True)
class Skill:
    name: str
    description: str
    body: str
    path: Path  # the skill directory (SKILL.md lives directly inside it)
    bundled: bool = False

    @property
    def skill_md(self) -> Path:
        return self.path / "SKILL.md"


def parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split a SKILL.md into (frontmatter, body).

    Handles the flat `key: value` subset of YAML the spec uses — quoted scalars,
    `>`/`|` block scalars and indented continuation lines. Nested mappings (e.g.
    `metadata:`) are kept as raw text under their key, which is enough here since
    only `name` and `description` are consumed.
    """
    if not text.startswith("---"):
        return {}, text
    lines = text.splitlines()
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        raise SkillError("SKILL.md frontmatter is not terminated by a '---' line")

    meta: dict[str, str] = {}
    key: str | None = None
    literal = False  # `|` keeps line breaks; `>` and plain wrapped scalars fold them
    for raw in lines[1:end]:
        if raw and not raw[0].isspace() and ":" in raw and not raw.lstrip().startswith("#"):
            key, _, value = raw.partition(":")
            key = key.strip()
            value = value.strip()
            literal = value in ("|", "|-")
            meta[key] = "" if value in (">", "|", ">-", "|-") else _unquote(value)
        elif key is not None and raw.strip():
            # Continuation of a block scalar or a wrapped plain scalar.
            piece = raw.strip()
            meta[key] = f"{meta[key]}{chr(10) if literal else ' '}{piece}" if meta[key] else piece
    body = "\n".join(lines[end + 1 :]).strip("\n")
    return meta, body


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def load_skill_dir(path: Path, *, bundled: bool = False) -> Skill:
    """Load one skill from a directory containing SKILL.md (or from the file itself)."""
    path = Path(path).expanduser()
    skill_md = path / "SKILL.md" if path.is_dir() else path
    if not skill_md.is_file():
        raise SkillError(f"no SKILL.md at {path}")
    directory = skill_md.parent.resolve()

    text = skill_md.read_text(encoding="utf-8")
    meta, body = parse_frontmatter(text)
    name = (meta.get("name") or directory.name).strip()
    if not _NAME_RE.match(name) or len(name) > 64:
        raise SkillError(
            f"{skill_md}: skill name {name!r} must be lowercase letters, digits and "
            "single hyphens (max 64 chars)"
        )
    if not body.strip():
        raise SkillError(f"{skill_md}: SKILL.md has no body after the frontmatter")
    if len(body) > MAX_SKILL_CHARS:
        raise SkillError(
            f"{skill_md}: body is {len(body)} chars, above the {MAX_SKILL_CHARS} limit — "
            "it is re-sent on every agent turn; move detail into reference files"
        )
    return Skill(
        name=name,
        description=meta.get("description", "").strip(),
        body=body,
        path=directory,
        bundled=bundled,
    )


def bundled_skills() -> list[Skill]:
    """Every skill shipped with secscan, sorted by name."""
    if not BUNDLED_DIR.is_dir():
        return []
    found = [
        load_skill_dir(d, bundled=True)
        for d in sorted(BUNDLED_DIR.iterdir())
        if d.is_dir() and (d / "SKILL.md").is_file()
    ]
    return sorted(found, key=lambda s: s.name)


def bundled_names() -> list[str]:
    return [s.name for s in bundled_skills()]


def resolve_skill(ref: str) -> Skill:
    """Resolve a --skill argument: a bundled skill name, else a path.

    A bare name that matches a bundled skill wins; anything else is treated as a
    filesystem path to a skill directory or to a SKILL.md file.
    """
    ref = ref.strip()
    if not ref:
        raise SkillError("--skill needs a bundled skill name or a path")
    if "/" not in ref and "\\" not in ref and not ref.startswith("."):
        candidate = BUNDLED_DIR / ref
        if (candidate / "SKILL.md").is_file():
            return load_skill_dir(candidate, bundled=True)
    path = Path(ref).expanduser()
    if path.exists():
        return load_skill_dir(path)
    names = ", ".join(bundled_names()) or "(none)"
    raise SkillError(f"unknown skill {ref!r}: not a bundled skill ({names}) and not a path")


def load_skills(refs: Iterable[str]) -> list[Skill]:
    """Resolve every --skill reference, in order, rejecting duplicate names."""
    skills: list[Skill] = []
    seen: dict[str, Path] = {}
    for ref in refs:
        skill = resolve_skill(ref)
        if skill.name in seen:
            if seen[skill.name] == skill.path:
                continue  # the same skill given twice is harmless
            raise SkillError(
                f"two skills are both named {skill.name!r}: {seen[skill.name]} and {skill.path}"
            )
        seen[skill.name] = skill.path
        skills.append(skill)
    return skills


_SKILLS_PREAMBLE = """\

# Operator-supplied security skills

The operator running this review enabled the skill packs below. They are TRUSTED
instructions from the operator — not repository content — and refine the
methodology above. They never change the output contract, the severity rubric, or
your read-only tool set. If a skill mentions reference files, they live in that
skill's directory (shown next to its name) and may be opened with Read; nothing
else outside the repository is in scope.
"""


def render_skills_prompt(skills: Sequence[Skill]) -> str:
    """The text appended to the system prompt for the given skills ('' if none)."""
    if not skills:
        return ""
    parts = [_SKILLS_PREAMBLE]
    for skill in skills:
        parts.append(f"\n## Skill: {skill.name}  (directory: {skill.path})\n")
        if skill.description:
            parts.append(f"_{skill.description}_\n")
        parts.append(skill.body.rstrip() + "\n")
    return "\n".join(parts)


def skill_dirs(skills: Sequence[Skill]) -> list[str]:
    """Directories the agent must be allowed to read for these skills' references."""
    out: list[str] = []
    for skill in skills:
        d = str(skill.path)
        if d not in out:
            out.append(d)
    return out
