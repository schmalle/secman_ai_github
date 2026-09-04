"""Generate fixes for High/Critical findings (`--fix`, `--create-fix-prs`).

After a review, the same engine is sent back into the repository — this time with
file-editing tools — with the High/Critical findings as its task, and the resulting
change is captured as a unified diff. `pull_requests.py` turns that diff into a
branch and a GitHub pull request when asked; on its own, `--fix` just leaves the
patch next to `findings.csv`.

The boundaries that make this acceptable to run over untrusted code:

- **Still no code execution.** The Claude engine gets `Edit`/`Write` and keeps
  `Bash` denied; the Kimi engine's agent spec adds only the two file-writing tools;
  Codex runs in its `workspace-write` OS sandbox with network off. None of them can
  run the repository's build, tests or scripts. The trade-off is explicit: the
  agent cannot verify its own change, so every fix PR is a proposal for a human
  reviewer, not a merge candidate.
- **The workspace is disposable.** A `scan`/`run` clone is edited in place (it is
  deleted afterwards unless `--keep-clones`). A local directory given to `review`
  is never modified: the fixer works on a fresh `git clone` of it (its committed
  HEAD; uncommitted changes are not included — a warning says so), or on a copy
  with a baseline commit when the directory is not a git repository.
- **The diff is the output, the agent's summary is a footnote.** What goes into the
  patch and the PR is whatever `git diff` reports after the run, regardless of what
  the model claims to have done. `.git/` is excluded by construction, and the
  fingerprints of the findings being addressed are recorded alongside so a PR can be
  deduplicated (see `pull_requests.fix_key`).
- **Dry-run leaves the fix step alone**, exactly like the review: `--dry-run` still
  writes `fixes.patch` locally but never pushes a branch or opens a PR.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from . import codex, kimi_cli
from .config import RunConfig
from .findings import Finding, fingerprint
from .providers import ProviderEnv
from .reviewer import AgentRun, fix_repo as claude_fix_repo

PATCH_FILENAME = "fixes.patch"
SUMMARY_FILENAME = "fixes.json"

# Identity used for the fix commit. Fixed, not the operator's git config: the
# commit is authored by the tool, and a clone's config never carries a user anyway.
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "secscan",
    "GIT_AUTHOR_EMAIL": "secscan@users.noreply.github.com",
    "GIT_COMMITTER_NAME": "secscan",
    "GIT_COMMITTER_EMAIL": "secscan@users.noreply.github.com",
}


class FixError(Exception):
    """The fix workspace could not be prepared or read back."""


@dataclass
class FixResult:
    patch: str = ""  # unified diff of the workspace after the agent ran ("" = no change)
    changed_files: list[str] = field(default_factory=list)
    summary: dict = field(default_factory=dict)  # the agent's {"fixes": [...]}, if parseable
    findings: list[Finding] = field(default_factory=list)  # what the agent was asked to fix
    workspace: Path | None = None  # where the edited tree lives (a git repo)
    cost_usd: float = 0.0
    duration_s: float = 0.0
    num_turns: int = 0
    error: str = ""

    @property
    def fix_key(self) -> str:
        return fix_key(self.findings)

    @property
    def fixed_titles(self) -> list[str]:
        return [
            str(f.get("title", "")) for f in self.summary.get("fixes", [])
            if isinstance(f, dict) and f.get("status") == "fixed"
        ]


def fix_key(findings: Iterable[Finding]) -> str:
    """Stable identity of a *set* of findings: the sorted fingerprints, hashed.

    Two runs that ask for the same fixes get the same key, so the PR ledger can
    refuse to open a second pull request for them; a run whose High/Critical set
    changed (a fix merged, a new finding) gets a new key and a new PR.
    """
    fps = sorted({fingerprint(f) for f in findings})
    return hashlib.sha256("\n".join(fps).encode()).hexdigest()


def findings_json(findings: Iterable[Finding]) -> str:
    """The findings as the agent sees them: the fields it needs, nothing else."""
    items = [
        {
            "severity": f.severity.value,
            "title": f.title,
            "category": f.category,
            "file_path": f.file_path,
            "line_range": f.line_range,
            "description": f.description,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]
    return json.dumps(items, indent=2, ensure_ascii=False)


# --- git plumbing --------------------------------------------------------------


def _git_env() -> dict[str, str]:
    env = {**os.environ, **GIT_IDENTITY, "GIT_TERMINAL_PROMPT": "0"}
    # A parent GIT_DIR/GIT_WORK_TREE (e.g. from a hook) must not redirect us.
    env.pop("GIT_DIR", None)
    env.pop("GIT_WORK_TREE", None)
    return env


async def git(*args: str, cwd: Path, check: bool = True, env: dict | None = None) -> str:
    """Run one git command in `cwd`, returning stdout; raises FixError on failure."""
    proc = await asyncio.create_subprocess_exec(
        "git", *args,
        cwd=str(cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env or _git_env(),
    )
    out, err = await proc.communicate()
    if check and proc.returncode != 0:
        raise FixError(f"git {args[0]} failed: {err.decode('utf-8', 'replace').strip()}")
    return out.decode("utf-8", "replace")


async def is_git_repo(path: Path) -> bool:
    try:
        out = await git("rev-parse", "--is-inside-work-tree", cwd=path, check=False)
    except OSError:
        return False
    return out.strip() == "true"


async def current_branch(path: Path) -> str:
    """The checked-out branch name, or "" when detached / not a repo."""
    try:
        out = await git("rev-parse", "--abbrev-ref", "HEAD", cwd=path, check=False)
    except OSError:
        return ""
    name = out.strip()
    return "" if name in ("", "HEAD") else name


async def has_uncommitted_changes(path: Path) -> bool:
    out = await git("status", "--porcelain", cwd=path, check=False)
    return bool(out.strip())


async def prepare_workspace(source: Path, dest_root: Path, name: str) -> Path:
    """A disposable git checkout of `source` for the fixer to edit.

    A git repository is cloned (so its history is intact and a fix branch can later
    be pushed to the same remote); anything else is copied and given a baseline
    commit so `git diff` has something to diff against. `source` itself is never
    written to.
    """
    dest_root = Path(dest_root)
    dest_root.mkdir(parents=True, exist_ok=True)
    dest = dest_root / f"{name}__fix"
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    if await is_git_repo(source):
        await git("clone", "--quiet", "--no-hardlinks", str(source), str(dest), cwd=dest_root)
        return dest

    shutil.copytree(source, dest, symlinks=True)
    await git("init", "--quiet", cwd=dest)
    await git("add", "-A", cwd=dest)
    await git("commit", "--quiet", "--allow-empty", "-m", "secscan: baseline", cwd=dest)
    return dest


async def diff_workspace(workspace: Path) -> tuple[str, list[str]]:
    """(unified diff, changed paths) of everything the agent changed, staged."""
    await git("add", "-A", cwd=workspace)
    patch = await git("diff", "--cached", "--no-color", "--binary", cwd=workspace)
    names = await git("diff", "--cached", "--name-only", cwd=workspace)
    return patch, [ln for ln in names.splitlines() if ln.strip()]


# --- the agent run -------------------------------------------------------------


def _parse_summary(text: str) -> dict:
    from .findings import _extract_json

    data = _extract_json(text) if text else None
    if isinstance(data, dict) and isinstance(data.get("fixes"), list):
        return {"fixes": [f for f in data["fixes"] if isinstance(f, dict)]}
    return {}


async def _run_engine(
    cfg: RunConfig, workspace: Path, full_name: str, payload: str, provider_env: ProviderEnv
) -> AgentRun:
    if cfg.engine == codex.ENGINE_NAME:
        return await codex.fix_repo(
            workspace, full_name, payload,
            cfg=cfg.codex, idle_timeout_s=cfg.timeout_s, skills=cfg.skills,
        )
    if cfg.engine == kimi_cli.ENGINE_NAME:
        return await kimi_cli.fix_repo(
            workspace, full_name, payload,
            cfg=cfg.kimi, idle_timeout_s=cfg.timeout_s, skills=cfg.skills,
        )
    return await claude_fix_repo(
        workspace, full_name, payload,
        model=cfg.model,
        max_turns=cfg.max_turns,
        max_cost_usd=cfg.max_cost_usd,
        extra_env=provider_env.env,
        idle_timeout_s=cfg.timeout_s,
        skills=cfg.skills,
    )


async def fix_findings(
    cfg: RunConfig,
    workspace: Path,
    full_name: str,
    findings: Sequence[Finding],
    provider_env: ProviderEnv,
) -> FixResult:
    """Run the configured engine in write mode over `workspace` and diff the result.

    `workspace` must be a git checkout the caller is happy to have modified (see
    `prepare_workspace`). Nothing here reaches GitHub.
    """
    result = FixResult(findings=list(findings), workspace=Path(workspace))
    if not findings:
        return result
    payload = findings_json(findings)
    run = await _run_engine(cfg, Path(workspace), full_name, payload, provider_env)
    result.cost_usd, result.duration_s, result.num_turns = run.cost_usd, run.duration_s, run.num_turns
    result.error = run.error
    result.summary = _parse_summary(run.text)
    try:
        result.patch, result.changed_files = await diff_workspace(Path(workspace))
    except FixError as exc:
        result.error = result.error or str(exc)
    return result


def write_artifacts(out_dir: Path, result: FixResult) -> tuple[Path, Path]:
    """Persist the patch and the agent's summary next to findings.csv."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    patch_path = out_dir / PATCH_FILENAME
    patch_path.write_text(result.patch, encoding="utf-8")
    summary_path = out_dir / SUMMARY_FILENAME
    summary_path.write_text(
        json.dumps(
            {
                "fix_key": result.fix_key,
                "findings": [
                    {"fingerprint": fingerprint(f), "severity": f.severity.value,
                     "title": f.title, "file_path": f.file_path}
                    for f in result.findings
                ],
                "changed_files": result.changed_files,
                "agent_summary": result.summary,
                "cost_usd": round(result.cost_usd, 4),
                "duration_s": round(result.duration_s, 1),
                "error": result.error,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return patch_path, summary_path


def temp_workspace_root() -> Path:
    return Path(tempfile.mkdtemp(prefix="secscan-fix-"))
