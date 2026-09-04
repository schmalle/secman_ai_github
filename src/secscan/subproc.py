"""Run an external agent CLI as a subprocess, streaming its output line by line.

Shared by the engines that drive a third-party command (`codex exec`, `kimi --print`,
`codescanai`). It provides the one behaviour they all need and that is easy to get
wrong: an **idle timeout** — abort when the child prints nothing for `idle_timeout_s`
seconds — rather than a cap on total duration, since a legitimate review can run for
a long time while a stalled one (waiting on a prompt nobody can answer, a hung
connection) is silent. Stdout and stderr are pumped concurrently so neither pipe can
fill up and deadlock the child; the caller gets every line through `on_line`, in
arrival order, and the full transcript afterwards.

The prompt, when there is one, goes in through stdin: it can be tens of kilobytes
once skill packs are appended, and a command-line argument that size is at the mercy
of the platform's argv limits (and visible in `ps`).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable, Mapping


@dataclass
class StreamResult:
    returncode: int | None = None
    stdout: list[str] = field(default_factory=list)
    stderr: list[str] = field(default_factory=list)
    timed_out: bool = False
    start_error: str = ""  # the executable could not be started at all

    @property
    def stderr_tail(self) -> str:
        return next((ln for ln in reversed(self.stderr) if ln.strip()), "")


async def _pump(stream: asyncio.StreamReader, tag: str, queue: asyncio.Queue) -> None:
    try:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            await queue.put((tag, raw.decode("utf-8", "replace").rstrip("\r\n")))
    finally:
        await queue.put((tag, None))


async def _feed_stdin(proc: asyncio.subprocess.Process, text: str) -> None:
    assert proc.stdin is not None
    try:
        proc.stdin.write(text.encode("utf-8"))
        await proc.stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass  # the child exited before reading everything; its exit status tells why
    finally:
        try:
            proc.stdin.close()
        except Exception:
            pass


async def run_streaming(
    argv: list[str],
    *,
    cwd: Path | str | None,
    env: Mapping[str, str],
    idle_timeout_s: float | None,
    stdin_text: str | None = None,
    on_line: Callable[[str, str], None] | None = None,
) -> StreamResult:
    """Run `argv` to completion, or until it is silent for `idle_timeout_s` seconds.

    `on_line(tag, line)` is called for every line as it arrives (`tag` is "out" or
    "err"). On an idle timeout the child is killed and `timed_out` is set; the lines
    received up to that point are still returned.
    """
    result = StreamResult()
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=str(cwd) if cwd is not None else None,
            env=dict(env),
            stdin=asyncio.subprocess.PIPE if stdin_text is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        result.start_error = f"cannot start {argv[0]}: {exc}"
        return result

    queue: asyncio.Queue = asyncio.Queue()
    tasks = [
        asyncio.create_task(_pump(proc.stdout, "out", queue)),
        asyncio.create_task(_pump(proc.stderr, "err", queue)),
    ]
    if stdin_text is not None:
        tasks.append(asyncio.create_task(_feed_stdin(proc, stdin_text)))

    open_streams = 2
    try:
        while open_streams:
            if idle_timeout_s:
                tag, line = await asyncio.wait_for(queue.get(), timeout=idle_timeout_s)
            else:
                tag, line = await queue.get()
            if line is None:
                open_streams -= 1
                continue
            (result.stdout if tag == "out" else result.stderr).append(line)
            if on_line is not None:
                on_line(tag, line)
    except asyncio.TimeoutError:
        result.timed_out = True
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    result.returncode = await proc.wait()
    return result


# Environment variables that carry no secret and that any of the CLI engines may
# need: to find its executable and its own on-disk credentials (PATH/HOME), for
# locale and temp-dir plumbing, and to reach its API through a corporate proxy or a
# private CA. Everything else in secscan's own environment — GitHub App key, PAT,
# DB/secman/SMTP passwords, the credentials of the *other* engines — stays out.
BASE_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TMPDIR",
        "TERM",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "NODE_EXTRA_CA_CERTS",
    }
)


def minimal_env(extra_names: frozenset[str] | set[str] = frozenset()) -> dict[str, str]:
    """Copy only allowlisted variables (plus `extra_names`) out of os.environ."""
    import os

    wanted = BASE_ENV_ALLOWLIST | set(extra_names)
    return {name: os.environ[name] for name in wanted if name in os.environ}
