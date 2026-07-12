# Claude Code Agent Context

`secscan` — enumerates GitHub App/PAT-reachable repositories, runs autonomous Claude
Code security reviews over them, and writes High/Critical findings as CSV (+ optional
SQLite/MySQL state, GitHub issues, secman push).

## secman integration

`secscan` pushes findings into [secman](https://github.com/schmalle/secman), a
separate security requirement/vulnerability management platform, via its
`POST /api/vulnerabilities/cli-add` endpoint. Whenever code touching that
integration changes (the secman push command, its client, credential handling,
or the request/response shape), **check the `secman` repository** — its API
contract, auth requirements, or `cli-add` behavior may have moved — before
assuming the existing integration still matches.
