---
name: llm-app-security
description: Review checklist for code that calls LLMs or runs agents — prompt injection that reaches tools with side effects, LLM output fed into shells/SQL/HTML/eval, excessive agency, leaked system prompts and keys, MCP server exposure and RAG data boundaries. Use when the repository imports an LLM SDK, an agent framework, or an MCP server library.
license: MIT
metadata:
  standards: OWASP Top 10 for LLM Applications (2025), OWASP Agentic AI threats (2026), CWE
---

# LLM and agent application security

Detect the surface first: `Grep` for `anthropic`, `openai`, `claude_agent_sdk`,
`langchain`, `llama_index`, `litellm`, `vercel/ai`, `@ai-sdk`, `google.generativeai`,
`mistral`, `ollama`, `bedrock-runtime`, `mcp`, `FastMCP`, `@modelcontextprotocol`,
`tool_use`, `function_call`, `tools=[`, `system_prompt`, `messages=[`.
If nothing matches, this skill does not apply — say nothing and move on.

The security model is the same as for any other untrusted input: **model output
is attacker-influenced whenever any model input is attacker-influenced.** Treat
text returned by a model as you would treat a request body. The question for
every finding is what *sink* that text reaches and what *authority* the process
holds when it gets there.

## LLM01 Prompt injection → tool with side effects

- Locate: where prompts are assembled from external data — user messages,
  documents, web pages, emails, tickets, repository files, RAG chunks, tool
  results — and which tools, functions or actions the model can trigger from
  that context: shell/`subprocess`, HTTP requests, file writes, database
  writes, sending email/messages, payments, git push, cloud SDK calls, "run
  code" sandboxes.
- Evidence: an attacker who controls part of the context can cause a tool call
  that changes state or exfiltrates data, and the code does not confirm with a
  human, restrict the tool set, or validate the tool arguments independently of
  the model. A read-only tool set (as secscan's own reviewer uses) is not a
  finding.
- Severity: `high` when the tool can write, send, spend or exfiltrate;
  `critical` when it runs arbitrary commands or holds broad credentials
  (CWE-77/CWE-94 via the model, or CWE-863 for authority the model should not
  have).

## LLM02 Sensitive information disclosure

- Locate: system prompts containing API keys, internal URLs, credentials or
  customer data; prompts that include other users' records; logging of full
  prompts/completions; model output returned verbatim to a different tenant.
- Evidence: the secret is real and reachable (a `system=` string with a live
  key, a prompt template pulling `SELECT * FROM users`), or a cross-tenant
  leak path exists.
- Severity: `high` for live credentials in prompts or logs (CWE-532/798);
  `critical` for cross-tenant data reachable by any user.

## LLM05 Improper output handling

- Locate: model output passed to `eval`/`exec`/`new Function`, `subprocess`
  with `shell=True`, SQL string building, `innerHTML`/`dangerouslySetInnerHTML`
  /`|safe`/`Markup`, `open()` with a model-chosen path, `os.system`, HTTP
  requests to a model-chosen URL, `json.loads` followed by attribute access
  that drives authorization, redirects.
- Evidence: the sink is reached without validation. "Structured output" or a
  JSON schema does not sanitize the *values*.
- Severity: `critical` for command/code execution; `high` for SQLi, SSRF, path
  traversal or stored XSS through model output (CWE-78/89/918/22/79).

## LLM06 Excessive agency

- Locate: agents given `bypassPermissions`, `--dangerously-skip-permissions`,
  `allowed_tools` containing `Bash`/`Write`/`Edit` alongside untrusted context,
  credentials with broad scope (an org-wide GitHub token, `AdministratorAccess`,
  a payment key) loaded into the agent's environment, autonomous loops with
  no budget or turn cap, sub-agent spawning without restriction.
- Evidence: the *combination* of untrusted input, a powerful tool and a broad
  credential in one process. Any one alone is a design note, not a finding.
- Severity: `high` (CWE-250/CWE-269); `critical` when reachable by
  unauthenticated users.

## LLM07 System prompt leakage

Only reportable when the prompt contains something whose disclosure matters
(credentials, security rules that can then be bypassed, hidden pricing logic);
the prompt text itself being recoverable is `info`.

## LLM08 Vector and embedding weaknesses (RAG)

- Locate: vector store queries lacking a tenant/ACL filter, ingestion of
  documents from untrusted sources without provenance, retrieval results
  inserted into prompts that drive tools.
- Evidence: a query that returns any tenant's chunks (CWE-284), or poisoned
  content reaching an LLM01 sink.
- Severity: `high` for cross-tenant retrieval; otherwise fold into LLM01.

## LLM03/04 Supply chain and data poisoning

Model or adapter files loaded with `torch.load`/`pickle` from a downloadable
location (CWE-502, `high` if the source is attacker-influenced), `trust_remote_code=True`
on hub downloads (`medium`), unpinned model names in production (`low`).

## LLM10 Unbounded consumption

Missing token/turn/cost caps and rate limits on LLM calls are **not** reported
(the false-positive filter excludes DoS); mention them as `info` only if they
also enable a billing attack against a third party's key.

## MCP servers and tool servers

- Locate: `FastMCP`, `Server(`, `@mcp.tool`, `@server.tool`, tool handlers
  that run commands, read/write files, or call HTTP with arguments from the
  model; transport setup (`stdio`, `sse`, `streamable-http`), bind address,
  auth middleware, `Origin` checks.
- Evidence: a tool handler that reaches a dangerous sink with unvalidated
  arguments (path not confined to a root, command built from a string, URL
  without allowlist), an HTTP/SSE transport bound on `0.0.0.0` or without
  authentication and origin validation (DNS-rebinding), tool descriptions that
  instruct the calling model to do something outside the tool's purpose
  (tool poisoning, report as `medium`).
- Severity: `critical` for unauthenticated remote command execution through a
  tool; `high` for path traversal / SSRF / file write through a tool
  (CWE-22/918/78/306).

## Agent frameworks and SDKs (Claude Agent SDK, LangChain, AutoGen, CrewAI…)

- Check permission mode, tool allow/deny lists, `setting_sources`/project
  config loading from untrusted working directories (a repo's `.claude/`
  or `.cursor/` rules executing hooks), hooks that run shell commands,
  `cwd` set to attacker-controlled paths, and whether repository files are
  treated as instructions.
- A hook or config loaded from an untrusted directory that executes commands
  is `high` (CWE-94).

## What is not a finding

- Prompt-injection *strings* found in data files (note as `info` at most).
- Jailbreak susceptibility, hallucination, bias, or model-quality issues.
- Missing content moderation, unless it gates a security decision.
- Using a third-party LLM API at all.

## Output discipline

Name the untrusted context source, the model call, the sink and the authority
(token/credential/scope) in `description`; recommend a concrete control in
`recommendation`: read-only or allowlisted tools, argument validation
independent of the model, human confirmation for side effects, least-privilege
credentials, per-tenant retrieval filters, authentication on the transport.
