---
name: cicd-and-iac
description: Read-only audit checklist for GitHub Actions and other CI pipelines, Dockerfiles, Kubernetes manifests, Helm charts and Terraform/CloudFormation — the misconfigurations that hand an attacker code execution, secrets or a public exposure. Use when the repository contains .github/workflows, Dockerfiles, k8s/helm manifests or IaC.
license: MIT
metadata:
  informed-by: Trail of Bits agentic-actions-auditor and insecure-defaults (CC-BY-SA-4.0, referenced, not copied); GitHub's own pwn-request and expression-injection guidance
---

# CI/CD pipelines and infrastructure-as-code

Pipelines and manifests are code that runs with secrets and cloud credentials.
Review them with the same source → sink discipline as application code: the
*source* is whatever an external contributor can influence (a pull request, an
issue title, a branch name, a commit message, a fork), the *sink* is a shell,
a checkout, a deploy step or a permission grant.

Start with `Glob` for `.github/workflows/*.yml`, `.gitlab-ci.yml`,
`Jenkinsfile`, `azure-pipelines.yml`, `bitbucket-pipelines.yml`, `Dockerfile*`,
`docker-compose*.yml`, `**/*.tf`, `**/template*.{yml,yaml,json}`
(CloudFormation), `charts/**/values.yaml`, `k8s/**`, `manifests/**`,
`**/deployment*.yaml`.

## GitHub Actions

### Untrusted triggers

Every workflow that runs on one of these triggers is reachable by any GitHub
user who can open a PR, issue or comment against the repository:

`pull_request_target`, `issue_comment`, `issues`, `discussion`,
`discussion_comment`, `workflow_run` (chained after a PR workflow), `fork`,
`watch`, `pull_request` from forks (limited secrets, but still code execution
on the runner).

For each such workflow, check:

1. **Pwn request** — `pull_request_target` (or `workflow_run`) combined with a
   checkout of the PR head (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`
   / `.head.ref` / `refs/pull/N/merge`) followed by anything that executes
   repository content: `npm install`/`npm ci` (lifecycle scripts), `pip install .`,
   `make`, `pre-commit`, a test run, a linter that loads config from the repo.
   The workflow runs with the base repository's secrets and a write token.
   Severity: `critical` (CWE-829 / CWE-94). Report the workflow file and the
   checkout step.
2. **Expression injection** — a GitHub context value that a contributor controls
   interpolated into a `run:` script, a `script:` block of `actions/github-script`,
   or an AI-agent prompt: `${{ github.event.issue.title }}`,
   `.issue.body`, `.pull_request.title`, `.pull_request.body`,
   `.pull_request.head.ref`, `.pull_request.head.repo.*`, `.comment.body`,
   `.review.body`, `.commits[*].message`, `.head_commit.message`,
   `.discussion.*`, `github.head_ref`, `inputs.*` on `workflow_dispatch` when the
   caller is untrusted. Bare `${{ }}` in `run:` is string-substituted *before*
   the shell sees it, so a quote in the title ends the command. Passing the
   value through `env:` and then expanding `"$VAR"` in the shell is the fix —
   unless the env var is later `eval`ed, used in `bash -c`, or fed to a tool
   that performs its own expansion. Severity: `high` with `GITHUB_TOKEN`
   default permissions, `critical` when the job has `contents: write`,
   `id-token: write`, or repository/organization secrets in scope (CWE-78,
   CWE-77).
3. **AI agents in workflows** — steps that invoke an agent (Claude Code Action,
   Gemini CLI, OpenAI Codex, Copilot, GitHub AI inference, or a `curl` to an
   LLM API) and hand it contributor-controlled text (issue body, PR diff,
   comment) while the agent can run tools, push, comment, or approve. Look for:
   the prompt built from `${{ github.event.* }}`, `gh pr view`/`gh issue view`
   output piped into the prompt, `--allowedTools` including `Bash` or write
   tools, `--dangerously-skip-permissions`, a disabled sandbox, and allowlists
   such as `if: contains(fromJSON('["*"]'), github.actor)` that admit anyone.
   Prompt injection here is *not* a theoretical text finding: the sink is a
   tool call with write access. Severity: `high`; `critical` when the agent's
   token can push to protected branches or reach secrets.
4. **Secrets and permissions** — a top-level or job-level `permissions:` block
   granting `write-all` or `contents: write` on an untrusted trigger; secrets
   passed to a step that runs contributor code; `ACTIONS_ALLOW_UNSECURE_COMMANDS`;
   `set-output`/`::set-env` still used with untrusted values; secrets echoed
   through `env` into logs (`env` dump steps). Severity: `high` when combined
   with an untrusted trigger, otherwise `low`.
5. **Mutable action references** — third-party actions pinned to a tag or a
   branch (`uses: some/action@v1`, `@main`) rather than a full commit SHA in a
   job that has secrets or write permissions. Severity: `medium` (supply chain,
   CWE-829); `high` only for an obscure/unmaintained action with secrets in
   scope.
6. **Self-hosted runners** on public repositories with `pull_request` from
   forks: persistent runner compromise. Severity: `high`.
7. **Cache and artifact poisoning** — `actions/cache` keys derived from
   contributor-controlled values in a workflow that later trusts the cache on
   the default branch; artifacts from an untrusted job consumed by a
   privileged `workflow_run` job without validation. Severity: `high`.

### What is *not* a finding

`pull_request` (not `_target`) from the same repository, `${{ }}` inside
`with:` of a well-known action that treats it as data, `workflow_dispatch`
guarded by branch protection, missing `permissions:` on a workflow that only
runs tests.

## Other CI systems

Apply the same three questions to GitLab CI (`rules` on merge requests from
forks + `$CI_MERGE_REQUEST_TITLE` etc. in `script:`), Jenkins (`Jenkinsfile`
using `env.CHANGE_TITLE` in `sh`), Azure Pipelines (`$(Build.SourceVersionMessage)`
in `script:`), Bitbucket and CircleCI. `curl … | bash` and `wget … | sh` in any
pipeline step with secrets is `high` (CWE-494) unless the URL is pinned to a
content hash.

## Dockerfiles and compose

- Secrets baked into the image: `ENV`/`ARG` with real tokens, `COPY .env`,
  `COPY id_rsa`, `RUN echo "$PASSWORD" >`, secrets in `docker-compose.yml`
  `environment:` committed to the repo. Severity: `high` (CWE-798); `critical`
  if the image is published (a `docker push` step, a registry reference).
- `curl | sh` at build time, `--allow-untrusted`/`--no-check-certificate`,
  `pip install --trusted-host`, disabled GPG checks: `medium`, `high` with
  a published image.
- Running as root, no `USER`, `latest` base tags, `--privileged` and
  `network_mode: host` in compose, mounting the Docker socket
  (`/var/run/docker.sock`): container escape only matters if the container
  runs untrusted input; `high` for a socket mount in a service that handles
  user requests, otherwise `low`.

## Kubernetes and Helm

- `securityContext.privileged: true`, `hostPID`/`hostNetwork`/`hostIPC: true`,
  `hostPath` mounts of `/`, `/var/run/docker.sock`, `/etc`, capabilities
  `SYS_ADMIN`, `allowPrivilegeEscalation: true` on a workload that processes
  external requests: `high` (CWE-250).
- Secrets in `ConfigMap`, in `values.yaml`, in plain `env:` `value:` fields, or
  committed `Secret` manifests with real base64 values: `high` (CWE-312/798).
- RBAC: `ClusterRoleBinding` to `cluster-admin`, `Role` with `verbs: ["*"]`
  on `secrets` or `pods/exec`, service account tokens auto-mounted into a
  workload that does not need them: `high` when bound to an internet-facing
  workload, otherwise `medium`.
- `Ingress`/`Service type: LoadBalancer` exposing admin dashboards
  (Kubernetes Dashboard, Argo, Grafana with anonymous auth, Jenkins) without
  auth annotations: `high`.
- Missing resource limits, missing network policies, `imagePullPolicy`,
  liveness probes: not security findings.

## Terraform, CloudFormation, Pulumi, ARM/Bicep

- Ingress `0.0.0.0/0` or `::/0` on 22, 3389, 3306, 5432, 6379, 27017, 9200,
  2375 or `-1`/all ports: `high` (CWE-284). The same on 80/443 of a web tier
  is expected.
- Public storage: `acl = "public-read"`, `block_public_acls = false`,
  `PublicAccessBlockConfiguration` missing, `allUsers`/`allAuthenticatedUsers`
  IAM members on buckets, Azure `allow_blob_public_access`, `container_access_type = "blob"`
  on data that is not meant to be public: `high`; `critical` for a bucket that
  the code writes user data or backups into.
- IAM/RBAC: `Action: "*"` + `Resource: "*"` policies attached to compute roles
  or users, `iam:PassRole` on `*`, `sts:AssumeRole` trust to `"AWS": "*"`,
  wildcard `Principal` on resource policies, GCP `roles/owner` on service
  accounts: `high`.
- Hardcoded credentials in `.tfvars`, `provider` blocks (`access_key =`,
  `secret_key =`, `client_secret =`), `terraform.tfstate` committed with
  secrets: `high`/`critical` (CWE-798).
- Databases/caches with `publicly_accessible = true`, `storage_encrypted = false`
  on regulated data, `skip_final_snapshot`, `deletion_protection = false`:
  encryption-at-rest gaps are `medium`; a public database with a weak or
  hardcoded master password is `critical`.
- Logging disabled, versioning off, KMS key rotation off, default VPC use: `low`.

## Output discipline

- `file_path` is the workflow/manifest/module file; `line_range` the trigger,
  step, resource or attribute.
- In `description`, name the untrusted source (e.g. "PR title from a fork"),
  the sink (e.g. "`run:` step with `contents: write`") and the token/secret
  scope the attacker obtains.
- `recommendation` should be the specific fix: switch to `pull_request`, move
  the value to `env:` and quote it, pin the action to a SHA, set
  `permissions: read-all`, block public access, tighten the CIDR, move the
  secret to a secret manager.
