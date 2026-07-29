# Security Decisions

Documents the rationale behind key security decisions made during this assessment.
Each decision includes the context, alternatives considered, and justification.

---

## Decision 1 — Severity-based quality gates

**Context:** The CI pipeline must decide when to block a merge vs. when to warn.

**Decision:**

| Severity | Action |
|---|---|
| Secrets detected | Always fail — no threshold |
| CRITICAL CVE | Fail — block merge |
| HIGH CVE | Fail — block merge |
| MEDIUM CVE | Warn — annotate, do not block |
| LOW CVE | Warn — annotate, do not block |

**Rationale:** CRITICAL and HIGH vulnerabilities have known exploits or significant
impact. Allowing them to reach `main` creates compounding technical debt — the longer
a HIGH CVE sits in production, the higher the probability it is exploited. MEDIUM and
LOW are tracked as warnings to avoid alert fatigue; they appear in scan reports and
artifact uploads without blocking developer velocity.

**Alternatives considered:** Fail on MEDIUM — rejected because a significant number
of MEDIUM CVEs in transitive dependencies have no upstream fix available yet. Failing
on unfixable issues erodes team confidence in the pipeline.

---

## Decision 2 — CodeQL for SAST

**Context:** Static Application Security Testing must be integrated into the pipeline.

**Decision:** Use GitHub CodeQL.

**Rationale:**
- Free for public repositories — zero additional cost.
- Deep data-flow and taint analysis; goes beyond pattern matching to track how
  user-controlled data flows through the application to sinks (SQL queries, file I/O,
  HTTP responses).
- Native GitHub integration: results surface directly in the Security tab and as
  PR annotations without additional tooling.
- Maintained by GitHub/Microsoft with a large community query library.

**Alternatives considered:**
- Semgrep — faster, more configurable, but shallower analysis. Better suited for
  enforcing custom coding standards than finding deep vulnerabilities.
- SonarQube — comprehensive, but requires a hosted server or SonarCloud subscription
  for private use beyond the free tier.

---

## Decision 3 — Dependency Review Action for SCA

**Context:** Software Composition Analysis must catch vulnerable dependencies before
they merge into `main`.

**Decision:** Use the GitHub Dependency Review Action.

**Rationale:**
- Runs on Pull Requests and compares the dependency graph of the base branch vs. the
  head branch — it only alerts on *newly introduced* vulnerable dependencies, not
  pre-existing ones. This eliminates noise from legacy debt while still blocking new
  risk from entering.
- Zero configuration required for Maven and npm projects — GitHub's dependency graph
  parser handles both `pom.xml` and `package.json` natively.
- Results appear directly in the PR diff, giving the developer immediate context
  about which dependency change introduced the vulnerability.

**Alternatives considered:**
- OWASP Dependency Check — thorough but produces verbose reports and runs slower in
  CI. Better suited as a scheduled weekly scan than a PR gate.
- Snyk — excellent UX and fix suggestions, but requires a paid plan for team usage
  beyond the free tier.

---

## Decision 4 — Least-privilege workflow permissions

**Context:** GitHub Actions workflows run with a `GITHUB_TOKEN` that can be scoped
to specific permissions.

**Decision:** Set `permissions: contents: read` at the workflow level as the default.
Grant additional permissions per-job only where required:

| Job | Extra permissions | Reason |
|---|---|---|
| `secret-scan` | `security-events: write` | Upload SARIF to Security tab |
| `sast-scan` | `security-events: write` | Upload CodeQL results |
| `dependency-scan` | `pull-requests: write` | Post Dependency Review PR comment |

**Rationale:** If a malicious dependency or compromised action gains code execution
within a workflow step, it inherits the job's token permissions. A token with
`contents: write` and no other restrictions could push to the repository, create
releases, or delete branches. Restricting to the minimum required permission limits
the blast radius of a supply-chain attack on the pipeline itself.

**Alternatives considered:** Leaving the default `permissions` block absent — rejected
because GitHub's default is `contents: write` for classic repositories, which is
unnecessarily broad.

---

## Decision 5 — Multi-stage Dockerfile with JRE-only runtime

**Context:** The container image must be minimal to reduce the attack surface.

**Decision:** Two-stage build: `eclipse-temurin:11-jdk-alpine` for build,
`eclipse-temurin:11-jre-alpine` for runtime.

**Rationale:** The JDK stage contains `javac`, `jmap`, `jstack`, `jconsole`, and the
full Maven toolchain. None of these are needed at runtime. If an attacker gains
remote code execution inside the container, these tools provide a significant
post-exploitation advantage. The JRE-only runtime image removes them entirely.
Alpine as the base OS reduces the image from ~300 MB (debian-slim) to ~90 MB and
removes hundreds of packages that represent potential CVE surface.

**Alternatives considered:**
- Distroless (Google) — even more minimal (no shell, no package manager), but removes
  the ability to `exec` into the container for legitimate debugging. Rejected as too
  operationally restrictive for an assessment context.
- Ubuntu base — larger attack surface, not justified by any functional requirement.

---

## Decision 6 — Non-root container user (UID 1001)

**Context:** Containers run as root by default unless explicitly configured otherwise.

**Decision:** Create `appuser` with UID/GID 1001 in the Dockerfile and enforce it in
`docker-compose.yml` via `user: "1001:1001"`.

**Rationale:** A process running as root inside a container has UID 0. If the
container runtime has a vulnerability (e.g. a `runc` escape), a root container
process can escalate to root on the host. A non-root user limits this blast radius.
The explicit UID/GID prevents accidental UID collisions with host system users and
ensures consistent identity across environments (dev, CI, staging, production).

---

## Decision 7 — Shannon entropy for secret confidence scoring

**Context:** Regex patterns alone cannot distinguish real secrets from placeholder
values in source code (e.g. `API_KEY="YOUR_KEY_HERE"` vs `API_KEY="AIzaSyD..."`).

**Decision:** Combine regex pattern matching with Shannon entropy analysis.
Values scoring below 3.5 bits/character are downgraded to LOW confidence.
Values scoring above 4.5 bits/character are promoted to HIGH confidence.

**Rationale:** Real cryptographic secrets (API keys, tokens, private keys) are
generated from high-entropy random sources and consistently score ≥ 4.5 bits/char.
Human-readable placeholders (`changeme`, `YOUR_KEY_HERE`, `xxxx`) have low entropy
and score ≤ 3.0 bits/char. This heuristic dramatically reduces false positives
without requiring a manually maintained allowlist.
