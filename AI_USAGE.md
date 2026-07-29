# AI / LLM Usage Disclosure

This file documents all AI tool usage during this assessment, as required by the
submission guidelines.

---

## Tool Used

**GitHub Copilot** (Claude Sonnet 4.6) via VS Code Copilot Chat

---

## Block 1 — Secret Detection Engine

### Prompt
> I am completing a DevSecOps Technical Assessment. Block 1: Secret Detection Engine
> (Python script). Detects API keys, passwords, tokens in Java/JS/JSON/YAML files.
> Confidence scoring, false-positive filtering, JSON output.
> Deliverables: scripts/secret-detection/detect_secrets.py + README + 3 test cases.

### Output received
- `scripts/secret-detection/detect_secrets.py` — full Python scanner (~320 lines)
- `scripts/secret-detection/README.md`
- Three test case files (`test_real_secrets.java`, `test_false_positives.js`, `test_mixed.yml`)

### Modifications made
- After running the scanner against all three test files, `YOUR_GITHUB_TOKEN_HERE` and
  `xoxb-YOUR-SLACK-TOKEN` were not being filtered as false positives on first pass.
- Tightened the false-positive regex pattern to include `\bYOUR\b` and `\bHERE\b`
  as suppression triggers.
- Re-ran scanner to verify correct exit codes and JSON schema before accepting output.

---

## Block 2 — Pipeline Security

### Prompt
> Block 2: Pipeline Security. File: .github/workflows/secure-pipeline.yml.
> Scanners: CodeQL (SAST) + Dependency Review Action (SCA) + Gitleaks (secrets) +
> Trivy (vulnerabilities). Quality gates: CRITICAL = fail, HIGH = fail,
> MEDIUM/LOW = warn. Secrets = always fail.

### Output received
- `.github/workflows/secure-pipeline.yml` — GitHub Actions workflow with four jobs:
  `secret-scan`, `sast-scan`, `dependency-scan`, `quality-gate`

### Modifications made
- Reviewed all job permissions for least-privilege correctness.
- Verified `if: always()` placement on the `quality-gate` job is correct to ensure
  the merge gate always produces a result even when upstream jobs fail.

---

## Block 3 — Container Security

### Prompt
> Block 3: Container Security. application/Dockerfile (multi-stage, non-root,
> minimal base image). infrastructure/docker-compose.yml (security hardening).
> Focus: Java backend service (country-service-main / Spring Boot 3.4.3 / Java 11).

### Output received
- `application/Dockerfile` — multi-stage build with eclipse-temurin:11-jre-alpine runtime
- `infrastructure/docker-compose.yml` — hardened Compose config
- `infrastructure/.env.example`

### Modifications made
- Verified Maven artifact name (`country-service-0.0.1-SNAPSHOT.jar`) against the
  actual `pom.xml` before accepting the COPY instruction in the Dockerfile.
- Confirmed `HEALTHCHECK` endpoint (`/actuator/health`) is valid for a Spring Boot
  app with `spring-boot-starter-web` present.

---

## Block 6 — Architecture Design

### Prompt
> Block 6: Architecture Design. docs/architecture-design.md. Current state analysis
> of the app + target DevSecOps architecture. Mermaid diagram + implementation roadmap.
> Tool justification. Include real findings from pom.xml analysis.

### Output received
- `docs/architecture-design.md` — full architecture document with Mermaid diagrams,
  7 findings from current-state analysis, 4-phase roadmap, tool justification table,
  scalability considerations, and cost/complexity trade-off analysis.

### Modifications made
- All 7 current-state findings were verified against the actual `pom.xml` before
  including (e.g. `spring-boot-devtools` runtime scope, `spring-boot-starter-security`
  version `2.7.0` pinned against a Boot 3.4.3 parent, H2 in runtime scope).
- Architecture document reflects the actual tools used in Blocks 1–3, not generic
  placeholder tool names.

---

## Summary

All four blocks were generated with AI assistance. Every generated file was:

1. Read and understood before committing
2. Validated against the actual source repository (pom.xml, app structure)
3. Tested where applicable (Block 1 scanner run against all three test cases)
4. Modified where the first output was incorrect (Block 1 false-positive filter,
   Block 2 HIGH severity gate)

The AI was used as a productivity tool within a timed assessment context. All
security reasoning, design decisions, and trade-off justifications reflect genuine
understanding of DevSecOps principles and were verified before submission.
