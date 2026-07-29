# DevSecOps Technical Assessment — Ismail Mallum

## Blocks Completed

- [x] Block 1: Security Automation — Secret Detection Engine
- [x] Block 2: Pipeline Security — GitHub Actions with Gitleaks + Trivy
- [x] Block 3: Container Security — Multi-stage Dockerfile + Docker Compose
- [x] Block 6: Architecture Design — DevSecOps target architecture

## Repository Structure

```
devsecops-assessment-ismail-mallum/
├── .github/workflows/
│   └── secure-pipeline.yml        # Block 2 — CI/CD with security gates
├── application/
│   ├── src/
│   │   ├── country-service-main/  # Java Spring Boot (provided)
│   │   └── country-flags-app-main/# JavaScript React (provided)
│   └── Dockerfile                 # Block 3 — Multi-stage, non-root
├── scripts/
│   └── secret-detection/
│       ├── detect_secrets.py      # Block 1 — Secret scanner
│       ├── README.md
│       └── test-data/             # 3 test cases
├── infrastructure/
│   └── docker-compose.yml         # Block 3 — Hardened deployment config
├── docs/
│   └── architecture-design.md     # Block 6 — DevSecOps architecture
├── .gitignore
└── README.md
```

## Source Application

Cloned from [kamo62/assess](https://github.com/kamo62/assess):
- **country-service-main** — Java Spring Boot REST API serving country data
- **country-flags-app-main** — JavaScript React frontend consuming the API

## Approach Summary

Selected blocks that demonstrate the full DevSecOps lifecycle:
- **Block 1** establishes the security automation foundation (shift-left secret detection)
- **Block 2** integrates security into CI/CD with automated quality gates
- **Block 3** hardens the runtime environment through container security
- **Block 6** ties everything together with a strategic architecture view

All tools chosen prioritise open-source, widely-adopted solutions with strong GitHub Actions integration.

## Tool Choices

| Block | Tool | Reason |
|---|---|---|
| Secret scanning | Custom Python engine + Gitleaks | stdlib scanner for portability; Gitleaks for CI coverage |
| Vulnerability scanning | Trivy | Single tool covering OS packages, language deps, and IaC |
| Container base image | Eclipse Temurin (Alpine) | Minimal attack surface; well-maintained official image |
| IaC | Docker Compose | Sufficient for assessment scope; production path would be Kubernetes |

## AI/LLM Usage

See [AI_USAGE.md](AI_USAGE.md) for full prompt and modification log.
