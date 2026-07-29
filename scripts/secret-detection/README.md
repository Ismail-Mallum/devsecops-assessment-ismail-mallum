# Secret Detection Engine

Scans source code for hardcoded secrets: API keys, passwords, bearer tokens, private keys, and other sensitive credentials. Produces actionable reports with confidence scores and Shannon-entropy analysis to reduce false positives.

## Features

| Capability | Detail |
|---|---|
| **Supported file types** | `.java` `.js` `.ts` `.json` `.yml` `.yaml` `.env` `.properties` `.xml` `.sh` `.conf` `.ini` `.toml` |
| **Detection rules** | 17 rules covering AWS, GCP, Azure, GitHub, Slack, Stripe, Twilio, JWT, DB connection strings, PEM keys |
| **Confidence scoring** | HIGH / MEDIUM / LOW based on regex match + Shannon entropy |
| **False-positive filtering** | Placeholder/example values suppressed automatically |
| **Output formats** | Human-readable text or machine-readable JSON |
| **CI/CD integration** | Exit code `1` when findings meet or exceed `--fail-on` threshold |

## Requirements

Python 3.11+. No third-party libraries required (stdlib only).

```bash
# Confirm Python version
python --version
```

## Usage

### Basic scan (text output)

```bash
python detect_secrets.py --path ./application/src
```

### JSON output for CI pipelines

```bash
python detect_secrets.py --path ./application/src --format json --output report.json
```

### Adjust minimum confidence level

```bash
# Only report HIGH confidence findings
python detect_secrets.py --path ./application/src --min-confidence HIGH
```

### Fail the build only on HIGH findings (allow MEDIUM)

```bash
python detect_secrets.py --path ./application/src --fail-on HIGH
```

### Include likely-false-positive findings

```bash
python detect_secrets.py --path ./application/src --include-fp
```

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` threshold |
| `1` | Findings detected — pipeline should fail |
| `2` | Script error (bad path, etc.) |

## CLI Reference

```
usage: detect_secrets.py [-h] --path PATH [--format {text,json}]
                         [--output OUTPUT]
                         [--min-confidence {HIGH,MEDIUM,LOW}]
                         [--include-fp]
                         [--fail-on {HIGH,MEDIUM,LOW,NONE}]

options:
  --path, -p            Directory or file to scan (required)
  --format, -f          Output format: text (default) or json
  --output, -o          Write report to file instead of stdout
  --min-confidence      Minimum confidence level to include in report (default: LOW)
  --include-fp          Include findings flagged as likely false positives
  --fail-on             Exit 1 when findings at this level exist (default: MEDIUM)
```

## Confidence Scoring

Each finding is assigned a confidence level:

- **HIGH** — Pattern strongly matches a known secret format (e.g. `AKIA...` for AWS, `ghp_` for GitHub tokens) **and** the value's Shannon entropy is above 4.5 bits/char.
- **MEDIUM** — Pattern matches a generic credential variable but entropy or context is ambiguous.
- **LOW** — Pattern matched but the value looks like a placeholder or has low entropy. Likely a false positive — review manually.

False-positive filters suppress findings where the value:
- Contains words like `placeholder`, `changeme`, `example`, `YOUR_KEY_HERE`
- Is a repeated character (e.g. `xxxxxxxxxxxx`)
- Is a template variable (`${SECRET}`, `{{API_KEY}}`)
- Is a reference to an environment variable (`process.env.KEY`, `System.getenv(...)`)

## JSON Report Schema

```json
{
  "scan_path": "/abs/path/to/scanned/dir",
  "scan_timestamp": "2026-07-29T10:00:00+00:00",
  "files_scanned": 42,
  "findings_count": 2,
  "high_count": 1,
  "medium_count": 1,
  "low_count": 0,
  "passed": false,
  "findings": [
    {
      "rule_id": "AWS_ACCESS_KEY",
      "description": "AWS Access Key ID",
      "file": "src/config/AppConfig.java",
      "line_number": 14,
      "line_snippet": "  String awsKey = \"AKIA***REDACTED***\";",
      "matched_value": "AKIA***REDACTED***",
      "confidence": "HIGH",
      "entropy": 4.891,
      "false_positive_filtered": false
    }
  ]
}
```

> **Note:** Secret values are always partially redacted in output to prevent leaking credentials into CI logs.

## Security Decisions

1. **No external dependencies** — stdlib-only eliminates supply-chain risk from the scanner itself.
2. **Output redaction** — Matched secret values are truncated to 4 characters + `***REDACTED***` so CI logs never contain full credentials.
3. **Entropy gating** — Shannon entropy analysis prevents high-volume noise from generic keyword matches, reducing alert fatigue.
4. **Comment-line skipping** — Lines beginning with `#`, `//`, `*`, or `<!--` are skipped; documentation examples should not trigger alerts.
5. **File size cap** — Files larger than 512 KB are skipped to prevent memory exhaustion on large binary or generated files accidentally given a text extension.

## Integration with GitHub Actions

```yaml
- name: Scan for secrets
  run: |
    python scripts/secret-detection/detect_secrets.py \
      --path . \
      --format json \
      --output secret-scan-report.json \
      --fail-on HIGH

- name: Upload secret scan report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: secret-scan-report
    path: secret-scan-report.json
```
