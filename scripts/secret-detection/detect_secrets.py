#!/usr/bin/env python3
"""
Secret Detection Engine
=======================
Scans source code for hardcoded secrets: API keys, passwords, tokens, and other
sensitive credentials. Produces actionable JSON reports with confidence scores.

Supports: .java, .js, .ts, .json, .yml, .yaml, .env, .properties, .xml

Usage:
    python detect_secrets.py --path ./app
    python detect_secrets.py --path ./app --format json --output report.json
    python detect_secrets.py --path ./app --min-confidence MEDIUM

Exit codes:
    0 = No findings at or above threshold
    1 = Findings detected (pipeline gate)
    2 = Script error
"""

import argparse
import json
import math
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# File extensions to scan. Only scan text-based source/config files.
SCANNABLE_EXTENSIONS: set[str] = {
    ".java", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".yml", ".yaml",
    ".env", ".properties", ".xml",
    ".sh", ".bash", ".conf", ".config", ".ini", ".toml",
}

# Directories to always skip (build artefacts, package caches, VCS metadata).
SKIP_DIRECTORIES: set[str] = {
    ".git", "node_modules", "vendor", "target", "build",
    "__pycache__", ".gradle", ".mvn", "dist", "out",
}

# Maximum individual file size to scan (prevents scanning huge binary blobs).
MAX_FILE_BYTES: int = 512 * 1024  # 512 KB

# Minimum Shannon entropy to flag a potential secret value.
# Legitimate secret values are high-entropy random strings; placeholder values
# (e.g. "changeme", "xxxx", "YOUR_KEY_HERE") have low entropy.
ENTROPY_THRESHOLD_HIGH: float = 4.5
ENTROPY_THRESHOLD_MEDIUM: float = 3.5

# ---------------------------------------------------------------------------
# Secret pattern registry
# Each entry: (rule_id, description, regex_pattern, base_confidence)
# The regex MUST contain a named group `secret` capturing the sensitive value.
# ---------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, str, str, str]] = [
    # --- Cloud provider credentials ---
    (
        "AWS_ACCESS_KEY",
        "AWS Access Key ID",
        r"(?i)(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "HIGH",
    ),
    (
        "AWS_SECRET_KEY",
        "AWS Secret Access Key",
        r'(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key[\s]*[=:"\s]+(?P<secret>[A-Za-z0-9/+]{40})',
        "HIGH",
    ),
    (
        "AZURE_CLIENT_SECRET",
        "Azure client secret / SAS token",
        r'(?i)(?:client[_\-]?secret|azure[_\-]?key|AZURE_CLIENT_SECRET)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9+/\-_.~]{20,})["\']?',
        "HIGH",
    ),
    (
        "GCP_API_KEY",
        "Google Cloud / GCP API key",
        r'(?i)AIza(?P<secret>[0-9A-Za-z\-_]{35})',
        "HIGH",
    ),

    # --- Generic API / bearer tokens ---
    (
        "GENERIC_API_KEY",
        "Generic API key assignment",
        r'(?i)(?:api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?key)\s*[=:]\s*["\']?(?P<secret>[A-Za-z0-9\-_]{16,})["\']?',
        "MEDIUM",
    ),
    (
        "BEARER_TOKEN",
        "Bearer / Authorization token",
        r'(?i)(?:bearer\s+|Authorization\s*:\s*Bearer\s+)(?P<secret>[A-Za-z0-9\-_\.]{20,})',
        "MEDIUM",
    ),
    (
        "JWT_TOKEN",
        "JSON Web Token (JWT)",
        # JWTs are three base64url segments separated by dots
        r'(?P<secret>ey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})',
        "HIGH",
    ),

    # --- Passwords ---
    (
        "HARDCODED_PASSWORD",
        "Hardcoded password in assignment",
        r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'](?P<secret>[^"\']{4,})["\']',
        "MEDIUM",
    ),
    (
        "DB_CONNECTION_STRING",
        "Database connection string with credentials",
        r'(?i)(?:jdbc|mongodb|postgres|mysql|redis|amqp)(?:ql)?://[^:]+:(?P<secret>[^@\s"\']{4,})@',
        "HIGH",
    ),

    # --- Private keys / certificates ---
    (
        "PEM_PRIVATE_KEY",
        "PEM-encoded private key header",
        r'(?P<secret>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)',
        "HIGH",
    ),
    (
        "PGP_PRIVATE_KEY",
        "PGP private key header",
        r'(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----)',
        "HIGH",
    ),

    # --- Tokens by provider ---
    (
        "GITHUB_TOKEN",
        "GitHub personal access token",
        # Classic PAT: ghp_  |  Fine-grained: github_pat_
        r'(?P<secret>(?:ghp_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{36,})',
        "HIGH",
    ),
    (
        "SLACK_TOKEN",
        "Slack OAuth token",
        r'(?P<secret>xox[baprs]-[A-Za-z0-9\-]{10,})',
        "HIGH",
    ),
    (
        "STRIPE_KEY",
        "Stripe API key",
        r'(?P<secret>(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,})',
        "HIGH",
    ),
    (
        "SENDGRID_KEY",
        "SendGrid API key",
        r'(?P<secret>SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})',
        "HIGH",
    ),
    (
        "TWILIO_KEY",
        "Twilio API key / SID",
        r'(?P<secret>AC[a-f0-9]{32})',
        "HIGH",
    ),

    # --- Generic high-entropy secret assignment ---
    (
        "SECRET_ASSIGNMENT",
        "High-entropy value assigned to secret-named variable",
        r'(?i)(?:secret|token|private[_\-]?key|auth[_\-]?token|session[_\-]?key)\s*[=:]\s*["\'](?P<secret>[^"\']{8,})["\']',
        "MEDIUM",
    ),
]

# ---------------------------------------------------------------------------
# False-positive filters
# Patterns that strongly suggest a value is a placeholder / test fixture.
# ---------------------------------------------------------------------------

FALSE_POSITIVE_PATTERNS: list[re.Pattern] = [
    # Explicit placeholder / example text (broad match covers YOUR_*_HERE, changeme, etc.)
    re.compile(r'(?i)(your[_\-\s]?|placeholder|changeme|replace[_\-]?me|insert[_\-]?here|\bhere\b|todo|fixme|dummy|fake|test[_\-]?key|sample|\bexample\b)', re.IGNORECASE),
    # All same character repeated (e.g. "xxxxxxxxxxxx", "000000000")
    re.compile(r'^(.)\1{7,}$'),
    # Mostly asterisks / masking characters
    re.compile(r'^[*x\-_\.]{6,}$', re.IGNORECASE),
    # Very short values unlikely to be real secrets
    re.compile(r'^.{1,5}$'),
    # Numeric-only values (unlikely to be secrets; more likely config values)
    re.compile(r'^\d+$'),
    # Template variable syntax: ${VAR}, {{VAR}}, <%= VAR %>
    re.compile(r'^\$\{[^}]+\}$|^\{\{[^}]+\}\}$|^<%=.+%>$'),
    # Environment variable reference: process.env.FOO, os.environ['FOO']
    re.compile(r'(?i)(?:process\.env\.|os\.environ|System\.getenv)', re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule_id: str
    description: str
    file: str
    line_number: int
    line_snippet: str       # Redacted preview for the report
    matched_value: str      # Redacted actual matched secret value
    confidence: str         # HIGH | MEDIUM | LOW
    entropy: float
    false_positive_filtered: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        # Ensure matched_value is redacted in output
        d["matched_value"] = _redact(self.matched_value)
        d["line_snippet"] = _redact_line(self.line_snippet, self.matched_value)
        return d


@dataclass
class ScanReport:
    scan_path: str
    scan_timestamp: str
    files_scanned: int
    findings_count: int
    high_count: int
    medium_count: int
    low_count: int
    passed: bool            # True = no findings at or above threshold
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact(value: str, show_chars: int = 4) -> str:
    """Partially redact a secret value for safe display in reports."""
    if len(value) <= show_chars:
        return "***"
    return value[:show_chars] + "***REDACTED***"


def _redact_line(line: str, secret: str) -> str:
    """Replace the secret in the line snippet with a redaction marker."""
    if not secret or len(secret) <= 4:
        return line
    return line.replace(secret, _redact(secret))


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string (bits per character).

    High-entropy strings (>= 4.5) are likely random secrets.
    Low-entropy strings are likely human-readable placeholders.
    """
    if not value:
        return 0.0
    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in freq.values())


def is_false_positive(value: str) -> bool:
    """Return True when a matched value looks like a placeholder rather than a real secret."""
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def adjust_confidence(base_confidence: str, entropy: float, value: str) -> str:
    """Upgrade or downgrade confidence based on entropy and value characteristics."""
    if is_false_positive(value):
        return "LOW"
    if base_confidence == "HIGH":
        return "HIGH"
    # For MEDIUM rules, promote to HIGH if entropy is very high
    if base_confidence == "MEDIUM" and entropy >= ENTROPY_THRESHOLD_HIGH:
        return "HIGH"
    # Downgrade to LOW if entropy is below minimum threshold
    if entropy < ENTROPY_THRESHOLD_MEDIUM:
        return "LOW"
    return base_confidence


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

def _compile_patterns() -> list[tuple[str, str, re.Pattern, str]]:
    """Pre-compile all regex patterns once at startup."""
    compiled = []
    for rule_id, description, pattern, confidence in SECRET_PATTERNS:
        try:
            compiled.append((rule_id, description, re.compile(pattern), confidence))
        except re.error as exc:
            print(f"[WARN] Failed to compile pattern {rule_id}: {exc}", file=sys.stderr)
    return compiled


COMPILED_PATTERNS = _compile_patterns()


def scan_file(file_path: Path, base_scan_path: Path) -> list[Finding]:
    """Scan a single file and return all findings."""
    findings: list[Finding] = []

    # Skip oversized files to avoid memory issues
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return findings
    except OSError:
        return findings

    try:
        # Use errors='replace' to handle non-UTF-8 source files gracefully
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    lines = content.splitlines()
    relative_path = str(file_path.relative_to(base_scan_path))

    for line_number, line in enumerate(lines, start=1):
        # Skip comment lines to reduce noise in docs / example files
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "<!--", "--")):
            continue

        for rule_id, description, pattern, base_confidence in COMPILED_PATTERNS:
            for match in pattern.finditer(line):
                # Extract the secret group if defined; otherwise use full match
                try:
                    secret_value = match.group("secret")
                except IndexError:
                    secret_value = match.group(0)

                if not secret_value:
                    continue

                entropy = shannon_entropy(secret_value)
                confidence = adjust_confidence(base_confidence, entropy, secret_value)
                fp_filtered = is_false_positive(secret_value)

                findings.append(Finding(
                    rule_id=rule_id,
                    description=description,
                    file=relative_path,
                    line_number=line_number,
                    line_snippet=line.rstrip(),
                    matched_value=secret_value,
                    confidence=confidence,
                    entropy=round(entropy, 3),
                    false_positive_filtered=fp_filtered,
                ))

    return findings


def walk_directory(scan_path: Path) -> list[Path]:
    """Recursively collect scannable files, skipping ignored directories."""
    files: list[Path] = []
    for root, dirs, filenames in os.walk(scan_path):
        # Modify dirs in-place to prevent os.walk from descending into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]
        for filename in filenames:
            file_path = Path(root) / filename
            if file_path.suffix.lower() in SCANNABLE_EXTENSIONS:
                files.append(file_path)
    return files


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def build_report(
    scan_path: Path,
    findings: list[Finding],
    files_scanned: int,
    min_confidence: str = "LOW",
    include_fp: bool = False,
) -> ScanReport:
    """Filter findings and assemble the final report."""
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_rank = confidence_rank.get(min_confidence, 1)

    visible = [
        f for f in findings
        if confidence_rank.get(f.confidence, 0) >= min_rank
        and (include_fp or not f.false_positive_filtered)
    ]

    high = sum(1 for f in visible if f.confidence == "HIGH")
    medium = sum(1 for f in visible if f.confidence == "MEDIUM")
    low = sum(1 for f in visible if f.confidence == "LOW")

    return ScanReport(
        scan_path=str(scan_path),
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        files_scanned=files_scanned,
        findings_count=len(visible),
        high_count=high,
        medium_count=medium,
        low_count=low,
        # Pass only when there are no HIGH or MEDIUM findings
        passed=(high == 0 and medium == 0),
        findings=visible,
    )


def print_text_report(report: ScanReport) -> None:
    """Print a human-readable summary to stdout."""
    status = "PASS" if report.passed else "FAIL"
    print(f"\n{'='*60}")
    print(f"  Secret Detection Report  [{status}]")
    print(f"{'='*60}")
    print(f"  Scan path  : {report.scan_path}")
    print(f"  Timestamp  : {report.scan_timestamp}")
    print(f"  Files      : {report.files_scanned}")
    print(f"  Findings   : {report.findings_count}  "
          f"(HIGH={report.high_count}, MEDIUM={report.medium_count}, LOW={report.low_count})")
    print(f"{'='*60}\n")

    for f in report.findings:
        print(f"  [{f.confidence}] {f.rule_id}")
        print(f"    File    : {f.file}:{f.line_number}")
        print(f"    Detail  : {f.description}")
        print(f"    Entropy : {f.entropy}")
        print(f"    Snippet : {_redact_line(f.line_snippet, f.matched_value)}")
        print()

    if report.passed:
        print("  Result: No high/medium severity secrets detected.\n")
    else:
        print(f"  Result: {report.high_count} HIGH and {report.medium_count} MEDIUM findings require remediation.\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Secret Detection Engine — scan source code for hardcoded secrets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--path", "-p",
        required=True,
        help="Directory or file path to scan.",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write report to this file instead of stdout.",
    )
    parser.add_argument(
        "--min-confidence",
        choices=["HIGH", "MEDIUM", "LOW"],
        default="LOW",
        help="Minimum confidence level to report (default: LOW).",
    )
    parser.add_argument(
        "--include-fp",
        action="store_true",
        default=False,
        help="Include findings that were flagged as likely false positives.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["HIGH", "MEDIUM", "LOW", "NONE"],
        default="MEDIUM",
        help="Exit with code 1 when findings at this level or above are found (default: MEDIUM).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    scan_path = Path(args.path).resolve()

    if not scan_path.exists():
        print(f"[ERROR] Path not found: {scan_path}", file=sys.stderr)
        sys.exit(2)

    # Collect files
    if scan_path.is_file():
        files = [scan_path] if scan_path.suffix.lower() in SCANNABLE_EXTENSIONS else []
        base_path = scan_path.parent
    else:
        files = walk_directory(scan_path)
        base_path = scan_path

    # Scan
    all_findings: list[Finding] = []
    for file_path in files:
        all_findings.extend(scan_file(file_path, base_path))

    # Build report
    report = build_report(
        scan_path=scan_path,
        findings=all_findings,
        files_scanned=len(files),
        min_confidence=args.min_confidence,
        include_fp=args.include_fp,
    )

    # Output
    if args.format == "json":
        output = json.dumps(report.to_dict(), indent=2)
    else:
        # For text format, print to stdout first then optionally write
        print_text_report(report)
        output = None

    if args.output and output is not None:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[INFO] Report written to: {args.output}", file=sys.stderr)
    elif output is not None:
        print(output)

    # Exit code for CI quality gate
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    fail_rank = confidence_rank.get(args.fail_on, 2)
    worst_rank = max(
        (confidence_rank.get(f.confidence, 0) for f in report.findings),
        default=0,
    )
    if worst_rank >= fail_rank and fail_rank > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
