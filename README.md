# Code Safety: Taint Analysis & SAST Benchmark

[![CI](https://github.com/laugiov/code-safety/actions/workflows/ci.yml/badge.svg)](https://github.com/laugiov/code-safety/actions/workflows/ci.yml)
[![Semgrep](https://github.com/laugiov/code-safety/actions/workflows/semgrep-analysis.yml/badge.svg)](https://github.com/laugiov/code-safety/actions/workflows/semgrep-analysis.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Django 4.2](https://img.shields.io/badge/django-4.2-green.svg)](https://www.djangoproject.com/)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

> **Lab only:** VulnShop is intentionally vulnerable. Do not deploy to production.

## Context

I built this project to explore how modern SAST tools handle taint analysis in practice. The idea was simple: create a controlled Django app with known vulnerabilities, then run Pysa, CodeQL, and Semgrep against it to see what they catch and what they miss.

The result is a benchmark with 16 OWASP Top 10 cases, each with documented taint flows (source, sink, sanitizer). This lets me measure detection rates objectively and understand where each tool shines or falls short.

## What I wanted to demonstrate

This repo reflects work I do in AppSec and Security Engineering: writing custom taint-analysis rules, integrating SAST into CI pipelines with SARIF output, and thinking about false positive management at scale. The `docs/` folder covers enterprise patterns like governance and rollout strategies.

If you're using the project, start with the Semgrep rules in `analysis/semgrep/rules/` and the ground truth definitions in `benchmarks/ground-truth/`. Run `make analyze-semgrep` to see the full detection pipeline.

## The benchmark app (VulnShop)

VulnShop is a Django e-commerce app I wrote specifically for this benchmark. It has 16 security cases:

| # | Case | CWE | Location |
|---|------|-----|----------|
| 1 | SQL Injection (Auth) | CWE-89 | `authentication/views.py` |
| 2 | SQL Injection (Search) | CWE-89 | `catalog/views.py` |
| 3 | XSS Reflected | CWE-79 | `catalog/views.py` |
| 4 | XSS Stored | CWE-79 | `reviews/views.py` |
| 5 | Command Injection | CWE-78 | `admin_panel/views.py` |
| 6 | Path Traversal | CWE-22 | `admin_panel/views.py` |
| 7 | IDOR | CWE-639 | `profile/views.py` |
| 8 | Mass Assignment | CWE-915 | `profile/views.py` |
| 9 | SSRF | CWE-918 | `webhooks/views.py` |
| 10 | Insecure Deserialization | CWE-502 | `cart/views.py` |
| 11 | SSTI | CWE-1336 | `notifications/views.py` |
| 12 | Hardcoded Secrets | CWE-798 | `settings.py` |
| 13 | Vulnerable Dependencies | CWE-1035 | `requirements.txt` |
| 14 | Sensitive Data Logging | CWE-532 | `middleware/logging.py` |
| 15 | XXE | CWE-611 | `api/views.py` |
| 16 | Missing Rate Limiting | CWE-307 | `authentication/views.py` |

Each vulnerability has a documented taint flow showing how user input reaches a dangerous sink, and what sanitization would prevent it.

## Tools and results

I tested three tools with different approaches: Pysa (Meta) does deep taint tracking, CodeQL (GitHub) offers semantic analysis with its own query language, and Semgrep is fast pattern matching suited for CI gates.

| Tool | Analysis type | Speed | Best for |
|------|--------------|-------|----------|
| Pysa | Taint tracking | Medium | Complex data flows |
| CodeQL | Semantic queries | Slow | Deep analysis |
| Semgrep | Pattern matching | Fast | CI/CD integration |

Semgrep is fully validated: 92 custom rules, 226 findings, 81.25% detection rate on the 16 cases. It catches SQLi, XSS, Command Injection, Path Traversal, IDOR, SSRF, Deserialization, SSTI, and XXE reliably. Mass Assignment is partial. Rate limiting and dependency checks are out of scope for SAST.

Pysa and CodeQL configs are ready but need their respective runtimes (Pyre and CodeQL CLI). I also included CVE reproductions for CVE-2023-36414 and CVE-2022-34265 (Django SQL injection patterns).

## Running it

```bash
git clone https://github.com/laugiov/code-safety.git
cd code-safety

# Docker: VulnShop on :8000, docs on :8080
docker-compose up -d

# Or run Semgrep directly
make analyze-semgrep
```

## Project structure

The repo is organized around three main areas: the vulnerable app itself, the analysis configurations, and the benchmark data with ground truth.

```
vulnerable-app/     # VulnShop Django app
analysis/           # Pysa, CodeQL, Semgrep configs
benchmarks/         # Ground truth and results
docs/               # MkDocs documentation (40+ pages)
.github/workflows/  # CI templates with SARIF
```

The CI workflows upload SARIF to GitHub's Security tab for centralized tracking.

## Documentation

Run `pip install mkdocs-material && mkdocs serve` to browse locally. The docs cover taint analysis theory, tool-specific guides, and enterprise topics like scaling SAST and managing false positives.

## License

MIT. Contributions welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Author

Laurent Giovannoni - [@laugiov](https://github.com/laugiov)
