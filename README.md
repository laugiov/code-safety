# Code Safety — Taint Analysis & SAST Benchmark Reference

A **Security Engineering** reference implementation to evaluate and operationalize
**taint analysis** in AppSec programs: **Pysa**, **CodeQL**, and **Semgrep** over a controlled Django benchmark app.

[![GitHub license](https://img.shields.io/github/license/laugiov/code-safety)](https://github.com/laugiov/code-safety/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/laugiov/code-safety)](https://github.com/laugiov/code-safety/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/laugiov/code-safety)](https://github.com/laugiov/code-safety/issues)

> **Lab only:** VulnShop is intentionally vulnerable. Do not deploy to production or expose to the Internet.

---

## Hiring Relevance

This repo demonstrates **AppSec / Security Engineering** capabilities:

- Building and tuning taint-analysis rules (sources / sinks / sanitizers)
- Operationalizing SAST in CI with SARIF + PR annotations
- Benchmarking tools with ground truth (precision / recall mindset)
- Designing governance for false positives and scale

---

## Evaluate in 15 Minutes

1. Open `docs/` → start with **Benchmarks** and **Enterprise** sections
2. Review `analysis/semgrep/rules/` and the **ground truth** in `benchmarks/ground-truth/`
3. Check CI templates in `.github/workflows/` for SARIF upload & PR annotations
4. Run `make analyze-semgrep` (fast path) to see end-to-end detection → SARIF output

---

## Overview

| Feature | Description |
|---------|-------------|
| **Benchmark App** | Controlled Django app with 16 documented OWASP Top 10 cases |
| **Multi-Tool Analysis** | Configurations for Pysa (Meta), CodeQL (GitHub), and Semgrep |
| **CI/CD Integration** | CI templates with SARIF upload and PR annotations (adaptable to enterprise pipelines) |
| **Ground Truth** | Quantitative comparison with documented taint flows |
| **Enterprise Patterns** | Scaling, false positive management, and governance documentation |

---

## Project Status

> **Active reference project** — some tool integrations require environment-specific setup (see matrix below).

| Component | Status | Notes |
|-----------|--------|-------|
| VulnShop Application | Complete | All 16 cases implemented and documented |
| Semgrep Rules | Complete | 92 rules validated, 226 findings |
| Pysa Configuration | Setup required | Models defined, requires Pyre runtime |
| CodeQL Queries | Setup required | Queries present, requires CodeQL CLI |
| Docker Setup | Pending validation | docker-compose.yml provided |
| CI/CD Workflows | Pending validation | Workflows defined, require secrets setup |
| Documentation | Complete | 40+ pages |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/laugiov/code-safety.git
cd code-safety

# Option 1: Docker (recommended)
docker-compose up -d
# VulnShop: http://localhost:8000
# Docs: http://localhost:8080

# Option 2: Run Semgrep directly
make analyze-semgrep
```

---

## Benchmark App (VulnShop)

A controlled Django application with 16 documented security cases for tool validation.

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

Each case includes:
- A documented **taint flow** (source → sink → sanitizer)
- Expected detections per tool
- A controlled test scenario for validation (lab-only)

---

## Analysis Tools

### Tool Comparison

| Aspect | Pysa | CodeQL | Semgrep |
|--------|------|--------|---------|
| **Developer** | Meta | GitHub | Semgrep Inc. |
| **Analysis Type** | Taint Tracking | Semantic Analysis | Pattern Matching |
| **Language** | Python (Stubs) | QL (Datalog variant) | YAML + Patterns |
| **Precision** | High | Very High | Medium |
| **Speed** | Medium | Slow | Fast |
| **Best For** | Complex taint flows | Deep semantic queries | CI/CD gates |

### Configurations

```
analysis/
├── pysa/
│   ├── .pyre_configuration
│   ├── taint.config
│   └── models/              # sources, sinks, sanitizers
├── codeql/
│   ├── codeql-config.yml
│   └── queries/             # custom QL queries
└── semgrep/
    └── rules/               # 92 custom YAML rules
```

---

## Benchmark Results

| Tool | Status | Notes |
|------|--------|-------|
| Semgrep | Measured | 226 findings, 81.25% detection rate |
| Pysa | Pending | Requires Pyre/Pysa runtime setup |
| CodeQL | Pending | Requires CodeQL CLI + database creation |

### Detection Matrix (Semgrep — Measured)

| Case | Detected |
|------|:--------:|
| SQL Injection (Auth) | ✅ |
| SQL Injection (Search) | ✅ |
| XSS Reflected | ✅ |
| XSS Stored | ✅ |
| Command Injection | ✅ |
| Path Traversal | ✅ |
| IDOR | ✅ |
| Mass Assignment | Partial |
| SSRF | ✅ |
| Insecure Deserialization | ✅ |
| SSTI | ✅ |
| Hardcoded Secrets | ✅ |
| Vulnerable Dependencies | N/A (SCA) |
| Sensitive Data Logging | ✅ |
| XXE | ✅ |
| Missing Rate Limiting | N/A (Logic) |

Full results in `benchmarks/results/`.

### Additional Test Patterns

| Pattern | Description |
|---------|-------------|
| Django SQL Injection (CVE-2023-36414) | Trunc/Extract injection pattern |
| Django SQL Injection (CVE-2022-34265) | Format string injection pattern |
| Expression Injection | Python equivalent scenario for demonstration |

---

## CI/CD Integration

CI templates in `.github/workflows/` with SARIF upload:

| Workflow | Description |
|----------|-------------|
| `ci.yml` | Linting, build verification |
| `semgrep-analysis.yml` | Semgrep scan + SARIF upload |
| `pysa-analysis.yml` | Pysa analysis + SARIF upload |
| `codeql-analysis.yml` | CodeQL scan + SARIF upload |
| `docs.yml` | Documentation build & deploy |

All workflows upload SARIF to GitHub Security tab for centralized tracking and PR annotations.

---

## Project Structure

```
code-safety/
├── vulnerable-app/          # VulnShop Django application
│   ├── authentication/      # SQL injection, rate limiting
│   ├── catalog/             # SQL injection, XSS
│   ├── cart/                # Deserialization
│   ├── profile/             # IDOR, mass assignment
│   ├── admin_panel/         # Command injection, path traversal
│   ├── webhooks/            # SSRF
│   ├── notifications/       # SSTI
│   └── api/                 # XXE
├── analysis/
│   ├── pysa/                # Pysa config & models
│   ├── codeql/              # CodeQL queries
│   └── semgrep/             # Semgrep rules
├── benchmarks/
│   ├── ground-truth/        # Documented cases
│   ├── cve-reproductions/   # CVE test patterns
│   └── results/             # Analysis outputs
├── docs/                    # MkDocs documentation
├── .github/workflows/       # CI/CD templates
├── docker-compose.yml
└── Makefile
```

---

## Documentation

```bash
# Serve documentation locally
pip install mkdocs-material
mkdocs serve
# Open http://localhost:8000
```

| Section | Description |
|---------|-------------|
| Getting Started | Installation, prerequisites |
| Theory | Taint analysis fundamentals, dataflow |
| Tools | Pysa, CodeQL, Semgrep guides |
| Enterprise | CI/CD integration, scaling, governance |
| Benchmarks | Methodology and results |

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/laugiov/code-safety.git
cd code-safety
pip install -r requirements-dev.txt
pre-commit install
```

---

## License

MIT License — see [LICENSE](LICENSE).

---

## Author

**Laurent Giovannoni** — [@laugiov](https://github.com/laugiov)
