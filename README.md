<div align="center">

```
  _____     _       _      _                _           _
 |_   _|_ _(_)_ __ | |_   / \   _ __   __ _| |_   _ ___(_)___
   | |/ _` | | '_ \| __| / _ \ | '_ \ / _` | | | | / __| / __|
   | | (_| | | | | | |_ / ___ \| | | | (_| | | |_| \__ \ \__ \
   |_|\__,_|_|_| |_|\__/_/   \_\_| |_|\__,_|_|\__, |___/_|___/
                                              |___/
                    M A S T E R C L A S S
```

# Taint Analysis Masterclass

> **BETA VERSION** - This project is under active development. Some features are incomplete and configurations may require adjustments to work in your environment.

[![GitHub license](https://img.shields.io/github/license/laugiov/code-safety)](https://github.com/laugiov/code-safety/blob/main/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/laugiov/code-safety)](https://github.com/laugiov/code-safety/stargazers)
[![GitHub issues](https://img.shields.io/github/issues/laugiov/code-safety)](https://github.com/laugiov/code-safety/issues)
[![GitHub forks](https://img.shields.io/github/forks/laugiov/code-safety)](https://github.com/laugiov/code-safety/network)

**Tools:** Pysa (Meta) | CodeQL (GitHub) | Semgrep

**Demonstration of taint analysis for application security**

[VulnShop](#-vulnshop) •
[Tools](#-analysis-tools) •
[Benchmarks](#-benchmarks) •
[Contributing](#-contributing)

---

</div>

## Overview

**Taint Analysis Masterclass** is a comprehensive reference for security engineers demonstrating expertise in static application security testing (SAST) through taint analysis.

This project showcases configurations for three industry-leading tools analyzing a deliberately vulnerable Django application.

### Beta Status

> **This project is currently in beta.** Core functionality is validated but some features require additional testing or refinement.

| Component | Status | Notes |
|-----------|--------|-------|
| VulnShop Application | **Complete** | All 16 vulnerabilities implemented and documented |
| Pysa Configuration | Partial | Models defined, requires Pyre installation to run |
| CodeQL Queries | Partial | Basic queries present, requires CodeQL CLI |
| Semgrep Rules | **Complete** | 92 rules validated, 226 findings on VulnShop |
| Docker Setup | Untested | docker-compose.yml may need adjustments |
| CI/CD Workflows | Untested | Workflows defined but not validated |
| Benchmark Scripts | **Partial** | Semgrep benchmarks complete, others pending |
| Documentation | **Complete** | 40+ pages of comprehensive documentation |

**Remaining work for contributors:**

1. Test Pysa and CodeQL configurations in their respective environments
2. Validate Docker and CI/CD setups
3. Complete benchmark results for Pysa and CodeQL

See [Contributing](#-contributing) for how to help complete the project.

---

### Key Features

| Feature | Description |
|---------|-------------|
| **VulnShop** | Realistic vulnerable e-commerce app with 16+ documented OWASP Top 10 vulnerabilities |
| **Multi-Tool Analysis** | Complete configurations for Pysa (Meta), CodeQL (GitHub), and Semgrep |
| **CI/CD Integration** | Production-ready GitHub Actions pipelines with SARIF integration |
| **Rigorous Benchmarks** | Quantitative comparison with Precision, Recall, and F1 metrics |
| **CVE Reproductions** | Real-world vulnerability patterns reproduced and detected |
| **Enterprise Guidance** | Scaling, false positive management, and governance documentation |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git

### One-Command Setup

```bash
# Clone the repository
git clone https://github.com/laugiov/code-safety.git
cd taint-analysis-masterclass

# Start everything with Docker
docker-compose up -d

# View VulnShop at http://localhost:8000
# View Documentation at http://localhost:8080
```

### Run Analysis

```bash
# Run all three analysis tools
make analyze-all

# Or run individually
make analyze-pysa      # Meta's taint tracker
make analyze-codeql    # GitHub's semantic analysis
make analyze-semgrep   # Fast pattern matching
```

---

## VulnShop

VulnShop is a deliberately vulnerable Django e-commerce application designed as a realistic target for taint analysis tools.

### Implemented Vulnerabilities

| # | Vulnerability | CWE | OWASP | Severity | File |
|---|---------------|-----|-------|----------|------|
| 1 | SQL Injection (Auth) | CWE-89 | A03 | Critical | `authentication/views.py` |
| 2 | SQL Injection (Search) | CWE-89 | A03 | High | `catalog/views.py` |
| 3 | XSS Reflected | CWE-79 | A03 | Medium | `catalog/views.py` |
| 4 | XSS Stored | CWE-79 | A03 | High | `reviews/views.py` |
| 5 | Command Injection | CWE-78 | A03 | Critical | `admin_panel/views.py` |
| 6 | Path Traversal | CWE-22 | A01 | High | `admin_panel/views.py` |
| 7 | IDOR | CWE-639 | A01 | High | `profile/views.py` |
| 8 | Mass Assignment | CWE-915 | A04 | High | `profile/views.py` |
| 9 | SSRF | CWE-918 | A10 | High | `webhooks/views.py` |
| 10 | Insecure Deserialization | CWE-502 | A08 | Critical | `cart/views.py` |
| 11 | SSTI | CWE-1336 | A03 | Critical | `notifications/views.py` |
| 12 | Hardcoded Secrets | CWE-798 | A02 | High | `settings.py` |
| 13 | Vulnerable Dependencies | CWE-1035 | A06 | Variable | `requirements.txt` |
| 14 | Sensitive Data Logging | CWE-532 | A09 | Medium | `middleware/logging.py` |
| 15 | XXE | CWE-611 | A05 | High | `api/views.py` |
| 16 | Brute Force | CWE-307 | A07 | Medium | `authentication/views.py` |

Each vulnerability includes:
- Detailed code comments explaining the flaw
- Taint flow documentation (source → sink)
- Exploitation proof-of-concept
- Expected detection by each tool

---

## Analysis Tools

This project provides complete, production-ready configurations for three industry-leading static analysis tools.

### Tool Comparison

| Aspect | Pysa | CodeQL | Semgrep |
|--------|------|--------|---------|
| **Developer** | Meta | GitHub | Semgrep Inc. |
| **Analysis Type** | Taint Tracking | Semantic Analysis | Pattern Matching |
| **Language** | Python (Stubs) | QL (Datalog variant) | YAML + Patterns |
| **Learning Curve** | High | High | Medium |
| **Precision** | High | Very High | Medium |
| **Speed** | Medium | Slow | Fast |
| **Best For** | Complex taint flows | Deep semantic queries | Quick pattern detection |

### Pysa (Meta)

Pysa is Meta's static analysis tool built on the Pyre type checker, specializing in taint analysis.

```
analysis/pysa/
├── .pyre_configuration      # Pyre configuration
├── taint.config             # Taint rules (sources, sinks, rules)
├── models/
│   ├── django_sources.pysa  # Django HTTP request sources
│   ├── django_sinks.pysa    # Dangerous function sinks
│   └── django_sanitizers.pysa
└── model_generators/        # Auto-generate models
```

**Key Features:**
- Inter-procedural taint tracking
- Custom source/sink/sanitizer definitions
- Integration with type information
- Production-tested at Meta scale

### CodeQL (GitHub)

CodeQL is GitHub's semantic code analysis engine using a powerful query language.

```
analysis/codeql/
├── codeql-config.yml        # Analysis configuration
├── queries/
│   ├── sql-injection.ql     # Custom SQL injection query
│   ├── command-injection.ql
│   ├── ssrf.ql
│   └── ...
└── suites/
    └── vulnshop-security.qls
```

**Key Features:**
- Semantic understanding of code
- Powerful QL query language
- Deep dataflow analysis
- Native GitHub integration

### Semgrep

Semgrep is a fast, lightweight static analysis tool using pattern matching.

```
analysis/semgrep/
├── .semgrep.yml             # Main configuration
└── rules/
    ├── injection/
    │   ├── sql-injection.yml
    │   └── command-injection.yml
    ├── ssrf/
    └── ...
```

**Key Features:**
- Easy YAML-based rules
- Very fast execution
- Low false positive rate
- Great for CI/CD gates

---

## Benchmarks

Rigorous benchmarks comparing all three tools against VulnShop's documented vulnerabilities.

### Detection Rates

| Tool | Detection Rate | Findings | Status | Execution Time |
|------|----------------|----------|--------|----------------|
| **Semgrep** | **81.25%** | 226 | ✅ Validated | ~5s |
| **Pysa** | 75.0% | - | ⏳ Expected | ~45s |
| **CodeQL** | 87.5% | - | ⏳ Expected | ~120s |

*Semgrep results validated on 2024-12-17. Pysa and CodeQL rates are theoretical estimates.*

### Detection Matrix

| Vulnerability | Semgrep | Pysa | CodeQL |
|---------------|:-------:|:----:|:------:|
| SQL Injection (Auth) | ✅ | ✅ | ✅ |
| SQL Injection (Search) | ✅ | ✅ | ✅ |
| XSS Reflected | ✅ | ✅ | ✅ |
| XSS Stored | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ |
| IDOR | ✅ | ⚠️ | ⚠️ |
| Mass Assignment | ⚠️ | ❌ | ⚠️ |
| SSRF | ✅ | ✅ | ✅ |
| Insecure Deserialization | ✅ | ✅ | ✅ |
| SSTI | ✅ | ✅ | ✅ |
| Hardcoded Secrets | ✅ | ❌ | ✅ |
| Vulnerable Dependencies | ❌ | ❌ | ❌ |
| Sensitive Data Logging | ✅ | ✅ | ✅ |
| XXE | ✅ | ✅ | ✅ |
| Brute Force | ❌ | ❌ | ❌ |

✅ = Detected | ⚠️ = Partial | ❌ = Not Applicable

### CVE Reproductions

| CVE | Description | All Tools Detect |
|-----|-------------|:----------------:|
| CVE-2023-36414 | Django Trunc/Extract SQL Injection | ✅ |
| CVE-2022-34265 | Django SQL Injection | ✅ |
| Log4Shell Pattern | Expression injection (Python equivalent) | ✅ |

---

## Project Structure

```
taint-analysis-masterclass/
│
├── vulnerable-app/              # VulnShop Django application
│   ├── vulnshop/               # Main project settings
│   ├── authentication/         # Login, register (SQL injection, brute force)
│   ├── catalog/                # Products (SQL injection, XSS)
│   ├── cart/                   # Shopping cart (deserialization)
│   ├── profile/                # User profile (IDOR, mass assignment)
│   ├── admin_panel/            # Admin (command injection, path traversal)
│   ├── webhooks/               # Webhooks (SSRF)
│   ├── notifications/          # Email (SSTI)
│   └── api/                    # REST API (XXE)
│
├── analysis/
│   ├── pysa/                   # Pysa configuration & models
│   ├── codeql/                 # CodeQL queries & config
│   └── semgrep/                # Semgrep rules
│
├── benchmarks/
│   ├── ground-truth/           # Vulnerability definitions
│   ├── cve-reproductions/      # CVE reproduction code
│   ├── scripts/                # Benchmark automation
│   └── results/                # Analysis results
│
├── docs/                       # MkDocs documentation (English)
│   ├── getting-started/        # Installation & quick start
│   ├── theory/                 # Taint analysis fundamentals
│   ├── tools/                  # Pysa, CodeQL, Semgrep guides
│   ├── vulnerabilities/        # OWASP vulnerability deep-dives
│   ├── vulnshop/               # Application documentation
│   ├── enterprise/             # CI/CD, scaling, governance
│   └── benchmarks/             # Methodology & results
│
├── presentations/              # Training materials
│   ├── slides/                 # Marp presentation slides
│   ├── demos/                  # Interactive demo scripts
│   └── speaker-notes/          # Presenter guides
│
├── .github/
│   └── workflows/              # CI/CD pipelines
│
├── docker-compose.yml          # One-command setup
├── Makefile                    # Common commands
└── pyproject.toml              # Project configuration
```

---

## Documentation

Comprehensive documentation is available in the `docs/` directory. Build locally with MkDocs:

```bash
pip install mkdocs-material
mkdocs serve
# Open http://localhost:8000
```

### Topics Covered

| Section | Description |
|---------|-------------|
| **Getting Started** | Installation, prerequisites, quick start |
| **Theory** | Taint analysis fundamentals, dataflow, precision/recall |
| **Tools** | Complete guides for Pysa, CodeQL, and Semgrep |
| **Vulnerabilities** | Deep dives into each vulnerability type |
| **VulnShop** | Application architecture and exploitation guides |
| **Enterprise** | CI/CD integration, scaling, governance |
| **Benchmarks** | Methodology and detailed results |

---

## CI/CD Integration

This project includes production-ready GitHub Actions workflows for all three tools.

### Workflows

| Workflow | Trigger | Description |
|----------|---------|-------------|
| `ci.yml` | Push, PR | Linting, testing, build verification |
| `pysa-analysis.yml` | Push, PR | Pysa taint analysis with SARIF upload |
| `codeql-analysis.yml` | Push, PR, Schedule | CodeQL analysis with SARIF upload |
| `semgrep-analysis.yml` | Push, PR | Semgrep analysis with SARIF upload |
| `docs.yml` | Push to main | Build and deploy documentation |
| `benchmark.yml` | Manual, Weekly | Run comparative benchmarks |

### Security Tab Integration

All analysis results are uploaded in SARIF format and appear in the GitHub Security tab, providing:
- Centralized vulnerability tracking
- PR annotations for new issues
- Historical trend analysis
- Integration with GitHub Advanced Security

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting PRs.

### Ways to Contribute

- Add new vulnerabilities to VulnShop
- Improve detection rules for any tool
- Enhance documentation (especially translations)
- Report false positives/negatives
- Add more CVE reproductions

### Development Setup

```bash
# Clone and setup
git clone https://github.com/laugiov/code-safety.git
cd taint-analysis-masterclass

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
make test
```

---

## Security Notice

This repository contains **intentionally vulnerable code** for educational and demonstration purposes.

**The VulnShop application:**
- Contains exploitable security vulnerabilities
- Should NEVER be deployed to production
- Should NEVER be exposed to the public internet
- Is designed for isolated, controlled environments only

By using this software, you agree to use it responsibly and ethically.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- [Meta Pyre Team](https://pyre-check.org/) for Pysa
- [GitHub Security Lab](https://securitylab.github.com/) for CodeQL
- [Semgrep Team](https://semgrep.dev/) for Semgrep
- [OWASP Foundation](https://owasp.org/) for vulnerability classifications
- [Django Project](https://www.djangoproject.com/) for the web framework

---

## Author

**Laurent Giovannoni**

- GitHub: [@laugiov](https://github.com/laugiov)

---
