# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial project structure
- VulnShop Django application with 16 vulnerabilities
- Pysa configuration and Django models
- CodeQL custom queries
- Semgrep custom rules
- GitHub Actions CI/CD pipelines
- MkDocs documentation (EN/FR)
- Docker Compose setup
- Benchmark framework
- CVE reproductions

### Changed
- Nothing yet

### Deprecated
- Nothing yet

### Removed
- Nothing yet

### Fixed
- Nothing yet

### Security
- This project intentionally contains vulnerable code for educational purposes

---

## [1.0.0] - YYYY-MM-DD

### Added

#### VulnShop Application
- Django e-commerce application with realistic functionality
- 16 documented security vulnerabilities covering OWASP Top 10:
  - SQL Injection (authentication and search)
  - Cross-Site Scripting (reflected and stored)
  - Command Injection
  - Path Traversal
  - Insecure Direct Object Reference (IDOR)
  - Mass Assignment
  - Server-Side Request Forgery (SSRF)
  - Insecure Deserialization
  - Server-Side Template Injection (SSTI)
  - Hardcoded Secrets
  - Vulnerable Dependencies
  - Sensitive Data Logging
  - XML External Entity (XXE)
  - Brute Force (no rate limiting)
- Each vulnerability includes exploitation PoC

#### Analysis Configurations
- **Pysa (Meta)**
  - Complete `.pyre_configuration`
  - Taint configuration with custom rules
  - Django source models (request.GET, POST, COOKIES, etc.)
  - Django sink models (cursor.execute, os.system, etc.)
  - Django sanitizer models
  - Model generators for automatic model creation

- **CodeQL (GitHub)**
  - Custom queries for SQL injection, XSS, SSRF, command injection
  - Query suite for VulnShop
  - CodeQL configuration for GitHub integration

- **Semgrep**
  - 20+ custom rules organized by vulnerability type
  - Rules for injection, access control, crypto, deserialization
  - Django-specific patterns

#### CI/CD Integration
- GitHub Actions workflows:
  - `ci.yml` - Basic CI (lint, test, build)
  - `pysa-analysis.yml` - Pysa taint analysis
  - `codeql-analysis.yml` - CodeQL semantic analysis
  - `semgrep-analysis.yml` - Semgrep pattern matching
  - `docs.yml` - Documentation deployment
  - `benchmark.yml` - Comparative benchmarks
- SARIF integration with GitHub Security tab
- PR annotations for security findings

#### Benchmarks
- Ground truth definition for all vulnerabilities
- Automated benchmark runner
- Metrics calculation (Precision, Recall, F1)
- Tool comparison reports
- CVE reproductions:
  - CVE-2023-36414 (Django SQL Injection)
  - CVE-2022-34265 (Django Trunc/Extract)
  - Log4Shell pattern equivalent

#### Documentation
- MkDocs Material theme
- Bilingual documentation (English primary, French secondary)
- Sections:
  - Getting Started
  - Theory (Taint Analysis, Dataflow, Metrics)
  - Tool Guides (Pysa, CodeQL, Semgrep)
  - Vulnerability Deep Dives
  - Enterprise Integration
  - Benchmark Results
- GitHub Pages deployment

#### Infrastructure
- Docker Compose for one-command setup
- Makefile with common commands
- Pre-commit hooks configuration
- EditorConfig for consistent formatting

### Security Notice
This release contains intentionally vulnerable code. VulnShop should NEVER be
deployed to production or exposed to the public internet.

---

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 1.0.0 | TBD | Initial release |

---

## Upgrade Guide

### From 0.x to 1.0.0

This is the initial release. No upgrade path required.

---

## Links

- [GitHub Releases](https://github.com/laugiov/code-safety/releases)
- [Issue Tracker](https://github.com/laugiov/code-safety/issues)
