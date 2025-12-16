---
title: Vulnerability Catalog
description: Comprehensive guide to security vulnerabilities detected by taint analysis
---

# Vulnerability Catalog

This section provides detailed documentation for each vulnerability type implemented in VulnShop and detected by our taint analysis tools.

## Vulnerability Overview

VulnShop contains **16 deliberately implemented vulnerabilities** across multiple categories. Here's how each tool performs:

| Vulnerability | CWE | Pysa | CodeQL | Semgrep |
|---------------|-----|:----:|:------:|:-------:|
| [SQL Injection](sql-injection.md) | CWE-89 | ✅ | ✅ | ✅ |
| [Command Injection](command-injection.md) | CWE-78 | ✅ | ✅ | ✅ |
| [XSS (Reflected)](xss.md) | CWE-79 | ✅ | ✅ | ✅ |
| [XSS (Stored)](xss.md#stored-xss) | CWE-79 | ✅ | ✅ | ⚠️ |
| [Path Traversal](path-traversal.md) | CWE-22 | ✅ | ✅ | ✅ |
| [SSRF](ssrf.md) | CWE-918 | ✅ | ✅ | ✅ |
| [Insecure Deserialization](deserialization.md) | CWE-502 | ✅ | ✅ | ✅ |
| [SSTI](ssti.md) | CWE-1336 | ✅ | ✅ | ✅ |
| [XXE](xxe.md) | CWE-611 | ✅ | ✅ | ✅ |
| Hardcoded Secrets | CWE-798 | ❌ | ✅ | ✅ |
| Sensitive Logging | CWE-532 | ✅ | ✅ | ⚠️ |
| IDOR | CWE-639 | ⚠️ | ⚠️ | ❌ |
| Mass Assignment | CWE-915 | ❌ | ⚠️ | ✅ |
| Weak Cryptography | CWE-327 | ❌ | ✅ | ✅ |
| Open Redirect | CWE-601 | ⚠️ | ✅ | ⚠️ |
| HTTP Response Splitting | CWE-113 | ❌ | ⚠️ | ⚠️ |

**Legend**: ✅ Detected | ⚠️ Partial | ❌ Not Detected

## Vulnerability Categories

### Injection Vulnerabilities

Occur when untrusted data is sent to an interpreter as part of a command or query.

<div class="grid cards" markdown>

-   :material-database-alert:{ .lg .middle } **SQL Injection**

    ---

    Manipulate SQL queries through user input

    [:octicons-arrow-right-24: Learn more](sql-injection.md)

-   :material-console:{ .lg .middle } **Command Injection**

    ---

    Execute arbitrary system commands

    [:octicons-arrow-right-24: Learn more](command-injection.md)

-   :material-code-tags:{ .lg .middle } **Cross-Site Scripting (XSS)**

    ---

    Inject malicious scripts into web pages

    [:octicons-arrow-right-24: Learn more](xss.md)

-   :material-file-code:{ .lg .middle } **Server-Side Template Injection**

    ---

    Inject code into template engines

    [:octicons-arrow-right-24: Learn more](ssti.md)

</div>

### Data Exposure Vulnerabilities

Occur when sensitive data is accessed or transmitted insecurely.

<div class="grid cards" markdown>

-   :material-folder-alert:{ .lg .middle } **Path Traversal**

    ---

    Access files outside intended directories

    [:octicons-arrow-right-24: Learn more](path-traversal.md)

-   :material-web:{ .lg .middle } **Server-Side Request Forgery**

    ---

    Force server to make unintended requests

    [:octicons-arrow-right-24: Learn more](ssrf.md)

-   :material-xml:{ .lg .middle } **XML External Entity (XXE)**

    ---

    Exploit XML parser vulnerabilities

    [:octicons-arrow-right-24: Learn more](xxe.md)

</div>

### Deserialization Vulnerabilities

Occur when untrusted data is used to abuse application logic or execute code.

<div class="grid cards" markdown>

-   :material-package-variant:{ .lg .middle } **Insecure Deserialization**

    ---

    Execute code through object deserialization

    [:octicons-arrow-right-24: Learn more](deserialization.md)

</div>

## OWASP Top 10 Mapping

| OWASP 2021 | VulnShop Vulnerabilities |
|------------|--------------------------|
| A01: Broken Access Control | Path Traversal, IDOR |
| A02: Cryptographic Failures | Weak Cryptography, Hardcoded Secrets |
| A03: Injection | SQL Injection, Command Injection, XSS, SSTI |
| A04: Insecure Design | Mass Assignment |
| A05: Security Misconfiguration | XXE |
| A06: Vulnerable Components | - |
| A07: Auth Failures | - |
| A08: Data Integrity Failures | Insecure Deserialization |
| A09: Logging Failures | Sensitive Logging |
| A10: SSRF | SSRF |

## Detection Difficulty

Understanding why some vulnerabilities are harder to detect:

### Easy to Detect

**Pattern-based detection works well:**

- SQL Injection (f-string patterns)
- Command Injection (os.system calls)
- Hardcoded Secrets (string patterns)
- XXE (parser configuration)

### Medium Difficulty

**Requires dataflow tracking:**

- XSS (source-to-sink flow)
- SSRF (URL construction)
- Path Traversal (path manipulation)
- SSTI (template rendering)

### Hard to Detect

**Requires semantic understanding:**

- IDOR (authorization logic)
- Mass Assignment (framework behavior)
- Stored XSS (multi-stage flow)
- Business Logic Flaws

## Reading Guide

For each vulnerability, documentation includes:

1. **Description** - What the vulnerability is and why it's dangerous
2. **VulnShop Location** - Where to find it in the codebase
3. **Attack Scenario** - How an attacker could exploit it
4. **Detection Methods** - How each tool detects it
5. **Remediation** - How to fix the vulnerability
6. **References** - CWE, OWASP, and other resources

## Start Learning

Choose your learning path:

### By Severity (Critical First)

1. [SQL Injection](sql-injection.md) - Database compromise
2. [Command Injection](command-injection.md) - Server takeover
3. [Insecure Deserialization](deserialization.md) - Remote code execution
4. [SSRF](ssrf.md) - Internal network access

### By Prevalence (Most Common)

1. [XSS](xss.md) - Most common web vulnerability
2. [SQL Injection](sql-injection.md) - Classic injection attack
3. [Path Traversal](path-traversal.md) - File access vulnerability
4. [SSRF](ssrf.md) - Growing threat in cloud environments

### By Detection Method

**Pattern Matching:**

- [SQL Injection](sql-injection.md)
- [Command Injection](command-injection.md)

**Taint Tracking:**

- [XSS](xss.md)
- [SSRF](ssrf.md)
- [Path Traversal](path-traversal.md)

**Configuration Analysis:**

- [XXE](xxe.md)
- [Insecure Deserialization](deserialization.md)
