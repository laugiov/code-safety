---
title: CodeQL
description: GitHub's semantic code analysis engine
---

# CodeQL

**CodeQL** is GitHub's semantic code analysis engine that treats code as data, enabling powerful queries to find security vulnerabilities and code quality issues.

## Overview

| Aspect | Details |
|--------|---------|
| **Developer** | GitHub (Microsoft) |
| **Website** | [codeql.github.com](https://codeql.github.com/) |
| **License** | Free for open source, paid for private repos |
| **Language** | QL (Datalog-based query language) |
| **Best For** | Deep semantic analysis and custom security research |

## Key Features

- **Semantic analysis** - Understands code meaning, not just syntax
- **Powerful query language** - QL enables complex patterns
- **Native GitHub integration** - Results in Security tab
- **Large query library** - Extensive community queries
- **Multi-language support** - Python, JavaScript, Java, C++, and more

## Quick Start

### Installation

Download CodeQL CLI from [GitHub Releases](https://github.com/github/codeql-action/releases).

```bash
# Extract and add to PATH
export PATH="$PATH:/path/to/codeql"

# Verify
codeql --version
```

### Run Analysis

```bash
cd analysis/codeql
./scripts/run_analysis.sh
```

## Configuration Structure

```
analysis/codeql/
├── codeql-config.yml       # Main configuration
├── qlpack.yml              # Query pack definition
├── queries/
│   ├── sql-injection.ql
│   ├── command-injection.ql
│   ├── xss-reflected.ql
│   ├── xss-stored.ql
│   ├── ssrf.ql
│   ├── path-traversal.ql
│   ├── deserialization.ql
│   ├── ssti.ql
│   ├── xxe.ql
│   └── ...
├── suites/
│   ├── vulnshop-security.qls
│   └── vulnshop-full.qls
├── libraries/
│   ├── DjangoSources.qll
│   └── DjangoSinks.qll
└── scripts/
    └── run_analysis.sh
```

## How CodeQL Works

### 1. Create Database

CodeQL first creates a relational database of your code:

```bash
codeql database create vulnshop-db \
  --language=python \
  --source-root=vulnerable-app
```

### 2. Write Queries

Queries use QL to find patterns:

```ql
/**
 * @name SQL Injection
 * @kind path-problem
 */
import python
import semmle.python.dataflow.new.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution sql | sink = sql.getSql())
  }
}
```

### 3. Run Analysis

```bash
codeql database analyze vulnshop-db \
  --format=sarif-latest \
  --output=results.sarif \
  vulnshop-security.qls
```

## VulnShop Results

CodeQL detects these vulnerabilities:

| Vulnerability | Detected | Query |
|---------------|:--------:|:------|
| SQL Injection (Auth) | ✅ | `sql-injection.ql` |
| SQL Injection (Search) | ✅ | `sql-injection.ql` |
| Command Injection | ✅ | `command-injection.ql` |
| XSS (Reflected) | ✅ | `xss-reflected.ql` |
| XSS (Stored) | ✅ | `xss-stored.ql` |
| Path Traversal | ✅ | `path-traversal.ql` |
| SSRF | ✅ | `ssrf.ql` |
| Deserialization | ✅ | `deserialization.ql` |
| SSTI | ✅ | `ssti.ql` |
| XXE | ✅ | `xxe.ql` |
| Hardcoded Secrets | ✅ | `hardcoded-secrets.ql` |
| Sensitive Logging | ✅ | `sensitive-logging.ql` |
| IDOR | ⚠️ | `idor.ql` |
| Mass Assignment | ⚠️ | `mass-assignment.ql` |

**Detection Rate: 87.5% (14/16)** - Highest among the three tools

## Section Navigation

<div class="grid cards" markdown>

-   :material-database:{ .lg .middle } **Database Creation**

    ---

    Creating and managing CodeQL databases

    [:octicons-arrow-right-24: Database Guide](database.md)

-   :material-file-code:{ .lg .middle } **Writing Queries**

    ---

    Learn to write custom QL queries

    [:octicons-arrow-right-24: Query Guide](queries.md)

-   :material-star:{ .lg .middle } **Advanced**

    ---

    Advanced patterns and optimization

    [:octicons-arrow-right-24: Advanced](advanced.md)

</div>

## GitHub Integration

CodeQL integrates natively with GitHub:

```yaml
# .github/workflows/codeql.yml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python
    queries: security-extended

- name: Perform Analysis
  uses: github/codeql-action/analyze@v3
```

Results appear in the repository's **Security** tab.

## Resources

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CodeQL for Python](https://codeql.github.com/docs/codeql-language-guides/codeql-for-python/)
- [Query Examples](https://github.com/github/codeql/tree/main/python/ql/src)
- [QL Language Reference](https://codeql.github.com/docs/ql-language-reference/)
