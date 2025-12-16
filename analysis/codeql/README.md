# CodeQL Analysis Configuration

> **CodeQL** is GitHub's semantic code analysis engine that finds vulnerabilities by treating code as data and running queries against it.

## Overview

This directory contains the complete CodeQL configuration for analyzing the VulnShop vulnerable Django application. CodeQL performs deep semantic analysis to detect security vulnerabilities through data flow and taint tracking.

## Directory Structure

```
codeql/
├── codeql-config.yml        # Main CodeQL configuration
├── qlpack.yml               # Query pack definition
├── queries/
│   ├── sql-injection.ql     # SQL Injection detection
│   ├── command-injection.ql # Command Injection detection
│   ├── xss-reflected.ql     # Reflected XSS detection
│   ├── xss-stored.ql        # Stored XSS detection
│   ├── ssrf.ql              # SSRF detection
│   ├── path-traversal.ql    # Path Traversal detection
│   ├── deserialization.ql   # Insecure Deserialization
│   ├── ssti.ql              # Template Injection
│   ├── xxe.ql               # XXE detection
│   ├── hardcoded-secrets.ql # Hardcoded credentials
│   ├── sensitive-logging.ql # Sensitive data logging
│   ├── idor.ql              # IDOR patterns
│   └── mass-assignment.ql   # Mass assignment
├── suites/
│   ├── vulnshop-security.qls # Security-focused suite
│   └── vulnshop-full.qls     # Complete analysis suite
├── libraries/
│   ├── DjangoSources.qll    # Django source definitions
│   └── DjangoSinks.qll      # Django sink definitions
├── scripts/
│   └── run_analysis.sh      # Analysis runner script
├── results/
│   └── .gitkeep
└── README.md                # This file
```

## Quick Start

### Prerequisites

```bash
# Install CodeQL CLI
# Download from: https://github.com/github/codeql-cli-binaries/releases

# Verify installation
codeql version
```

### Running Analysis

```bash
# Full analysis with database creation
./scripts/run_analysis.sh

# Use existing database
./scripts/run_analysis.sh --skip-db-creation

# Run full suite (including code quality)
./scripts/run_analysis.sh --suite full

# Verbose output
./scripts/run_analysis.sh --verbose
```

### Output

Results are saved to:
- `results/codeql_results.sarif` - SARIF format for GitHub Security
- `results/analysis.log` - Analysis log
- `vulnshop-db/` - CodeQL database

## Query Writing

### Query Structure

```ql
/**
 * @name Query Name
 * @description What this query detects
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/query-id
 * @tags security
 *       external/cwe/cwe-89
 */

import python
import semmle.python.dataflow.new.TaintTracking

class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Define sources
  }

  override predicate isSink(DataFlow::Node sink) {
    // Define sinks
  }
}

from MyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Message: $@", source.getNode(), "source description"
```

### Query Metadata

| Annotation | Description |
|-----------|-------------|
| `@name` | Human-readable name |
| `@description` | Detailed description |
| `@kind` | `problem` or `path-problem` |
| `@problem.severity` | `error`, `warning`, `recommendation` |
| `@security-severity` | CVSS score (0.0-10.0) |
| `@precision` | `high`, `medium`, `low` |
| `@id` | Unique identifier |
| `@tags` | Categories and CWE/OWASP references |

## Detection Matrix

| Vulnerability | CWE | Query | Expected |
|--------------|-----|-------|----------|
| SQL Injection (Auth) | CWE-89 | sql-injection.ql | ✅ |
| SQL Injection (Search) | CWE-89 | sql-injection.ql | ✅ |
| Reflected XSS | CWE-79 | xss-reflected.ql | ✅ |
| Stored XSS | CWE-79 | xss-stored.ql | ✅ |
| Command Injection | CWE-78 | command-injection.ql | ✅ |
| Path Traversal | CWE-22 | path-traversal.ql | ✅ |
| IDOR | CWE-639 | idor.ql | ⚠️ Partial |
| Mass Assignment | CWE-915 | mass-assignment.ql | ⚠️ Partial |
| SSRF | CWE-918 | ssrf.ql | ✅ |
| Insecure Deserialization | CWE-502 | deserialization.ql | ✅ |
| SSTI | CWE-1336 | ssti.ql | ✅ |
| Hardcoded Secrets | CWE-798 | hardcoded-secrets.ql | ✅ |
| Vulnerable Dependencies | CWE-1035 | N/A | ❌ |
| Sensitive Logging | CWE-532 | sensitive-logging.ql | ✅ |
| XXE | CWE-611 | xxe.ql | ✅ |
| Brute Force | CWE-307 | N/A | ❌ |

**Expected Detection Rate: 14/16 (87.5%)**

## Custom Libraries

### DjangoSources.qll

Extends RemoteFlowSource to include Django-specific sources:

```ql
import DjangoSources

// Now includes:
// - request.GET, request.POST
// - request.COOKIES, request.FILES
// - request.body, request.headers
// - DRF request.data, request.query_params
// - URL parameters (pk, id, slug, etc.)
```

### DjangoSinks.qll

Defines Django-specific security sinks:

```ql
import DjangoSinks

// Includes:
// - DjangoSqlSink (cursor.execute, raw queries)
// - DjangoTemplateSink (Template construction)
// - DjangoMarkSafeSink (XSS)
// - DjangoRedirectSink (Open redirect)
// - DjangoFileSink (FileResponse)
```

## GitHub Actions Integration

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v3
  with:
    languages: python
    config-file: analysis/codeql/codeql-config.yml
    queries: +analysis/codeql/queries

- name: Autobuild
  uses: github/codeql-action/autobuild@v3

- name: Perform CodeQL Analysis
  uses: github/codeql-action/analyze@v3
  with:
    category: codeql-python
```

## Troubleshooting

### Database Creation Fails

```bash
# Check Python version
python3 --version

# Create database with verbose output
codeql database create vulnshop-db \
    --language=python \
    --source-root=../../vulnerable-app \
    --overwrite \
    --verbose
```

### No Results

1. Verify queries compile: `codeql query compile queries/`
2. Check database: `codeql database analyze vulnshop-db --dry-run`
3. Run with verbose: `--verbose` flag

### Performance Issues

```bash
# Increase threads
codeql database analyze ... --threads=8

# Use RAM disk for database
export CODEQL_RAM=/tmp/codeql
```

## References

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CodeQL for Python](https://codeql.github.com/docs/codeql-language-guides/codeql-for-python/)
- [Writing CodeQL Queries](https://codeql.github.com/docs/writing-codeql-queries/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

---

*Part of the Taint Analysis Masterclass project*
