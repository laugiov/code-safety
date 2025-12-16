---
title: Tool Comparison
description: Comprehensive comparison of Pysa, CodeQL, and Semgrep
---

# Tool Comparison

This page provides a detailed comparison of the three taint analysis tools configured in this project: **Pysa**, **CodeQL**, and **Semgrep**.

## Overview

| Aspect | Pysa | CodeQL | Semgrep |
|--------|------|--------|---------|
| **Developer** | Meta (Facebook) | GitHub (Microsoft) | Semgrep Inc. |
| **First Release** | 2019 | 2019 (public) | 2020 |
| **License** | MIT | Custom (free for OSS) | LGPL |
| **Primary Language** | Python (stubs) | QL (Datalog variant) | YAML |
| **Analysis Type** | Taint Tracking | Semantic Analysis | Pattern Matching |

## Analysis Approach

### Pysa

**Type: Inter-procedural Taint Tracking**

Pysa (Python Static Analyzer) is built on Meta's Pyre type checker. It performs deep taint tracking with type information.

```
Source (request.GET) → Model Definition → Taint Propagation → Sink (cursor.execute)
```

**Strengths:**
- Deep inter-procedural analysis
- Leverages type information
- Production-tested at Meta scale
- Custom source/sink/sanitizer definitions

**Weaknesses:**
- Python-only
- Steeper learning curve
- Requires type stubs/models

### CodeQL

**Type: Semantic Code Analysis**

CodeQL creates a queryable database of code semantics, enabling powerful QL queries.

```
Code → Database Creation → QL Query Execution → Results
```

**Strengths:**
- Most expressive query language
- Deep semantic understanding
- Excellent documentation
- Native GitHub integration

**Weaknesses:**
- Slow database creation
- Complex query language
- Resource intensive

### Semgrep

**Type: Syntactic Pattern Matching**

Semgrep uses structural pattern matching with optional taint tracking.

```
Pattern (YAML) → Code Matching → Results
```

**Strengths:**
- Very fast execution
- Easy YAML rules
- Low false positive rate
- Great CI/CD experience

**Weaknesses:**
- Shallower analysis
- Limited cross-file tracking
- Less precise for complex flows

## Performance Comparison

### Detection Rates (VulnShop Benchmark)

| Metric | Pysa | CodeQL | Semgrep |
|--------|:----:|:------:|:-------:|
| **Detection Rate** | 75.0% | 87.5% | 68.75% |
| **Precision** | 85.0% | 92.0% | 78.0% |
| **Recall** | 75.0% | 87.5% | 68.75% |
| **F1 Score** | 0.80 | 0.90 | 0.73 |
| **Execution Time** | ~45s | ~120s | ~5s |

### Detection by Vulnerability Type

| Vulnerability | Pysa | CodeQL | Semgrep |
|--------------|:----:|:------:|:-------:|
| SQL Injection | ✅ | ✅ | ✅ |
| Command Injection | ✅ | ✅ | ✅ |
| XSS (Reflected) | ✅ | ✅ | ✅ |
| XSS (Stored) | ✅ | ✅ | ⚠️ |
| Path Traversal | ✅ | ✅ | ✅ |
| SSRF | ✅ | ✅ | ✅ |
| Deserialization | ✅ | ✅ | ✅ |
| SSTI | ✅ | ✅ | ✅ |
| XXE | ✅ | ✅ | ✅ |
| IDOR | ⚠️ | ⚠️ | ❌ |
| Mass Assignment | ❌ | ⚠️ | ⚠️ |
| Hardcoded Secrets | ❌ | ✅ | ✅ |
| Sensitive Logging | ✅ | ✅ | ⚠️ |

✅ = Detected | ⚠️ = Partial | ❌ = Not Detected

## Rule/Model Syntax

### Pysa Model Example

```python
# django_sources.pysa
def django.http.request.HttpRequest.GET.__getitem__(
    self,
    key
) -> TaintSource[UserControlled]: ...

# django_sinks.pysa
def django.db.connection.cursor.execute(
    self,
    sql: TaintSink[SQL],
    params = ...
): ...
```

### CodeQL Query Example

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

### Semgrep Rule Example

```yaml
rules:
  - id: sql-injection
    message: SQL Injection detected
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: cursor.execute($QUERY)
          - pattern: cursor.execute(f"...", ...)
    pattern-sources:
      - pattern: request.GET.get(...)
```

## Use Case Recommendations

### When to Use Pysa

Best for:

- **Deep taint analysis** in Python codebases
- **Type-aware** security analysis
- **Large codebases** with complex data flows
- Teams already using **Pyre** for type checking

Example scenarios:

- Tracking sensitive data through complex APIs
- Analyzing Django/Flask applications thoroughly
- Finding indirect injection vulnerabilities

### When to Use CodeQL

Best for:

- **Maximum precision** requirements
- **Custom security research** and queries
- **Multi-language** projects
- GitHub-hosted repositories (native integration)

Example scenarios:

- Security audit of critical applications
- Developing organization-specific security rules
- Variant analysis after finding a vulnerability

### When to Use Semgrep

Best for:

- **CI/CD integration** (speed is critical)
- **Quick wins** on common vulnerabilities
- **Developer-friendly** enforcement
- Teams with **limited security expertise**

Example scenarios:

- Pre-commit hooks for security checks
- Pull request security gates
- Rapid scanning during development

## Recommended Strategy: Defense in Depth

Use multiple tools for comprehensive coverage:

```
┌─────────────────────────────────────────────────────────────┐
│                    DEFENSE IN DEPTH                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐          │
│   │ SEMGREP  │     │  CODEQL  │     │   PYSA   │          │
│   │          │     │          │     │          │          │
│   │ Pre-     │     │ PR       │     │ Nightly  │          │
│   │ commit   │     │ Review   │     │ Deep     │          │
│   │ ~5s      │     │ ~2min    │     │ Scan     │          │
│   └────┬─────┘     └────┬─────┘     └────┬─────┘          │
│        │                │                 │                 │
│        ▼                ▼                 ▼                 │
│   ┌─────────────────────────────────────────────┐          │
│   │           SECURITY DASHBOARD                │          │
│   │         (GitHub Security Tab)               │          │
│   └─────────────────────────────────────────────┘          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### CI/CD Pipeline Example

```yaml
# Pre-commit (immediate feedback)
pre-commit:
  - semgrep --config auto .

# Pull Request (comprehensive)
pull-request:
  - semgrep --config r/python.django.security
  - codeql analyze --output=results.sarif

# Nightly (deep analysis)
scheduled:
  - pysa analyze --output=findings.json
  - codeql analyze --query-suites=security-extended
```

## Learning Curve

### Time to Proficiency

| Tool | Basic Usage | Custom Rules | Advanced |
|------|-------------|--------------|----------|
| Semgrep | Hours | Days | Weeks |
| Pysa | Days | Weeks | Months |
| CodeQL | Days | Weeks | Months |

### Documentation Quality

| Tool | Docs | Examples | Community |
|------|:----:|:--------:|:---------:|
| Semgrep | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| CodeQL | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| Pysa | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |

## Cost Considerations

| Tool | Open Source | Enterprise |
|------|-------------|------------|
| Semgrep | Free | Paid (Team features) |
| CodeQL | Free for OSS | GitHub Advanced Security |
| Pysa | Free | Free |

## Conclusion

| Goal | Recommendation |
|------|----------------|
| Best coverage | CodeQL |
| Fastest scanning | Semgrep |
| Deepest Python analysis | Pysa |
| Best CI/CD experience | Semgrep |
| Most flexible queries | CodeQL |
| Best for type-aware analysis | Pysa |
| Defense in depth | All three |

---

*Next: [Pysa Configuration](pysa/index.md) | [CodeQL Queries](codeql/index.md) | [Semgrep Rules](semgrep/index.md)*
