---
title: Analysis Tools
description: Overview of Pysa, CodeQL, and Semgrep for taint analysis
---

# Analysis Tools

This project provides production-ready configurations for three industry-leading static analysis tools. Each has unique strengths suited to different use cases.

## Tool Overview

<div class="grid cards" markdown>

-   :material-snake:{ .lg .middle } **Pysa** (Meta)

    ---

    Deep inter-procedural taint tracking built on Pyre type checker

    [:octicons-arrow-right-24: Pysa Guide](pysa/index.md)

-   :material-database-search:{ .lg .middle } **CodeQL** (GitHub)

    ---

    Semantic code analysis with powerful query language

    [:octicons-arrow-right-24: CodeQL Guide](codeql/index.md)

-   :material-magnify-scan:{ .lg .middle } **Semgrep** (Semgrep Inc.)

    ---

    Fast pattern matching with simple YAML rules

    [:octicons-arrow-right-24: Semgrep Guide](semgrep/index.md)

</div>

## Quick Comparison

| Aspect | Pysa | CodeQL | Semgrep |
|--------|:----:|:------:|:-------:|
| **Developer** | Meta | GitHub | Semgrep Inc. |
| **Language** | Python (stubs) | QL | YAML |
| **Analysis Type** | Taint Tracking | Semantic | Pattern Matching |
| **Precision** | High | Very High | Medium |
| **Speed** | Medium (~45s) | Slow (~120s) | Fast (~5s) |
| **Learning Curve** | High | High | Medium |

## Performance on VulnShop

| Metric | Pysa | CodeQL | Semgrep |
|--------|:----:|:------:|:-------:|
| **Detection Rate** | 75.0% | 87.5% | 68.8% |
| **Precision** | 85.0% | 92.0% | 78.0% |
| **Recall** | 75.0% | 87.5% | 68.8% |
| **F1 Score** | 0.80 | 0.90 | 0.73 |

## When to Use Each Tool

### Use Pysa When...

- You need deep inter-procedural analysis
- Your codebase is primarily Python
- You're already using Pyre for type checking
- You need to track complex data flows

### Use CodeQL When...

- You need maximum precision
- You're developing custom security research
- You're using GitHub (native integration)
- You have time for longer scan durations

### Use Semgrep When...

- Speed is critical (CI/CD gates)
- You need quick wins on common patterns
- Your team has limited security expertise
- You want easy rule customization

## Recommended Strategy

For defense in depth, use multiple tools:

```
┌─────────────────────────────────────────────────────────────┐
│                     DEVELOPMENT PIPELINE                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   PRE-COMMIT         PR REVIEW          NIGHTLY             │
│   ┌──────────┐       ┌──────────┐       ┌──────────┐       │
│   │ SEMGREP  │       │ SEMGREP  │       │  PYSA    │       │
│   │ (~5s)    │       │ + CodeQL │       │ + CodeQL │       │
│   │ Fast     │       │ (~3min)  │       │ Deep     │       │
│   │ feedback │       │ PR block │       │ analysis │       │
│   └──────────┘       └──────────┘       └──────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Project Configuration Files

| Tool | Key Files |
|------|-----------|
| **Pysa** | `.pyre_configuration`, `taint.config`, `models/*.pysa` |
| **CodeQL** | `codeql-config.yml`, `queries/*.ql`, `suites/*.qls` |
| **Semgrep** | `.semgrep.yml`, `rules/**/*.yml` |

## Running Analyses

### All Tools

```bash
make analyze-all
```

### Individual Tools

```bash
make analyze-pysa
make analyze-codeql
make analyze-semgrep
```

### Direct Script Execution

```bash
# Pysa
cd analysis/pysa && ./scripts/run_pysa.sh

# CodeQL
cd analysis/codeql && ./scripts/run_analysis.sh

# Semgrep
cd analysis/semgrep && ./scripts/run_semgrep.sh
```

## Results Format

All tools output results in **SARIF** (Static Analysis Results Interchange Format):

```json
{
  "runs": [{
    "tool": { "driver": { "name": "Semgrep" } },
    "results": [
      {
        "ruleId": "sql-injection",
        "message": { "text": "SQL injection detected" },
        "locations": [{
          "physicalLocation": {
            "artifactLocation": { "uri": "views.py" },
            "region": { "startLine": 42 }
          }
        }]
      }
    ]
  }]
}
```

SARIF is compatible with:
- GitHub Security tab
- VS Code SARIF Viewer
- Azure DevOps
- Many other security platforms

---

*Choose a tool to learn more: [Pysa](pysa/index.md) | [CodeQL](codeql/index.md) | [Semgrep](semgrep/index.md)*
