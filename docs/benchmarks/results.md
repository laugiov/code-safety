---
title: Benchmark Results
description: Comparative analysis results for taint analysis tools
---

# Benchmark Results

Detailed results from benchmarking Pysa, CodeQL, and Semgrep against VulnShop.

## Summary

| Tool | Detection Rate | Precision | F1 Score | Time |
|------|:--------------:|:---------:|:--------:|:----:|
| CodeQL | 87.5% | 93% | 0.90 | 2m 15s |
| Pysa | 75.0% | 92% | 0.83 | 45s |
| Semgrep | 68.75% | 85% | 0.76 | 5s |

## Detection by Vulnerability

| Vulnerability | Pysa | CodeQL | Semgrep |
|---------------|:----:|:------:|:-------:|
| SQL Injection (Auth) | ✅ | ✅ | ✅ |
| SQL Injection (Search) | ✅ | ✅ | ✅ |
| Reflected XSS | ✅ | ✅ | ✅ |
| Stored XSS | ✅ | ✅ | ⚠️ |
| Command Injection | ✅ | ✅ | ✅ |
| Path Traversal | ✅ | ✅ | ✅ |
| SSRF | ✅ | ✅ | ✅ |
| Deserialization | ✅ | ✅ | ✅ |
| SSTI | ✅ | ✅ | ✅ |
| XXE | ✅ | ✅ | ✅ |
| IDOR | ⚠️ | ⚠️ | ❌ |
| Mass Assignment | ❌ | ⚠️ | ✅ |
| Hardcoded Secrets | ❌ | ✅ | ✅ |
| Sensitive Logging | ✅ | ✅ | ⚠️ |
| Weak Crypto | ❌ | ✅ | ✅ |
| Open Redirect | ⚠️ | ✅ | ⚠️ |

## Performance Comparison

### Execution Time

```
CodeQL    ████████████████████████████████████████ 135s
Pysa      ████████████████ 45s
Semgrep   ██ 5s
```

### Memory Usage

```
CodeQL    ████████████████████ 2.1 GB
Pysa      ████████████ 1.2 GB
Semgrep   ████ 0.4 GB
```

## False Positive Analysis

| Tool | Total Findings | True Positives | False Positives | FP Rate |
|------|:--------------:|:--------------:|:---------------:|:-------:|
| CodeQL | 15 | 14 | 1 | 6.7% |
| Pysa | 13 | 12 | 1 | 7.7% |
| Semgrep | 13 | 11 | 2 | 15.4% |

## Strengths & Weaknesses

### CodeQL

**Strengths:**

- Highest detection rate (87.5%)
- Best semantic understanding
- Lowest false positive rate
- Excellent for complex dataflow

**Weaknesses:**

- Slowest execution
- Highest memory usage
- Complex query language
- Requires database creation

### Pysa

**Strengths:**

- Good balance of speed and accuracy
- Strong inter-procedural analysis
- Type-aware analysis
- Lower resource usage than CodeQL

**Weaknesses:**

- Python-only
- Cannot detect pattern-based issues
- Complex model syntax
- Requires type annotations for best results

### Semgrep

**Strengths:**

- Fastest execution (5s)
- Simple rule syntax
- Easy CI/CD integration
- Large rule registry

**Weaknesses:**

- Limited dataflow tracking
- Higher false positive rate
- Misses some stored XSS
- Pattern matching limitations

## Recommendations

### Use Case: Fast CI/CD Feedback

**Recommended:** Semgrep

```yaml
# Block on critical issues only
semgrep --config "p/security-audit" --severity ERROR
```

### Use Case: Deep Security Analysis

**Recommended:** CodeQL

```yaml
# Nightly comprehensive scan
codeql database analyze --query-suite security-extended
```

### Use Case: Python-Specific Analysis

**Recommended:** Pysa + Semgrep

```yaml
# Combine for best coverage
- run: semgrep --config rules/
- run: pyre analyze
```

### Use Case: Maximum Coverage

**Recommended:** All three tools

```
Detection with all tools: 15/16 (93.75%)
Only missed: Complex IDOR pattern
```
