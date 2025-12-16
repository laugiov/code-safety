# Benchmarks

> Rigorous comparison of Pysa, CodeQL, and Semgrep against documented vulnerabilities.

## Overview

This directory contains the benchmark infrastructure for comparing taint analysis tools against the VulnShop application. Our methodology provides quantitative metrics (Precision, Recall, F1) alongside qualitative analysis of detection capabilities.

## Directory Structure

```
benchmarks/
├── ground-truth/               # Definitive vulnerability catalog
│   ├── vulnerabilities.json    # 16 documented vulnerabilities
│   └── taint-flows.yaml        # Detailed source-to-sink flows
│
├── cve-reproductions/          # Real-world CVE patterns
│   ├── cve_2023_36414.py       # Django Trunc/Extract SQLi
│   ├── cve_2022_34265.py       # Django SQL Injection
│   ├── log4shell_pattern.py    # Expression injection (Python equivalent)
│   └── README.md               # CVE documentation
│
├── scripts/                    # Benchmark automation
│   ├── run_benchmarks.py       # Main benchmark runner
│   ├── generate_report.py      # Report generator
│   └── utils/                  # Helper utilities
│
├── results/                    # Analysis outputs
│   ├── pysa/                   # Pysa results
│   ├── codeql/                 # CodeQL results
│   └── semgrep/                # Semgrep results
│
└── reports/                    # Generated reports
    └── charts/                 # Visualization images
```

## Quick Start

### Run Complete Benchmark Suite

```bash
# Run all tools against VulnShop
python scripts/run_benchmarks.py

# Run specific tools
python scripts/run_benchmarks.py --tools pysa,semgrep

# Verbose output
python scripts/run_benchmarks.py --verbose

# Use existing results (skip execution)
python scripts/run_benchmarks.py --skip-execution
```

### Generate Reports

```bash
# Generate all report formats
python scripts/generate_report.py

# Markdown only
python scripts/generate_report.py --format markdown

# HTML with charts
python scripts/generate_report.py --format html --include-charts
```

## Ground Truth

### Vulnerability Catalog

The ground truth consists of 16 intentionally vulnerable code patterns in VulnShop:

| # | Vulnerability | CWE | Expected Detection |
|---|--------------|-----|-------------------|
| 1 | SQL Injection (Auth) | CWE-89 | ✅ All |
| 2 | SQL Injection (Search) | CWE-89 | ✅ All |
| 3 | Reflected XSS | CWE-79 | ✅ All |
| 4 | Stored XSS | CWE-79 | ⚠️ Partial |
| 5 | Command Injection | CWE-78 | ✅ All |
| 6 | Path Traversal | CWE-22 | ✅ All |
| 7 | IDOR | CWE-639 | ⚠️ Partial |
| 8 | Mass Assignment | CWE-915 | ⚠️ Partial |
| 9 | SSRF | CWE-918 | ✅ All |
| 10 | Insecure Deserialization | CWE-502 | ✅ All |
| 11 | SSTI | CWE-1336 | ✅ All |
| 12 | Hardcoded Secrets | CWE-798 | ⚠️ Not Pysa |
| 13 | Vulnerable Dependencies | CWE-1035 | ❌ None |
| 14 | Sensitive Logging | CWE-532 | ⚠️ Partial |
| 15 | XXE | CWE-611 | ✅ All |
| 16 | Brute Force | CWE-307 | ❌ None |

### Taint Flow Documentation

Each vulnerability includes detailed taint flow documentation:

```yaml
flows:
  - id: FLOW-SQL-001
    source:
      type: http_request
      code: "request.POST.get('username')"
    propagation:
      - step: 1
        description: "Assigned to local variable"
      - step: 2
        description: "Interpolated into f-string"
    sink:
      type: sql_execution
      code: "cursor.execute(query)"
```

## Metrics

### Definition

| Metric | Formula | Description |
|--------|---------|-------------|
| **Precision** | TP / (TP + FP) | Accuracy of positive predictions |
| **Recall** | TP / (TP + FN) | Coverage of actual vulnerabilities |
| **F1 Score** | 2 × (P × R) / (P + R) | Harmonic mean of P and R |

### Expected Results

| Tool | Detection Rate | Precision | Recall | F1 Score | Time |
|------|---------------|-----------|--------|----------|------|
| **Pysa** | 75.0% | 85.0% | 75.0% | 0.80 | ~45s |
| **CodeQL** | 87.5% | 92.0% | 87.5% | 0.90 | ~120s |
| **Semgrep** | 68.75% | 78.0% | 68.75% | 0.73 | ~5s |

## CVE Reproductions

Real-world vulnerability patterns reproduced for validation:

### CVE-2023-36414 / CVE-2022-34265 (Django SQL Injection)

```python
# Vulnerable: User input in Trunc/Extract kind parameter
interval = request.GET.get('interval')
orders.annotate(period=Trunc('created_at', kind=interval))

# Fixed: Allowlist validation
if interval not in VALID_KINDS:
    return HttpResponseBadRequest()
```

### Log4Shell Pattern (Expression Injection)

```python
# Vulnerable: User input interpreted as format string
log_template = request.GET.get('format')
logger.info(log_template.format(user=user))

# Fixed: Use parameterized logging
logger.info("User action", extra={'user': user})
```

## Methodology

### Matching Algorithm

Findings are matched to ground truth using:

1. **File Matching:** Compare finding file path to vulnerability location
2. **Line Range:** Check if finding line is within vulnerability range (±20 lines)
3. **CWE Matching:** Verify CWE identifiers match
4. **Rule Correlation:** Map tool-specific rules to vulnerability types

### Limitations

1. **Heuristic Matching:** File/line matching may miss alternative locations
2. **Partial Detections:** Some vulnerabilities have nuanced detection states
3. **Configuration Variance:** Tool configs may not be fully optimized
4. **Static Analysis Limits:** Some vulnerabilities require runtime context

## Usage in CI/CD

### GitHub Actions Integration

```yaml
- name: Run Security Benchmarks
  run: |
    cd benchmarks
    python scripts/run_benchmarks.py --tools pysa,semgrep
    python scripts/generate_report.py --format markdown

- name: Upload Benchmark Report
  uses: actions/upload-artifact@v3
  with:
    name: benchmark-report
    path: benchmarks/reports/
```

### Regression Testing

```bash
# Compare against baseline
python scripts/run_benchmarks.py
diff results/benchmark_results.json baseline/expected_results.json
```

## Contributing

### Adding Vulnerabilities

1. Add code to VulnShop with proper documentation
2. Update `ground-truth/vulnerabilities.json`
3. Add taint flow to `ground-truth/taint-flows.yaml`
4. Update expected detection matrix

### Adding CVE Reproductions

1. Create `cve_YYYY_NNNNN.py` with standard header
2. Include vulnerable and fixed code patterns
3. Document taint flow
4. Add to CVE catalog in README

## References

- [NIST NVD](https://nvd.nist.gov/)
- [CWE Database](https://cwe.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SARIF Specification](https://sarifweb.azurewebsites.net/)

---

*Part of the Taint Analysis Masterclass project*
