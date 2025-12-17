# Benchmark Results Summary

**Last Updated:** 2024-12-17
**Target Application:** VulnShop (16 documented vulnerabilities)

## Overall Detection Rates

| Tool | Detection Rate | Precision | Findings | Status |
|------|---------------|-----------|----------|--------|
| **Semgrep** | 81.25% | HIGH | 226 | ✅ Validated |
| Pysa | 75.0% | HIGH | - | ⏳ Pending |
| CodeQL | 87.5% | VERY HIGH | - | ⏳ Pending |

## Detection Matrix

| Vulnerability | CWE | Semgrep | Pysa | CodeQL |
|---------------|-----|:-------:|:----:|:------:|
| SQL Injection (Auth) | CWE-89 | ✅ | - | - |
| SQL Injection (Search) | CWE-89 | ✅ | - | - |
| Reflected XSS | CWE-79 | ✅ | - | - |
| Stored XSS | CWE-79 | ✅ | - | - |
| Command Injection | CWE-78 | ✅ | - | - |
| Path Traversal | CWE-22 | ✅ | - | - |
| IDOR | CWE-639 | ✅ | - | - |
| Mass Assignment | CWE-915 | ⚠️ | - | - |
| SSRF | CWE-918 | ✅ | - | - |
| Insecure Deserialization | CWE-502 | ✅ | - | - |
| SSTI | CWE-1336 | ✅ | - | - |
| Hardcoded Secrets | CWE-798 | ✅ | - | - |
| Vulnerable Dependencies | CWE-1035 | ❌ | - | - |
| Sensitive Data Logging | CWE-532 | ✅ | - | - |
| XXE | CWE-611 | ✅ | - | - |
| Brute Force | CWE-307 | ❌ | - | - |

**Legend:** ✅ Detected | ⚠️ Partial | ❌ Not Applicable/Not Detected | - Pending

## Execution Performance

| Tool | Scan Time | Files | Rules |
|------|-----------|-------|-------|
| Semgrep | ~5 sec | 98 | 92 |
| Pysa | ~45 sec | - | - |
| CodeQL | ~120 sec | - | - |

## Key Insights

### Semgrep Strengths
- Fast execution suitable for CI/CD gates
- Excellent detection of injection vulnerabilities
- Strong SSRF and deserialization detection
- Easy-to-maintain YAML rules

### Semgrep Limitations
- Cannot detect missing security controls (rate limiting)
- Dependency vulnerabilities require SCA tools
- Business logic flaws need custom rules

## Files Generated

- `semgrep/vulnshop-scan.json` - Raw scan results
- `semgrep/benchmark-report.md` - Detailed analysis report

## Running Benchmarks

```bash
# Run Semgrep scan
make analyze-semgrep

# Or manually
semgrep --config analysis/semgrep/rules/ vulnerable-app/ --json
```
