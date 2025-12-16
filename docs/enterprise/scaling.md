---
title: Scaling Taint Analysis
description: Strategies for scaling security analysis to large codebases
---

# Scaling Taint Analysis

Strategies for effectively analyzing large codebases and multiple repositories.

## Challenges at Scale

| Challenge | Impact | Solution |
|-----------|--------|----------|
| Analysis time | Slow feedback | Parallel execution, caching |
| Finding volume | Alert fatigue | Prioritization, baselines |
| Configuration drift | Inconsistent coverage | Centralized management |
| Resource usage | High costs | Optimized scheduling |

## Performance Optimization

### Semgrep

```bash
# Parallel execution
semgrep --jobs 8 --config rules/ .

# File type filtering
semgrep --include "*.py" --exclude "*_test.py" .

# Incremental scanning (CI)
semgrep ci --baseline-commit HEAD~1
```

### Pysa

```json
// .pyre_configuration
{
  "number_of_workers": 16,
  "parallel": true,
  "shared_memory": {
    "heap_size": 17179869184
  }
}
```

### CodeQL

```bash
# Increase threads
codeql database analyze db --threads 8 --ram 16384

# Use query caching
codeql database analyze db --search-path ~/.codeql/packages
```

## Repository Strategy

### Monorepo

```yaml
# Single scan, multiple paths
paths:
  - services/auth/
  - services/api/
  - shared/common/
paths-ignore:
  - "**/node_modules/"
  - "**/tests/"
```

### Multi-repo

```yaml
# Centralized rules, distributed execution
jobs:
  security-scan:
    strategy:
      matrix:
        repo: [service-a, service-b, service-c]
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ matrix.repo }}
      - run: semgrep --config central-rules/ .
```

## Caching Strategies

### CI/CD Cache

```yaml
# GitHub Actions
- uses: actions/cache@v4
  with:
    path: |
      ~/.semgrep/
      ~/.codeql/
    key: security-cache-${{ hashFiles('rules/**') }}
```

### Database Reuse (CodeQL)

```bash
# Create database once, analyze multiple times
codeql database create db --language=python
codeql database analyze db query1.ql
codeql database analyze db query2.ql
```

## Prioritization Framework

### Severity Tiers

| Tier | Severity | SLA | Action |
|------|----------|-----|--------|
| P0 | Critical | 24h | Block deployment |
| P1 | High | 7 days | Fix before release |
| P2 | Medium | 30 days | Track in backlog |
| P3 | Low | Quarterly | Best effort |

### Risk-Based Prioritization

```python
RISK_SCORE = (
    SEVERITY_WEIGHT * severity +
    EXPLOITABILITY_WEIGHT * exploitability +
    EXPOSURE_WEIGHT * is_public_facing +
    DATA_WEIGHT * handles_sensitive_data
)
```

## Metrics Dashboard

Track these metrics across repositories:

```yaml
metrics:
  - name: detection_rate
    query: findings / known_vulnerabilities
  - name: false_positive_rate
    query: false_positives / total_findings
  - name: mean_time_to_fix
    query: avg(fix_date - detection_date)
  - name: coverage
    query: repos_scanned / total_repos
```

## Best Practices

1. **Start small** - Pilot with high-risk repos
2. **Standardize** - Central rule management
3. **Automate** - Integrate into CI/CD
4. **Measure** - Track effectiveness metrics
5. **Iterate** - Continuously improve rules
