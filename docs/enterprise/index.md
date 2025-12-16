---
title: Enterprise Guide
description: Deploying taint analysis at scale in enterprise environments
---

# Enterprise Guide

This section covers deploying taint analysis tools in enterprise environments, including CI/CD integration, false positive management, and scaling strategies.

## Overview

Implementing security analysis at enterprise scale requires:

1. **CI/CD Integration** - Automated analysis in development pipelines
2. **False Positive Management** - Efficient triage and baseline management
3. **Scaling** - Handling large codebases and multiple repositories
4. **Governance** - Security policies and compliance

<div class="grid cards" markdown>

-   :material-pipe:{ .lg .middle } **CI/CD Integration**

    ---

    Automate security analysis in your pipelines

    [:octicons-arrow-right-24: CI/CD Guide](ci-cd.md)

-   :material-filter:{ .lg .middle } **False Positive Management**

    ---

    Efficiently manage and reduce noise

    [:octicons-arrow-right-24: False Positives](false-positives.md)

-   :material-scale-balance:{ .lg .middle } **Scaling**

    ---

    Handle large codebases effectively

    [:octicons-arrow-right-24: Scaling Guide](scaling.md)

-   :material-gavel:{ .lg .middle } **Governance**

    ---

    Security policies and compliance

    [:octicons-arrow-right-24: Governance](governance.md)

</div>

## Tool Selection Matrix

| Factor | Pysa | CodeQL | Semgrep |
|--------|:----:|:------:|:-------:|
| **Speed** | Medium | Slow | Fast |
| **Accuracy** | High | Highest | Medium |
| **Ease of Use** | Medium | Complex | Easy |
| **Custom Rules** | Medium | Complex | Easy |
| **CI/CD Support** | Good | Excellent | Excellent |
| **Cost** | Free | Free/Paid | Free/Paid |

### Recommended Combinations

**Speed-focused Pipeline:**
```
Semgrep → Quick feedback on PRs (seconds)
```

**Accuracy-focused Pipeline:**
```
CodeQL → Nightly deep analysis (minutes)
```

**Comprehensive Pipeline:**
```
Semgrep (PR) → Pysa (merge) → CodeQL (release)
```

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

1. Choose primary tool based on needs
2. Set up basic CI/CD integration
3. Run initial scan and establish baseline
4. Configure severity thresholds

### Phase 2: Integration (Week 3-4)

1. Integrate into PR workflow
2. Set up blocking rules for critical issues
3. Create developer documentation
4. Train security champions

### Phase 3: Optimization (Week 5-8)

1. Tune rules to reduce false positives
2. Add custom rules for business logic
3. Implement baseline management
4. Set up metrics and reporting

### Phase 4: Scale (Ongoing)

1. Roll out to additional repositories
2. Centralize rule management
3. Implement governance framework
4. Continuous improvement

## Quick Start: GitHub Actions

### Semgrep

```yaml
name: Semgrep
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/python
```

### CodeQL

```yaml
name: CodeQL
on: [push, pull_request]
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: python
      - uses: github/codeql-action/analyze@v3
```

### Pysa

```yaml
name: Pysa
on: [push]
jobs:
  pysa:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - run: pip install pyre-check
      - run: |
          cd analysis/pysa
          pyre analyze --output-format sarif
```

## Success Metrics

Track these metrics to measure effectiveness:

| Metric | Target | Measurement |
|--------|--------|-------------|
| Detection Rate | >80% | Vulnerabilities found / Total vulnerabilities |
| False Positive Rate | <20% | False positives / Total findings |
| Time to Fix | <7 days | Average time from detection to remediation |
| Coverage | >90% | Repositories scanned / Total repositories |
| Developer Adoption | >80% | PRs with security analysis / Total PRs |

## Common Challenges

### Challenge 1: Too Many Findings

**Solution:**
- Start with critical/high severity only
- Establish baseline for existing issues
- Fix incrementally, focus on new code

### Challenge 2: Slow Analysis

**Solution:**
- Use Semgrep for PR checks
- Run CodeQL nightly or on releases
- Parallelize analysis where possible

### Challenge 3: Developer Resistance

**Solution:**
- Provide clear, actionable findings
- Reduce false positives aggressively
- Integrate into existing workflows
- Celebrate security champions

### Challenge 4: Custom Vulnerabilities

**Solution:**
- Write custom rules for business logic
- Collaborate with security team
- Share rules across organization

## Next Steps

Start with the [CI/CD Integration Guide](ci-cd.md) for detailed setup instructions.
