---
title: Benchmark Methodology
description: How we measure and compare taint analysis tools
---

# Benchmark Methodology

Our methodology for fair and reproducible tool comparison.

## Metrics

### Detection Metrics

| Metric | Formula | Description |
|--------|---------|-------------|
| **True Positives (TP)** | Correctly identified vulnerabilities | |
| **False Positives (FP)** | Incorrect alerts | |
| **False Negatives (FN)** | Missed vulnerabilities | |
| **Precision** | TP / (TP + FP) | How many findings are real |
| **Recall** | TP / (TP + FN) | How many vulns are found |
| **F1 Score** | 2 × (P × R) / (P + R) | Balanced metric |

### Performance Metrics

| Metric | Description |
|--------|-------------|
| **Execution Time** | Total analysis duration |
| **Memory Usage** | Peak memory consumption |
| **CPU Usage** | Average CPU utilization |

## Ground Truth

### VulnShop Vulnerabilities

Each vulnerability is documented with:

```yaml
- id: "VULN-001"
  name: "SQL Injection in Login"
  type: "sql-injection"
  cwe: "CWE-89"
  location:
    file: "authentication/views.py"
    line: 25
    function: "login_view"
  source: "request.POST['username']"
  sink: "cursor.execute(query)"
  exploitable: true
```

### Verification Process

1. Manual code review by security expert
2. Exploit development and testing
3. Cross-validation with multiple tools
4. Documentation in ground-truth files

## Test Protocol

### Environment

```yaml
environment:
  os: Ubuntu 22.04 LTS
  python: 3.10.12
  ram: 16GB
  cpu: 8 cores
```

### Execution

```bash
# Clean environment for each run
./scripts/clean_environment.sh

# Run each tool 3 times
for i in {1..3}; do
  time ./scripts/run_tool.sh semgrep
  time ./scripts/run_tool.sh pysa
  time ./scripts/run_tool.sh codeql
done

# Record median results
```

### Result Collection

```python
results = {
    "tool": "semgrep",
    "findings": [...],
    "execution_time_seconds": 4.2,
    "memory_peak_mb": 512,
    "timestamp": "2024-01-15T10:30:00Z"
}
```

## Scoring

### Detection Score

```python
def calculate_score(tool_results, ground_truth):
    tp = len(set(tool_results) & set(ground_truth))
    fp = len(set(tool_results) - set(ground_truth))
    fn = len(set(ground_truth) - set(tool_results))

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {"precision": precision, "recall": recall, "f1": f1}
```

### Composite Score

```python
COMPOSITE_SCORE = (
    0.4 * recall +           # Finding vulnerabilities is most important
    0.3 * precision +        # Reducing noise matters
    0.2 * (1 - normalized_time) +  # Speed bonus
    0.1 * ease_of_use        # Usability factor
)
```

## Limitations

1. **VulnShop-specific** - Results may not generalize to all codebases
2. **Python-focused** - Only tests Python support
3. **Configuration-dependent** - Results vary with rule configurations
4. **Point-in-time** - Tool capabilities evolve

## Reproducibility

All benchmark data and scripts are available:

```
benchmarks/
├── ground-truth/
│   └── vulnerabilities.json
├── scripts/
│   ├── run_benchmarks.py
│   └── generate_report.py
└── results/
    ├── pysa/
    ├── codeql/
    └── semgrep/
```

Run benchmarks yourself:

```bash
cd benchmarks
python scripts/run_benchmarks.py --tools all --output results/
```
