---
title: Advanced Pysa Techniques
description: Advanced patterns, optimization, and complex taint analysis
---

# Advanced Pysa Techniques

This guide covers advanced patterns for complex taint analysis scenarios, performance optimization, and enterprise-scale deployment.

## Complex Taint Patterns

### Multi-Hop Taint Tracking

Track taint through multiple function calls:

```python
# Code pattern
def get_user_input(request):
    return request.GET["data"]

def process_data(data):
    return data.upper()

def build_query(processed):
    return f"SELECT * FROM users WHERE name = '{processed}'"

def execute(request):
    data = get_user_input(request)     # Source
    processed = process_data(data)      # Propagation
    query = build_query(processed)      # Propagation
    cursor.execute(query)               # Sink
```

Pysa tracks this automatically with proper models:

```python
# models/propagation.pysa
def str.upper(
    self: TaintInTaintOut[LocalReturn]
) -> str: ...
```

### Taint Through Collections

Track taint through lists, dicts, and sets:

```python
# models/collections.pysa

# List operations
def list.__init__(
    self,
    iterable: TaintInTaintOut[LocalReturn] = ...
): ...

def list.append(
    self: TaintInTaintOut[LocalReturn],
    object: TaintInTaintOut[LocalReturn]
): ...

def list.__getitem__(
    self: TaintInTaintOut[LocalReturn],
    key
): ...

# Dict operations
def dict.__setitem__(
    self: TaintInTaintOut[LocalReturn],
    key,
    value: TaintInTaintOut[LocalReturn]
): ...

def dict.__getitem__(
    self: TaintInTaintOut[LocalReturn],
    key
): ...

def dict.get(
    self: TaintInTaintOut[LocalReturn],
    key,
    default: TaintInTaintOut[LocalReturn] = ...
): ...

def dict.values(
    self: TaintInTaintOut[LocalReturn]
): ...
```

### Class Attribute Taint

Handle taint on object attributes:

```python
# Code pattern
class UserData:
    def __init__(self, request):
        self.name = request.GET["name"]  # Tainted
        self.id = request.GET["id"]      # Tainted

def vulnerable(request):
    user = UserData(request)
    cursor.execute(f"SELECT * FROM users WHERE name = '{user.name}'")
```

Model with attribute propagation:

```python
# models/attributes.pysa
def object.__getattribute__(
    self: TaintInTaintOut[LocalReturn],
    name: str
): ...

def object.__setattr__(
    self: TaintInTaintOut[LocalReturn],
    name: str,
    value: TaintInTaintOut[LocalReturn]
): ...
```

### Generic Type Propagation

```python
# models/generics.pysa

# Optional unwrapping
def typing.Optional.__getitem__(
    cls,
    item: TaintInTaintOut[LocalReturn]
): ...

# Type casting
def typing.cast(
    typ,
    val: TaintInTaintOut[LocalReturn]
): ...
```

## Custom Taint Kinds

### Defining Specialized Sources

```json
// taint.config
{
  "sources": [
    {"name": "UserControlled", "comment": "General user input"},
    {"name": "AdminInput", "comment": "Admin-only input"},
    {"name": "APIKey", "comment": "API keys and secrets"},
    {"name": "PII", "comment": "Personally identifiable information"},
    {"name": "DatabasePassword", "comment": "Database credentials"},
    {"name": "SessionToken", "comment": "Session identifiers"}
  ]
}
```

### Multi-Source Rules

```json
{
  "rules": [
    {
      "name": "Credential Exposure",
      "code": 5100,
      "sources": ["APIKey", "DatabasePassword"],
      "sinks": ["Logging", "HTTPResponse"],
      "message_format": "Credentials flowing to {$sinks}"
    },
    {
      "name": "PII Leak",
      "code": 5101,
      "sources": ["PII"],
      "sinks": ["Logging", "ThirdPartyAPI"],
      "message_format": "PII data flowing to {$sinks}"
    }
  ]
}
```

### Transforms

Transform taint kinds through operations:

```json
{
  "transforms": [
    {
      "name": "Encrypted",
      "comment": "Data that has been encrypted"
    }
  ],
  "rules": [
    {
      "name": "Unencrypted PII Storage",
      "code": 5102,
      "sources": ["PII"],
      "transforms": [],
      "sinks": ["DatabaseWrite"],
      "message_format": "Unencrypted PII written to database"
    }
  ]
}
```

Apply transforms in models:

```python
# models/crypto.pysa
def cryptography.fernet.Fernet.encrypt(
    self,
    data: ApplyTransform[Encrypted]
) -> bytes: ...
```

## Sanitizer Patterns

### Conditional Sanitizers

Sanitize only for specific sinks:

```python
# models/sanitizers.pysa

# Only sanitizes for XSS, not SQL
def django.utils.html.escape(
    text: Sanitize[TaintSink[XSS]]
) -> str: ...

# Only sanitizes for path traversal
def os.path.basename(
    p: Sanitize[TaintSink[FileSystem]]
) -> str: ...

# Only sanitizes for command injection
def shlex.quote(
    s: Sanitize[TaintSink[RemoteCodeExecution]]
) -> str: ...
```

### Partial Sanitizers

Mark functions that reduce but don't eliminate risk:

```python
# models/partial_sanitizers.pysa

# Partial - still allows some attacks
def custom_filter(
    data: PartialSanitize[TaintSink[XSS]]
) -> str: ...
```

### Validation Sanitizers

```python
# models/validation.pysa

# UUID validation eliminates arbitrary string injection
def uuid.UUID.__init__(
    self,
    hex: Sanitize[TaintSink[SQL, FileSystem]]
): ...

# Integer conversion removes string injection
def builtins.int(
    __x: Sanitize[TaintSink[SQL, RemoteCodeExecution, FileSystem]]
): ...

# Regex match validation
def re.fullmatch(
    pattern: str,
    string: Sanitize[TaintSink[SQL]]
) -> typing.Optional[re.Match]: ...
```

## Model Generators

Auto-generate models for large codebases:

```python
#!/usr/bin/env python3
"""Generate Pysa models for Django views."""

import ast
import sys
from pathlib import Path

def generate_view_models(app_path: Path) -> str:
    models = []

    for py_file in app_path.rglob("views.py"):
        with open(py_file) as f:
            tree = ast.parse(f.read())

        module = str(py_file.relative_to(app_path)).replace("/", ".").replace(".py", "")

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if first param is 'request'
                if node.args.args and node.args.args[0].arg == "request":
                    models.append(f"""
# Auto-generated model for {module}.{node.name}
def {module}.{node.name}(
    request: TaintSource[UserControlled],
    *args,
    **kwargs
): ...""")

    return "\n".join(models)

if __name__ == "__main__":
    app_path = Path(sys.argv[1])
    print(generate_view_models(app_path))
```

Run generator:

```bash
python model_generators/generate_django_models.py ../../vulnerable-app > models/generated.pysa
```

## Performance Optimization

### Excluding Irrelevant Code

```json
// .pyre_configuration
{
  "exclude": [
    ".*/migrations/.*",
    ".*/tests/.*",
    ".*/fixtures/.*",
    ".*/static/.*",
    ".*/node_modules/.*",
    ".*_test\\.py$",
    ".*conftest\\.py$"
  ]
}
```

### Limiting Trace Depth

```bash
# Reduce trace depth for faster analysis
pyre analyze --maximum-trace-length 10
```

### Parallelization

```json
// .pyre_configuration
{
  "number_of_workers": 16,
  "parallel": true
}
```

### Incremental Analysis

```bash
# Start Pyre server for incremental updates
pyre start

# Run incremental analysis
pyre incremental

# Analyze changes only
pyre analyze --incremental
```

### Memory Optimization

```json
// .pyre_configuration
{
  "shared_memory": {
    "heap_size": 17179869184,
    "dependency_table_power": 28,
    "hash_table_power": 26
  }
}
```

## Framework-Specific Patterns

### Django REST Framework

```python
# models/drf_sources.pysa

# Serializer validated data
def rest_framework.serializers.Serializer.validated_data.fget(
    self
) -> TaintSource[UserControlled]: ...

# Request data
def rest_framework.request.Request.data.fget(
    self
) -> TaintSource[UserControlled]: ...

def rest_framework.request.Request.query_params.fget(
    self
) -> TaintSource[UserControlled]: ...
```

### Celery Tasks

```python
# models/celery.pysa

# Task arguments can be tainted
def celery.app.task.Task.apply_async(
    self,
    args: TaintInTaintOut[LocalReturn] = ...,
    kwargs: TaintInTaintOut[LocalReturn] = ...
): ...

# Results from tasks
def celery.result.AsyncResult.get(
    self
) -> TaintSource[DatabaseRead]: ...
```

### SQLAlchemy

```python
# models/sqlalchemy.pysa

# Raw SQL execution
def sqlalchemy.engine.Connection.execute(
    self,
    statement: TaintSink[SQL],
    parameters = ...
): ...

def sqlalchemy.orm.Session.execute(
    self,
    statement: TaintSink[SQL],
    params = ...
): ...

# Text queries
def sqlalchemy.text(
    text: TaintSink[SQL]
): ...
```

## Debugging Complex Issues

### Trace Visualization

```python
#!/usr/bin/env python3
"""Visualize Pysa taint traces."""

import json
import sys

def visualize_trace(issue):
    data = issue['data']
    print(f"\n{'='*60}")
    print(f"Issue: {data['message']}")
    print(f"File: {data['filename']}:{data['line']}")
    print(f"Function: {data['callable']}")
    print(f"{'='*60}")

    for trace in data.get('traces', []):
        direction = trace['name']
        print(f"\n{direction.upper()} TRACE:")

        for i, root in enumerate(trace.get('roots', [])):
            if 'call' in root:
                call = root['call']
                pos = call['position']
                print(f"  {i+1}. Line {pos['line']}: {call['resolves_to']}")
                if 'leaves' in root:
                    kinds = [l['kind'] for l in root['leaves']]
                    print(f"      Taint kinds: {kinds}")

with open(sys.argv[1]) as f:
    results = json.load(f)
    for issue in results[:10]:  # First 10 issues
        visualize_trace(issue)
```

### Call Graph Analysis

```bash
# Generate call graph
pyre analyze --dump-call-graph > call_graph.json

# Find paths between functions
python scripts/analyze_call_graph.py call_graph.json \
  --from "get_user_input" \
  --to "execute_query"
```

### Model Verification

```bash
# Verify all models are valid
pyre analyze --verify-models

# Check specific model file
pyre analyze --verify-models --taint-models-path models/django_sources.pysa
```

## Integration with Other Tools

### Combining with Semgrep

Use Semgrep for pattern matching, Pysa for dataflow:

```yaml
# .github/workflows/security.yml
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: semgrep/semgrep-action@v1
        with:
          config: analysis/semgrep/rules/

  pysa:
    runs-on: ubuntu-latest
    steps:
      - name: Run Pysa
        run: |
          pip install pyre-check
          cd analysis/pysa
          pyre analyze --output-format sarif

  combine-results:
    needs: [semgrep, pysa]
    runs-on: ubuntu-latest
    steps:
      - name: Merge SARIF files
        run: |
          python scripts/merge_sarif.py \
            semgrep-results.sarif \
            pysa-results.sarif \
            --output combined.sarif
```

### SARIF Post-Processing

```python
#!/usr/bin/env python3
"""Post-process SARIF for better integration."""

import json

def enrich_sarif(sarif_file, output_file):
    with open(sarif_file) as f:
        sarif = json.load(f)

    for run in sarif.get('runs', []):
        for result in run.get('results', []):
            # Add severity mapping
            rule_id = result.get('ruleId', '')
            if 'SQL' in rule_id or 'RCE' in rule_id:
                result['level'] = 'error'
            elif 'XSS' in rule_id or 'SSRF' in rule_id:
                result['level'] = 'warning'
            else:
                result['level'] = 'note'

            # Add CWE mapping
            if 'SQL' in rule_id:
                result['taxa'] = [{'id': 'CWE-89'}]
            elif 'Command' in rule_id:
                result['taxa'] = [{'id': 'CWE-78'}]

    with open(output_file, 'w') as f:
        json.dump(sarif, f, indent=2)
```

## Enterprise Deployment

### Centralized Configuration

```
security-analysis/
├── pysa/
│   ├── base-config/
│   │   ├── .pyre_configuration.base
│   │   └── taint.config
│   ├── models/
│   │   ├── common/
│   │   ├── django/
│   │   ├── flask/
│   │   └── fastapi/
│   └── scripts/
│       └── run_analysis.sh
└── project-configs/
    ├── service-a/
    │   └── .pyre_configuration
    └── service-b/
        └── .pyre_configuration
```

### Baseline Management

```python
#!/usr/bin/env python3
"""Manage Pysa baselines."""

import json
from pathlib import Path

def create_baseline(results_file, baseline_file):
    """Create baseline from current results."""
    with open(results_file) as f:
        results = json.load(f)

    baseline = []
    for issue in results:
        data = issue['data']
        baseline.append({
            'file': data['filename'],
            'line': data['line'],
            'code': data['code'],
            'callable': data['callable']
        })

    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=2)

def filter_baseline(results_file, baseline_file, output_file):
    """Remove baselined issues from results."""
    with open(results_file) as f:
        results = json.load(f)
    with open(baseline_file) as f:
        baseline = json.load(f)

    baseline_set = {
        (b['file'], b['code'], b['callable'])
        for b in baseline
    }

    new_issues = [
        r for r in results
        if (r['data']['filename'], r['data']['code'], r['data']['callable'])
        not in baseline_set
    ]

    with open(output_file, 'w') as f:
        json.dump(new_issues, f, indent=2)

    return len(results) - len(new_issues)
```

## Next Steps

- [Configuration](configuration.md) - Complete configuration reference
- [Writing Models](models.md) - Model creation guide
- [Running Pysa](running.md) - Execution and results
