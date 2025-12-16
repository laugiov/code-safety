---
title: Advanced CodeQL Techniques
description: Advanced patterns, optimization, and enterprise deployment
---

# Advanced CodeQL Techniques

This guide covers advanced CodeQL patterns for complex vulnerability detection, performance optimization, and enterprise-scale deployment.

## Advanced Taint Tracking

### Multi-Stage Taint Tracking

Track taint through multiple transformation stages:

```ql
/**
 * Tracks taint through JSON parsing and object access.
 */
class JsonTaintConfig extends TaintTracking::Configuration {
  JsonTaintConfig() { this = "JsonTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // json.loads() result is tainted if input is tainted
    exists(Call call |
      call.getFunc().(Attribute).getName() = "loads" and
      call.getFunc().(Attribute).getObject().(Name).getId() = "json" and
      node1.asExpr() = call.getArg(0) and
      node2.asExpr() = call
    )
    or
    // Dictionary access preserves taint
    exists(Subscript sub |
      node1.asExpr() = sub.getObject() and
      node2.asExpr() = sub
    )
    or
    // Attribute access preserves taint
    exists(Attribute attr |
      node1.asExpr() = attr.getObject() and
      node2.asExpr() = attr
    )
  }
}
```

### Taint Through Containers

Track taint stored and retrieved from collections:

```ql
class ContainerTaintConfig extends TaintTracking::Configuration {
  ContainerTaintConfig() { this = "ContainerTaintConfig" }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // List append then iteration
    exists(Call append, For loop |
      append.getFunc().(Attribute).getName() = "append" and
      node1.asExpr() = append.getArg(0) and
      loop.getIter() = append.getFunc().(Attribute).getObject() and
      node2.asExpr() = loop.getTarget()
    )
    or
    // Dict storage then retrieval
    exists(Subscript store, Subscript retrieve |
      store.getCtx() instanceof Store and
      retrieve.getCtx() instanceof Load and
      store.getObject() = retrieve.getObject() and
      node1.asExpr() = store.getValue() and
      node2.asExpr() = retrieve
    )
  }
}
```

### Interprocedural Analysis

Track taint across function boundaries:

```ql
class InterproceduralConfig extends TaintTracking::Configuration {
  InterproceduralConfig() { this = "InterproceduralConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof SqlSink
  }

  // Track through function parameters and returns
  override int fieldFlowBranchLimit() {
    result = 100  // Increase for deeper analysis
  }

  // Track through class instances
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    exists(FunctionDef f, Return ret |
      node1.asExpr() = f.getArg(_) and
      ret.getScope() = f and
      node2.asExpr() = ret.getValue()
    )
  }
}
```

## Advanced Query Patterns

### Finding Stored XSS

Two-stage query: first tracks to database storage, then from database to output:

```ql
/**
 * @name Stored XSS
 * @kind path-problem
 */
import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

// Stage 1: User input to database storage
class StorageConfig extends TaintTracking::Configuration {
  StorageConfig() { this = "StorageConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Attribute).getName() = "save" and
      sink.asExpr() = call.getFunc().(Attribute).getObject()
    )
  }
}

// Stage 2: Database read to HTML output
class OutputConfig extends TaintTracking::Configuration {
  OutputConfig() { this = "OutputConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call call |
      call.getFunc().(Attribute).getName() in ["filter", "get", "all"] and
      source.asExpr() = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Name).getId() = "HttpResponse" and
      sink.asExpr() = call.getArg(0)
    )
  }
}

from StorageConfig storage, OutputConfig output,
     DataFlow::PathNode storageSource, DataFlow::PathNode storageSink,
     DataFlow::PathNode outputSource, DataFlow::PathNode outputSink
where storage.hasFlowPath(storageSource, storageSink) and
      output.hasFlowPath(outputSource, outputSink)
select outputSink.getNode(), storageSource, outputSink,
  "Stored XSS: user input at $@ stored and output at $@.",
  storageSource.getNode(), "source",
  outputSink.getNode(), "sink"
```

### Finding IDOR Vulnerabilities

```ql
/**
 * @name Insecure Direct Object Reference
 * @kind path-problem
 */
import python
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

class IdorConfig extends TaintTracking::Configuration {
  IdorConfig() { this = "IdorConfig" }

  override predicate isSource(DataFlow::Node source) {
    exists(Call call |
      // URL path parameters
      call.getFunc().(Attribute).getName() = "get" and
      call.getFunc().(Attribute).getObject().(Name).getId() = "kwargs" and
      source.asExpr() = call
    )
    or
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      // Direct database lookup without authorization
      call.getFunc().(Attribute).getName() in ["get", "filter"] and
      call.getFunc().(Attribute).getObject().(Attribute).getName() = "objects" and
      // Check if lookup uses user-provided ID
      exists(Keyword kw |
        kw = call.getAKeyword() and
        kw.getArg().matches("%id%") and
        sink.asExpr() = kw.getValue()
      )
    )
  }

  // Don't flag if authorization check exists
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call call |
      call.getFunc().(Attribute).getName() in [
        "has_perm", "check_object_permissions", "get_object_or_404"
      ]
    )
  }
}

from IdorConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Database lookup with user-controlled ID from $@ without authorization check.",
  source.getNode(), "user input"
```

### Finding Mass Assignment

```ql
/**
 * @name Mass Assignment vulnerability
 * @kind problem
 */
import python

from Call call, Dict dict
where
  // Model.objects.create(**request.POST)
  call.getFunc().(Attribute).getName() = "create" and
  call.getFunc().(Attribute).getObject().(Attribute).getName() = "objects" and
  exists(Keyword kw |
    kw = call.getAKeyword() and
    kw.getValue() instanceof Starred
  )
select call, "Potential mass assignment: model created with unpacked user input"
```

## Query Optimization

### Predicate Optimization

```ql
// BAD: Computes cross product
from Function f, Call c
where f.getAStmt() = c.getAnEnclosingStmt()
select f, c

// GOOD: Use specific relationships
from Function f, Call c
where c.getScope() = f
select f, c
```

### Caching with Predicates

```ql
// Define predicate to cache results
predicate isDangerousSink(DataFlow::Node sink) {
  sink instanceof SqlSink
  or sink instanceof CommandSink
  or sink instanceof XssSink
}

// Use cached predicate
class MultiSinkConfig extends TaintTracking::Configuration {
  override predicate isSink(DataFlow::Node sink) {
    isDangerousSink(sink)
  }
}
```

### Limiting Result Size

```ql
from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection"
// Limit to first 100 results per file
limit 100
```

### Using Recursive Predicates Efficiently

```ql
// Efficient recursive predicate with base case
predicate reaches(DataFlow::Node start, DataFlow::Node end) {
  start = end
  or
  exists(DataFlow::Node mid |
    step(start, mid) and
    reaches(mid, end)
  )
}

// Add depth limit for performance
predicate reachesWithLimit(DataFlow::Node start, DataFlow::Node end, int depth) {
  depth = 0 and start = end
  or
  depth > 0 and
  exists(DataFlow::Node mid |
    step(start, mid) and
    reachesWithLimit(mid, end, depth - 1)
  )
}
```

## Custom Libraries

### Django Security Library

```ql
// libraries/DjangoSecurity.qll

import python
import semmle.python.dataflow.new.DataFlow

/**
 * Comprehensive Django security sources and sinks.
 */
module DjangoSecurity {

  /** A source of untrusted data from Django requests. */
  class DjangoSource extends DataFlow::Node {
    string sourceType;

    DjangoSource() {
      // GET parameters
      this = djangoGetSource() and sourceType = "GET parameter"
      or
      // POST parameters
      this = djangoPostSource() and sourceType = "POST parameter"
      or
      // Request body
      this = djangoBodySource() and sourceType = "request body"
      or
      // Headers
      this = djangoHeaderSource() and sourceType = "HTTP header"
      or
      // Cookies
      this = djangoCookieSource() and sourceType = "cookie"
      or
      // File uploads
      this = djangoFileSource() and sourceType = "uploaded file"
    }

    string getSourceType() { result = sourceType }
  }

  private DataFlow::Node djangoGetSource() {
    exists(Call call |
      call.getFunc().(Attribute).getName() in ["get", "__getitem__"] and
      call.getFunc().(Attribute).getObject().(Attribute).getName() = "GET" and
      result.asExpr() = call
    )
  }

  private DataFlow::Node djangoPostSource() {
    exists(Call call |
      call.getFunc().(Attribute).getName() in ["get", "__getitem__"] and
      call.getFunc().(Attribute).getObject().(Attribute).getName() = "POST" and
      result.asExpr() = call
    )
  }

  private DataFlow::Node djangoBodySource() {
    exists(Attribute attr |
      attr.getName() = "body" and
      attr.getObject().(Name).getId() = "request" and
      result.asExpr() = attr
    )
  }

  private DataFlow::Node djangoHeaderSource() {
    exists(Subscript sub |
      sub.getObject().(Attribute).getName() = "META" and
      result.asExpr() = sub
    )
  }

  private DataFlow::Node djangoCookieSource() {
    exists(Call call |
      call.getFunc().(Attribute).getName() in ["get", "__getitem__"] and
      call.getFunc().(Attribute).getObject().(Attribute).getName() = "COOKIES" and
      result.asExpr() = call
    )
  }

  private DataFlow::Node djangoFileSource() {
    exists(Subscript sub |
      sub.getObject().(Attribute).getName() = "FILES" and
      result.asExpr() = sub
    )
  }

  /** SQL execution sinks in Django. */
  class DjangoSqlSink extends DataFlow::Node {
    DjangoSqlSink() {
      exists(Call call |
        (
          // Raw cursor execution
          call.getFunc().(Attribute).getName() = "execute" and
          this.asExpr() = call.getArg(0)
        )
        or
        (
          // QuerySet.raw()
          call.getFunc().(Attribute).getName() = "raw" and
          this.asExpr() = call.getArg(0)
        )
        or
        (
          // QuerySet.extra()
          call.getFunc().(Attribute).getName() = "extra" and
          this.asExpr() = call.getAKeyword().getValue()
        )
      )
    }
  }
}
```

### Using Custom Library

```ql
import python
import semmle.python.dataflow.new.TaintTracking
import DjangoSecurity
import DataFlow::PathGraph

class DjangoSqlInjection extends TaintTracking::Configuration {
  DjangoSqlInjection() { this = "DjangoSqlInjection" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DjangoSecurity::DjangoSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof DjangoSecurity::DjangoSqlSink
  }
}

from DjangoSqlInjection config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection from " + source.getNode().(DjangoSecurity::DjangoSource).getSourceType()
```

## Enterprise Deployment

### Centralized Query Management

```
codeql-queries/
├── qlpack.yml              # Query pack definition
├── queries/
│   ├── python/
│   │   ├── security/
│   │   │   ├── SqlInjection.ql
│   │   │   ├── CommandInjection.ql
│   │   │   └── ...
│   │   └── quality/
│   └── javascript/
├── libraries/
│   ├── python/
│   │   ├── DjangoSecurity.qll
│   │   └── FlaskSecurity.qll
│   └── shared/
└── suites/
    ├── security-critical.qls
    ├── security-extended.qls
    └── code-quality.qls
```

### Query Pack Configuration

```yaml
# qlpack.yml
name: company/security-queries
version: 1.0.0
groups:
  - python
  - security
dependencies:
  codeql/python-all: "*"
  codeql/python-queries: "*"
extractor: python
library: false
```

### GitHub Advanced Security Integration

```yaml
# .github/codeql/codeql-config.yml
name: "Custom CodeQL Configuration"

queries:
  - uses: security-and-quality
  - uses: ./analysis/codeql/queries

paths-ignore:
  - "**/test/**"
  - "**/tests/**"
  - "**/vendor/**"

query-filters:
  - exclude:
      problem.severity: recommendation
  - include:
      tags contain: security
```

### Baseline Management

```python
#!/usr/bin/env python3
"""Manage CodeQL baselines."""

import json
from pathlib import Path

def create_baseline(sarif_file: Path, baseline_file: Path):
    """Create baseline from SARIF results."""
    with open(sarif_file) as f:
        sarif = json.load(f)

    baseline = []
    for run in sarif.get('runs', []):
        for result in run.get('results', []):
            baseline.append({
                'ruleId': result['ruleId'],
                'fingerprints': result.get('fingerprints', {}),
                'message': result['message']['text'][:100]
            })

    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=2)

def filter_new_issues(sarif_file: Path, baseline_file: Path) -> list:
    """Return only issues not in baseline."""
    with open(sarif_file) as f:
        sarif = json.load(f)
    with open(baseline_file) as f:
        baseline = json.load(f)

    baseline_fingerprints = {
        b['fingerprints'].get('primaryLocationLineHash')
        for b in baseline
    }

    new_issues = []
    for run in sarif.get('runs', []):
        for result in run.get('results', []):
            fp = result.get('fingerprints', {}).get('primaryLocationLineHash')
            if fp not in baseline_fingerprints:
                new_issues.append(result)

    return new_issues
```

## Performance Monitoring

### Query Execution Stats

```bash
# Run with performance logging
codeql database analyze vulnshop-db \
  --format=sarif-latest \
  --output=results.sarif \
  --evaluator-log=eval.log \
  queries/sql-injection.ql

# Analyze performance
codeql generate log-summary eval.log
```

### Memory Profiling

```bash
# Set memory limit
codeql database analyze vulnshop-db \
  --ram=8192 \
  --threads=4 \
  queries/

# Monitor memory usage
codeql database analyze vulnshop-db \
  --evaluator-log=perf.log \
  --log-to-stderr \
  queries/
```

## Next Steps

- [Writing Queries](queries.md) - Query fundamentals
- [Database Creation](database.md) - Database management
- [CodeQL Overview](index.md) - Return to main guide
