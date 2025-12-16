---
marp: true
theme: default
paginate: true
backgroundColor: #fff
style: |
  section {
    font-family: 'Segoe UI', Arial, sans-serif;
  }
  h1 { color: #4051B5; }
  h2 { color: #333; }
  .tool-pysa { color: #1877f2; }
  .tool-codeql { color: #333; }
  .tool-semgrep { color: #4b11a8; }
---

# Tool Deep Dive

## Pysa, CodeQL, and Semgrep Compared

---

# Part 1: Pysa

## Meta's Python Static Analyzer

---

# Pysa Architecture

```
┌─────────────────────────────────────────────┐
│                 Pyre Type Checker           │
├─────────────────────────────────────────────┤
│                 Pysa Analyzer               │
├─────────────────────────────────────────────┤
│  .pysa models  │  taint.config  │  stubs    │
└─────────────────────────────────────────────┘
```

Built on Pyre's type information for precision.

---

# Defining Sources (Pysa)

```python
# models/django_sources.pysa

def django.http.request.HttpRequest.GET.__getitem__(
    self,
    key: str
) -> TaintSource[UserControlled]: ...

def django.http.request.HttpRequest.POST.get(
    self,
    key: str,
    default = ...
) -> TaintSource[UserControlled]: ...
```

---

# Defining Sinks (Pysa)

```python
# models/django_sinks.pysa

def django.db.backends.utils.CursorWrapper.execute(
    self,
    sql: TaintSink[SQL],
    params = ...
): ...

def os.system(
    command: TaintSink[RemoteCodeExecution]
): ...
```

---

# Defining Rules (Pysa)

```json
{
  "name": "SQL Injection",
  "code": 5001,
  "sources": ["UserControlled"],
  "sinks": ["SQL"],
  "message_format": "User data flows to SQL query"
}
```

---

# Pysa Output

```json
{
  "code": 5001,
  "message": "User-controlled data flows to SQL query",
  "filename": "authentication/views.py",
  "line": 32,
  "traces": [
    {"name": "forward", "roots": [...]},
    {"name": "backward", "roots": [...]}
  ]
}
```

---

# Part 2: CodeQL

## GitHub's Semantic Analysis Engine

---

# CodeQL Architecture

```
┌─────────────────────────────────────────────┐
│            Source Code                      │
├─────────────────────────────────────────────┤
│         CodeQL Database                     │
│  (AST + Types + Control Flow + Data Flow)   │
├─────────────────────────────────────────────┤
│            QL Queries                       │
└─────────────────────────────────────────────┘
```

Code becomes a queryable database.

---

# CodeQL Query Structure

```sql
/**
 * @name SQL Injection
 * @kind path-problem
 */
import python
import semmle.python.dataflow.new.TaintTracking

class SqlInjectionConfig extends TaintTracking::Configuration {
  // Define sources, sinks, sanitizers
}

from SqlInjectionConfig c, DataFlow::PathNode src, sink
where c.hasFlowPath(src, sink)
select sink, src, sink, "SQL injection"
```

---

# CodeQL Sources

```sql
override predicate isSource(DataFlow::Node source) {
  // Any remote flow source
  source instanceof RemoteFlowSource
  or
  // Custom Django source
  exists(Call call |
    call.getFunc().(Attribute).getName() = "__getitem__" and
    call.getFunc().(Attribute).getObject().(Attribute).getName() = "GET"
  ) and source.asExpr() = call
}
```

---

# CodeQL Sinks

```sql
override predicate isSink(DataFlow::Node sink) {
  exists(Call call |
    call.getFunc().(Attribute).getName() = "execute" and
    sink.asExpr() = call.getArg(0)
  )
}
```

---

# CodeQL Sanitizers

```sql
override predicate isSanitizer(DataFlow::Node node) {
  // int() conversion sanitizes SQL injection
  exists(Call call |
    call.getFunc().(Name).getId() = "int" and
    node.asExpr() = call
  )
  or
  // Parameterized query
  exists(Call call |
    call.getFunc().(Attribute).getName() = "execute" and
    call.getArg(1).isPresent()
  )
}
```

---

# Part 3: Semgrep

## Fast Pattern Matching

---

# Semgrep Rule Structure

```yaml
rules:
  - id: sql-injection
    message: SQL injection vulnerability
    severity: ERROR
    languages: [python]
    pattern: cursor.execute(f"...{$INPUT}...")
```

Simple YAML-based rules.

---

# Semgrep Pattern Operators

| Operator | Purpose |
|----------|---------|
| `pattern` | Match exact code |
| `pattern-either` | Match any of multiple |
| `pattern-not` | Exclude patterns |
| `pattern-inside` | Match within context |
| `patterns` | Combine clauses |

---

# Semgrep Metavariables

```yaml
# $X matches any expression
pattern: cursor.execute($QUERY)

# Named metavariables for messages
message: "Query $QUERY may be vulnerable"
```

---

# Semgrep Taint Mode

```yaml
rules:
  - id: sql-injection-taint
    mode: taint
    pattern-sources:
      - pattern: request.GET[...]
    pattern-sinks:
      - pattern: cursor.execute($Q)
        focus-metavariable: $Q
    pattern-sanitizers:
      - pattern: int(...)
```

---

# Comparison: Configuration

| Aspect | Pysa | CodeQL | Semgrep |
|--------|------|--------|---------|
| Language | `.pysa` files | QL | YAML |
| Learning | Medium | High | Low |
| Flexibility | High | Highest | Medium |
| Maintainability | Medium | Low | High |

---

# Comparison: Analysis

| Aspect | Pysa | CodeQL | Semgrep |
|--------|------|--------|---------|
| Inter-procedural | ✅ Deep | ✅ Deep | ⚠️ Limited |
| Type-aware | ✅ Yes | ✅ Yes | ❌ No |
| Custom sinks | ✅ Easy | ✅ Complex | ✅ Easy |
| Speed | Medium | Slow | Fast |

---

# When to Use Each

## Pysa
- Python-only projects
- Complex taint flows
- Type-aware analysis needed

## CodeQL
- Multi-language projects
- Deep semantic analysis
- Research/custom queries

## Semgrep
- CI/CD integration
- Quick feedback loops
- Simple patterns

---

# Combined Approach

```bash
# PR check (5 seconds)
semgrep --config rules/ --severity ERROR

# Main branch (1 minute)
pyre analyze

# Nightly (5 minutes)
codeql database analyze
```

---

# Questions?
