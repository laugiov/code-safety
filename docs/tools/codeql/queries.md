---
title: Writing CodeQL Queries
description: Learn to write custom QL queries for security analysis
---

# Writing CodeQL Queries

CodeQL uses a powerful, declarative query language called QL. This guide teaches you to write custom queries for detecting security vulnerabilities.

## QL Fundamentals

### Query Structure

Every CodeQL query follows this structure:

```ql
/**
 * @name Query Name
 * @description What this query finds
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id py/custom-query-id
 * @tags security
 */

import python

from /* variable declarations */
where /* conditions */
select /* what to report */
```

### Metadata Annotations

| Annotation | Purpose | Values |
|------------|---------|--------|
| `@name` | Human-readable name | Any string |
| `@kind` | Query type | `problem`, `path-problem` |
| `@problem.severity` | Issue severity | `error`, `warning`, `recommendation` |
| `@security-severity` | CVSS-like score | 0.0 - 10.0 |
| `@precision` | False positive rate | `low`, `medium`, `high`, `very-high` |
| `@id` | Unique identifier | `language/category/name` |
| `@tags` | Categories | `security`, `correctness`, etc. |

## Basic Queries

### Finding Function Calls

```ql
/**
 * @name Find eval calls
 * @kind problem
 */
import python

from Call call, Name name
where call.getFunc() = name and
      name.getId() = "eval"
select call, "Dangerous eval() call"
```

### Finding String Patterns

```ql
/**
 * @name Hardcoded passwords
 * @kind problem
 */
import python

from StrConst s
where s.getText().regexpMatch("(?i).*(password|passwd|pwd).*=.*")
select s, "Possible hardcoded password"
```

### Finding Class Methods

```ql
/**
 * @name Find Django views
 * @kind problem
 */
import python

from Function f
where f.getName().matches("%_view") or
      f.getArgByName(0).getName() = "request"
select f, "Django view function"
```

## Understanding the AST

### Python AST Hierarchy

```
Module
├── Import
├── ImportFrom
├── FunctionDef
│   ├── arguments
│   ├── Return
│   └── Expr
│       └── Call
│           ├── Name (function)
│           └── Args
├── ClassDef
│   └── FunctionDef (methods)
└── Assign
    ├── Name (target)
    └── Value (expression)
```

### Navigating the AST

```ql
import python

// Get function name
from Function f
select f.getName()

// Get function arguments
from Function f, Name arg
where arg = f.getArg(_)
select f, arg.getId()

// Get function body statements
from Function f, Stmt s
where s = f.getAStmt()
select f, s

// Get call arguments
from Call c, Expr arg
where arg = c.getArg(_)
select c, arg
```

## Taint Tracking Queries

### Basic Taint Configuration

```ql
/**
 * @name SQL Injection
 * @kind path-problem
 */
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Attribute).getName() = "execute" and
      sink.asExpr() = call.getArg(0)
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "SQL injection from $@.", source.getNode(), "user input"
```

### Custom Sources

```ql
import python
import semmle.python.dataflow.new.DataFlow

class DjangoRequestSource extends DataFlow::Node {
  DjangoRequestSource() {
    exists(Call call, Attribute attr |
      // request.GET["key"] or request.POST["key"]
      call.getFunc() = attr and
      attr.getName() = "__getitem__" and
      attr.getObject().(Attribute).getName() in ["GET", "POST", "COOKIES"]
    ) and
    this.asExpr() = call
  }
}

class CustomFlaskSource extends DataFlow::Node {
  CustomFlaskSource() {
    exists(Call call |
      // flask.request.form["key"]
      call.getFunc().(Attribute).getName() = "get" and
      call.getFunc().(Attribute).getObject().(Attribute).getName() = "form"
    ) and
    this.asExpr() = call
  }
}
```

### Custom Sinks

```ql
import python
import semmle.python.dataflow.new.DataFlow

class RawSqlSink extends DataFlow::Node {
  RawSqlSink() {
    exists(Call call |
      // cursor.execute(query)
      call.getFunc().(Attribute).getName() = "execute" and
      this.asExpr() = call.getArg(0)
    )
  }
}

class OsCommandSink extends DataFlow::Node {
  OsCommandSink() {
    exists(Call call |
      // os.system(cmd), os.popen(cmd)
      call.getFunc().(Attribute).getName() in ["system", "popen"] and
      call.getFunc().(Attribute).getObject().(Name).getId() = "os" and
      this.asExpr() = call.getArg(0)
    )
    or
    exists(Call call |
      // subprocess.run([cmd])
      call.getFunc().(Attribute).getName() in ["run", "call", "Popen"] and
      this.asExpr() = call.getArg(0)
    )
  }
}
```

### Sanitizers

```ql
import python
import semmle.python.dataflow.new.TaintTracking

class SqlInjectionWithSanitizers extends TaintTracking::Configuration {
  SqlInjectionWithSanitizers() { this = "SqlInjectionWithSanitizers" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof RawSqlSink
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // int() conversion sanitizes
    exists(Call call |
      call.getFunc().(Name).getId() = "int" and
      node.asExpr() = call
    )
    or
    // Parameterized queries are safe
    exists(Call call |
      call.getFunc().(Attribute).getName() = "execute" and
      call.getArg(1).isPresent()  // Has params argument
    )
  }
}
```

## VulnShop Queries

### SQL Injection Query

```ql
/**
 * @name SQL Injection vulnerability
 * @description User input flows to SQL query without sanitization
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-89
 */
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      call.getFunc().(Attribute).getName() = "execute" and
      sink.asExpr() = call.getArg(0) and
      // Not a parameterized query
      not call.getArg(1).isPresent()
    )
    or
    exists(Call call |
      call.getFunc().(Attribute).getName() = "raw" and
      sink.asExpr() = call.getArg(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call call |
      call.getFunc().(Name).getId() in ["int", "float", "bool"] and
      node.asExpr() = call
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL query depends on $@.", source.getNode(), "user-provided value"
```

### Command Injection Query

```ql
/**
 * @name Command Injection vulnerability
 * @description User input flows to OS command execution
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/command-injection
 * @tags security
 *       external/cwe/cwe-78
 */
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      (
        // os.system, os.popen
        call.getFunc().(Attribute).getName() in ["system", "popen"] and
        call.getFunc().(Attribute).getObject().(Name).getId() = "os"
      )
      or
      (
        // subprocess functions
        call.getFunc().(Attribute).getName() in ["run", "call", "Popen", "check_output"] and
        call.getFunc().(Attribute).getObject().(Name).getId() = "subprocess"
      )
    ) and
    sink.asExpr() = call.getArg(0)
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call call |
      // shlex.quote sanitizes
      call.getFunc().(Attribute).getName() = "quote" and
      call.getFunc().(Attribute).getObject().(Name).getId() = "shlex" and
      node.asExpr() = call
    )
  }
}

from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "This command depends on $@.", source.getNode(), "user-provided value"
```

### SSRF Query

```ql
/**
 * @name Server-Side Request Forgery
 * @description User input controls URL in server-side HTTP request
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id py/ssrf
 * @tags security
 *       external/cwe/cwe-918
 */
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(Call call |
      (
        // requests library
        call.getFunc().(Attribute).getName() in ["get", "post", "put", "delete", "head", "patch"] and
        call.getFunc().(Attribute).getObject().(Name).getId() = "requests"
      )
      or
      (
        // urllib
        call.getFunc().(Attribute).getName() = "urlopen" and
        call.getFunc().(Attribute).getObject().(Attribute).getName() = "request"
      )
      or
      (
        // httpx
        call.getFunc().(Attribute).getName() in ["get", "post"] and
        call.getFunc().(Attribute).getObject().(Name).getId() = "httpx"
      )
    ) and
    sink.asExpr() = call.getArg(0)
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call call |
      // URL validation functions
      call.getFunc().(Name).getId() in ["validate_url", "is_safe_url"] and
      node.asExpr() = call
    )
  }
}

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "This URL depends on $@.", source.getNode(), "user-provided value"
```

## Query Libraries

### Creating Reusable Libraries

```ql
// libraries/DjangoSources.qll

import python
import semmle.python.dataflow.new.DataFlow

/**
 * A source of user-controlled data from Django requests.
 */
class DjangoSource extends DataFlow::Node {
  DjangoSource() {
    exists(Call call |
      djangoGetParameter(call) or
      djangoPostParameter(call) or
      djangoCookie(call) or
      djangoHeader(call)
    ) and
    this.asExpr() = call
  }
}

private predicate djangoGetParameter(Call call) {
  call.getFunc().(Attribute).getName() in ["get", "__getitem__"] and
  call.getFunc().(Attribute).getObject().(Attribute).getName() = "GET"
}

private predicate djangoPostParameter(Call call) {
  call.getFunc().(Attribute).getName() in ["get", "__getitem__"] and
  call.getFunc().(Attribute).getObject().(Attribute).getName() = "POST"
}

private predicate djangoCookie(Call call) {
  call.getFunc().(Attribute).getName() in ["get", "__getitem__"] and
  call.getFunc().(Attribute).getObject().(Attribute).getName() = "COOKIES"
}

private predicate djangoHeader(Call call) {
  call.getFunc().(Attribute).getName() = "__getitem__" and
  call.getFunc().(Attribute).getObject().(Attribute).getName() = "META"
}
```

### Using Libraries in Queries

```ql
import python
import semmle.python.dataflow.new.TaintTracking
import DjangoSources
import DjangoSinks

class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DjangoSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof DjangoSqlSink
  }
}
```

## Query Suites

### Creating a Suite

```yaml
# suites/vulnshop-security.qls
- description: VulnShop security queries
- queries: .
- include:
    kind:
      - problem
      - path-problem
    tags contain: security
- exclude:
    precision: low
```

### Running Suites

```bash
codeql database analyze vulnshop-db \
  --format=sarif-latest \
  --output=results.sarif \
  suites/vulnshop-security.qls
```

## Testing Queries

### Creating Test Cases

```
queries/sql-injection/
├── SqlInjection.ql
├── SqlInjection.expected    # Expected results
└── test/
    └── vulnerable.py        # Test code
```

### Test Code Example

```python
# test/vulnerable.py

def vulnerable_login(request):
    username = request.GET["username"]  # Source
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)  # Sink - should be detected

def safe_login(request):
    username = request.GET["username"]  # Source
    cursor.execute("SELECT * FROM users WHERE name = %s", [username])  # Safe
```

### Running Tests

```bash
codeql test run queries/sql-injection/
```

## Next Steps

- [Database Creation](database.md) - Creating CodeQL databases
- [Advanced Techniques](advanced.md) - Complex patterns
- [CodeQL Overview](index.md) - Return to main guide
