/**
 * @name SQL Injection
 * @description Detects SQL injection vulnerabilities where user input flows directly
 *              to SQL query execution without proper parameterization.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/vulnshop-sql-injection
 * @tags security
 *       external/cwe/cwe-89
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A taint tracking configuration for SQL injection vulnerabilities.
 * Tracks data flow from remote sources (HTTP requests) to SQL execution sinks.
 */
class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }

  /**
   * Holds if `source` is a source of potentially untrusted data.
   */
  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  /**
   * Holds if `sink` is a SQL execution sink.
   */
  override predicate isSink(DataFlow::Node sink) {
    exists(SqlExecution sql | sink = sql.getSql())
  }

  /**
   * Holds if `node` is a sanitizer that makes data safe for SQL.
   * Django ORM methods like filter, get, exclude use parameterized queries.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["filter", "get", "exclude", "create", "update"] and
      node.asExpr() = c.getAnArg()
    )
    or
    // Integer conversion sanitizes string input for numeric IDs
    exists(Call c |
      c.getFunc().(Name).getId() = "int" and
      node.asExpr() = c
    )
  }

  /**
   * Holds if taint is propagated through string formatting operations.
   */
  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // f-string formatting
    exists(Fstring fs |
      node1.asExpr() = fs.getAValue() and
      node2.asExpr() = fs
    )
    or
    // String concatenation
    exists(BinaryExpr binop |
      binop.getOp() instanceof Add and
      (
        node1.asExpr() = binop.getLeft() or
        node1.asExpr() = binop.getRight()
      ) and
      node2.asExpr() = binop
    )
    or
    // % formatting
    exists(BinaryExpr binop |
      binop.getOp() instanceof Mod and
      node1.asExpr() = binop.getRight() and
      node2.asExpr() = binop
    )
    or
    // .format() method
    exists(Call c |
      c.getFunc().(Attribute).getName() = "format" and
      node1.asExpr() = c.getAnArg() and
      node2.asExpr() = c
    )
  }
}

from SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection vulnerability: user input from $@ flows to SQL query execution.",
  source.getNode(), "user-controlled data"
