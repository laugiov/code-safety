/**
 * @name Stored Cross-Site Scripting (XSS)
 * @description Detects stored XSS vulnerabilities where data from the database
 *              is rendered without proper escaping.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id py/vulnshop-xss-stored
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph

/**
 * A source of data from the database (model fields).
 */
class DatabaseSource extends DataFlow::Node {
  DatabaseSource() {
    // Attribute access on model instances
    exists(Attribute attr |
      this.asExpr() = attr and
      // Common patterns for model field access
      attr.getName() in ["comment", "content", "body", "text", "description", "title", "name", "message", "html", "comment_html"]
    )
    or
    // QuerySet results
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["first", "last", "get"] and
      this.asExpr() = c
    )
  }
}

/**
 * A call to mark_safe which bypasses Django's auto-escaping.
 */
class MarkSafeSink extends DataFlow::Node {
  MarkSafeSink() {
    exists(Call c |
      (
        c.getFunc().(Name).getId() = "mark_safe"
        or
        c.getFunc().(Attribute).getName() = "mark_safe"
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * Assigning to an _html suffixed field (common pattern for storing pre-rendered HTML)
 */
class HtmlFieldAssignment extends DataFlow::Node {
  HtmlFieldAssignment() {
    exists(AssignStmt a, Attribute attr |
      attr.getName().matches("%_html") and
      a.getTarget(0) = attr and
      this.asExpr() = a.getValue()
    )
  }
}

/**
 * Configuration for tracking stored XSS vulnerabilities.
 */
class StoredXssConfig extends TaintTracking::Configuration {
  StoredXssConfig() { this = "StoredXssConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof DatabaseSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MarkSafeSink
    or
    sink instanceof HtmlFieldAssignment
  }

  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      (
        c.getFunc().(Name).getId() in ["escape", "strip_tags", "escapejs"]
        or
        c.getFunc().(Attribute).getName() in ["escape", "strip_tags", "escapejs"]
      ) and
      node.asExpr() = c
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getObject().(Name).getId() = "bleach" and
      c.getFunc().(Attribute).getName() = "clean" and
      node.asExpr() = c
    )
  }
}

from StoredXssConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Stored XSS vulnerability: database content from $@ rendered without escaping.",
  source.getNode(), "database field"
