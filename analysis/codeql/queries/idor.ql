/**
 * @name Insecure Direct Object Reference (IDOR)
 * @description Detects potential IDOR vulnerabilities where user-supplied IDs
 *              are used to access resources without authorization checks.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id py/vulnshop-idor
 * @tags security
 *       external/cwe/cwe-639
 *       external/owasp/owasp-a01
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * An object retrieval that might be vulnerable to IDOR.
 * This detects patterns like Model.objects.get(id=user_input).
 */
class ObjectRetrievalSink extends DataFlow::Node {
  ObjectRetrievalSink() {
    exists(Call c, Keyword kw |
      // Model.objects.get(id=...) or .get(pk=...)
      c.getFunc().(Attribute).getName() = "get" and
      kw = c.getAKeyword() and
      kw.getArg() in ["id", "pk", "user_id", "owner_id", "profile_id", "order_id", "account_id"] and
      this.asExpr() = kw.getValue()
    )
    or
    exists(Call c, Keyword kw |
      // Model.objects.filter(id=...).first()
      c.getFunc().(Attribute).getName() = "filter" and
      kw = c.getAKeyword() and
      kw.getArg() in ["id", "pk", "user_id", "owner_id", "profile_id"] and
      this.asExpr() = kw.getValue()
    )
  }
}

/**
 * Direct database ID access without filtering by current user.
 */
class DirectIdAccessSink extends DataFlow::Node {
  DirectIdAccessSink() {
    // Direct subscript access like objects[id]
    exists(Subscript s |
      this.asExpr() = s.getIndex()
    )
    or
    // .get(id) positional argument
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getNumArgs() >= 1 and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * Configuration for tracking potential IDOR vulnerabilities.
 */
class IdorConfig extends TaintTracking::Configuration {
  IdorConfig() { this = "IdorConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof ObjectRetrievalSink
  }

  /**
   * Authorization checks that filter by current user are sanitizers.
   * Note: This is heuristic-based and may have false positives.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    // Filter by current user is a form of authorization
    exists(Call c, Keyword kw |
      c.getFunc().(Attribute).getName() = "filter" and
      kw = c.getAKeyword() and
      kw.getArg() in ["user", "owner", "created_by", "user_id"] and
      (
        kw.getValue().(Attribute).getName() = "user"
        or
        kw.getValue().(Attribute).getName() = "id" and
        kw.getValue().(Attribute).getObject().(Attribute).getName() = "user"
      ) and
      node.asExpr() = c
    )
    or
    // Integer conversion can be considered partial sanitization
    // as it prevents string-based attacks
    exists(Call c |
      c.getFunc().(Name).getId() = "int" and
      node.asExpr() = c
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Function argument passing
    exists(Call c |
      node1.asExpr() = c.getAnArg() and
      node2.asExpr() = c
    )
  }
}

from IdorConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Potential IDOR: user-supplied ID from $@ used to retrieve object without ownership verification.",
  source.getNode(), "user input"
