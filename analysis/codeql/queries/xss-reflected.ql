/**
 * @name Reflected Cross-Site Scripting (XSS)
 * @description Detects reflected XSS vulnerabilities where user input is rendered
 *              in HTML responses without proper escaping.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id py/vulnshop-xss-reflected
 * @tags security
 *       external/cwe/cwe-79
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

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
 * A call to format_html with user input in non-placeholder position.
 */
class FormatHtmlSink extends DataFlow::Node {
  FormatHtmlSink() {
    exists(Call c |
      c.getFunc().(Attribute).getName() = "format_html" and
      this.asExpr() = c.getArg(0)  // Format string itself is dangerous
    )
  }
}

/**
 * HttpResponse with content_type='text/html' and user content.
 */
class HttpResponseSink extends DataFlow::Node {
  HttpResponseSink() {
    exists(Call c |
      c.getFunc().(Name).getId() = "HttpResponse" and
      (
        not exists(Keyword kw | kw = c.getAKeyword() and kw.getArg() = "content_type")
        or
        exists(Keyword kw |
          kw = c.getAKeyword() and
          kw.getArg() = "content_type" and
          kw.getValue().(StrConst).getText().matches("%html%")
        )
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * Configuration for tracking reflected XSS vulnerabilities.
 */
class ReflectedXssConfig extends TaintTracking::Configuration {
  ReflectedXssConfig() { this = "ReflectedXssConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MarkSafeSink
    or
    sink instanceof FormatHtmlSink
    or
    sink instanceof HttpResponseSink
  }

  /**
   * Django's escape and strip_tags functions sanitize XSS
   */
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
    // bleach.clean is a sanitizer
    exists(Call c |
      c.getFunc().(Attribute).getObject().(Name).getId() = "bleach" and
      c.getFunc().(Attribute).getName() = "clean" and
      node.asExpr() = c
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // String formatting propagates taint
    exists(Fstring fs |
      node1.asExpr() = fs.getAValue() and
      node2.asExpr() = fs
    )
  }
}

from ReflectedXssConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Reflected XSS vulnerability: user input from $@ rendered without escaping.",
  source.getNode(), "user-controlled data"
