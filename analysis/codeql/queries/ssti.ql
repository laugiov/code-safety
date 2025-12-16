/**
 * @name Server-Side Template Injection (SSTI)
 * @description Detects SSTI vulnerabilities where user input is used to construct
 *              templates, allowing code execution through template expressions.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/vulnshop-ssti
 * @tags security
 *       external/cwe/cwe-1336
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A template construction from string, which can lead to SSTI.
 */
class TemplateConstructionSink extends DataFlow::Node {
  string templateEngine;

  TemplateConstructionSink() {
    exists(Call c |
      // Django Template()
      (
        c.getFunc().(Name).getId() = "Template" and
        this.asExpr() = c.getArg(0) and
        templateEngine = "Django"
      )
      or
      // django.template.Template
      (
        c.getFunc().(Attribute).getName() = "Template" and
        this.asExpr() = c.getArg(0) and
        templateEngine = "Django"
      )
      or
      // Jinja2 Template()
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "jinja2" and
        c.getFunc().(Attribute).getName() = "Template" and
        this.asExpr() = c.getArg(0) and
        templateEngine = "Jinja2"
      )
      or
      // Environment.from_string()
      (
        c.getFunc().(Attribute).getName() = "from_string" and
        this.asExpr() = c.getArg(0) and
        templateEngine = "Jinja2"
      )
      or
      // Mako Template()
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "mako" and
        c.getFunc().(Attribute).getName() = "Template" and
        this.asExpr() = c.getArg(0) and
        templateEngine = "Mako"
      )
      or
      // Tornado template
      (
        c.getFunc().(Attribute).getName() = "Template" and
        this.asExpr() = c.getArg(0) and
        templateEngine = "Tornado"
      )
    )
  }

  string getTemplateEngine() { result = templateEngine }
}

/**
 * render_template_string in Flask is also vulnerable to SSTI.
 */
class FlaskRenderStringSink extends DataFlow::Node {
  FlaskRenderStringSink() {
    exists(Call c |
      c.getFunc().(Name).getId() = "render_template_string" and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * Configuration for tracking SSTI vulnerabilities.
 */
class SstiConfig extends TaintTracking::Configuration {
  SstiConfig() { this = "SstiConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof TemplateConstructionSink
    or
    sink instanceof FlaskRenderStringSink
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // String formatting propagates taint
    exists(Fstring fs |
      node1.asExpr() = fs.getAValue() and
      node2.asExpr() = fs
    )
    or
    // Concatenation
    exists(BinaryExpr binop |
      binop.getOp() instanceof Add and
      (node1.asExpr() = binop.getLeft() or node1.asExpr() = binop.getRight()) and
      node2.asExpr() = binop
    )
  }
}

from SstiConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Server-Side Template Injection: user input from $@ used in template construction.",
  source.getNode(), "user input"
