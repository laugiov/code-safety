/**
 * @name Server-Side Request Forgery (SSRF)
 * @description Detects SSRF vulnerabilities where user-controlled URLs are used
 *              in HTTP requests, potentially allowing access to internal services.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id py/vulnshop-ssrf
 * @tags security
 *       external/cwe/cwe-918
 *       external/owasp/owasp-a10
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A call to an HTTP client function that makes requests.
 */
class HttpRequestSink extends DataFlow::Node {
  HttpRequestSink() {
    exists(Call c |
      // requests library
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "requests" and
        c.getFunc().(Attribute).getName() in ["get", "post", "put", "delete", "patch", "head", "options", "request"] and
        this.asExpr() = c.getArg(0)
      )
      or
      // requests.Session methods
      (
        c.getFunc().(Attribute).getName() in ["get", "post", "put", "delete", "patch", "head", "options", "request"] and
        this.asExpr() = c.getArg(0)
      )
      or
      // urllib.request.urlopen
      (
        c.getFunc().(Attribute).getName() = "urlopen" and
        this.asExpr() = c.getArg(0)
      )
      or
      // urllib.request.Request
      (
        c.getFunc().(Attribute).getName() = "Request" and
        this.asExpr() = c.getArg(0)
      )
      or
      // http.client.HTTPConnection
      (
        c.getFunc().(Name).getId() in ["HTTPConnection", "HTTPSConnection"] and
        this.asExpr() = c.getArg(0)
      )
      or
      // httpx (async HTTP client)
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "httpx" and
        c.getFunc().(Attribute).getName() in ["get", "post", "put", "delete", "patch"] and
        this.asExpr() = c.getArg(0)
      )
      or
      // aiohttp
      (
        c.getFunc().(Attribute).getName() in ["get", "post", "put", "delete", "patch"] and
        this.asExpr() = c.getArg(0)
      )
    )
  }
}

/**
 * Configuration for tracking SSRF vulnerabilities.
 */
class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof HttpRequestSink
  }

  /**
   * URL validation functions can be sanitizers if properly implemented.
   * Note: Most URL validation is insufficient for SSRF prevention.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    // Only mark as sanitized if going through an allowlist check
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["validate_allowed_url", "is_allowed_host"] and
      node.asExpr() = c
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // URL parsing/joining propagates taint
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["urljoin", "urlparse", "urlunparse"] and
      node1.asExpr() = c.getAnArg() and
      node2.asExpr() = c
    )
    or
    // String formatting
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

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SSRF vulnerability: user-controlled URL from $@ used in HTTP request.",
  source.getNode(), "user input"
