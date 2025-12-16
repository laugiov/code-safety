/**
 * @name Sensitive Data Logging
 * @description Detects logging of sensitive data such as passwords, tokens,
 *              and personal information that may be exposed in log files.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 5.5
 * @precision medium
 * @id py/vulnshop-sensitive-logging
 * @tags security
 *       external/cwe/cwe-532
 *       external/owasp/owasp-a09
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A source of sensitive data (passwords, tokens, PII).
 */
class SensitiveDataSource extends DataFlow::Node {
  string dataType;

  SensitiveDataSource() {
    // Password fields from request
    (
      exists(Subscript s |
        this.asExpr() = s and
        s.getIndex().(StrConst).getText().regexpMatch("(?i).*(password|passwd|pwd|secret|token|key|credit_?card|ssn|social_security).*")
      ) and
      dataType = "credential"
    )
    or
    // Dict.get() with sensitive key
    (
      exists(Call c |
        c.getFunc().(Attribute).getName() = "get" and
        c.getArg(0).(StrConst).getText().regexpMatch("(?i).*(password|passwd|pwd|secret|token|api_key).*") and
        this.asExpr() = c
      ) and
      dataType = "credential"
    )
    or
    // POST data that might contain passwords
    (
      exists(Attribute attr |
        attr.getName() = "POST" and
        this.asExpr() = attr
      ) and
      dataType = "form_data"
    )
    or
    // Cookie data
    (
      exists(Attribute attr |
        attr.getName() = "COOKIES" and
        this.asExpr() = attr
      ) and
      dataType = "cookies"
    )
    or
    // Session data
    (
      exists(Attribute attr |
        attr.getName() = "session" and
        this.asExpr() = attr
      ) and
      dataType = "session"
    )
  }

  string getDataType() { result = dataType }
}

/**
 * A logging function call.
 */
class LoggingSink extends DataFlow::Node {
  string logLevel;

  LoggingSink() {
    exists(Call c |
      // logging module functions
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "logging" and
        c.getFunc().(Attribute).getName() in ["debug", "info", "warning", "error", "critical", "exception"] and
        (this.asExpr() = c.getArg(0) or this.asExpr() = c.getAnArg()) and
        logLevel = c.getFunc().(Attribute).getName()
      )
      or
      // Logger instance methods
      (
        c.getFunc().(Attribute).getName() in ["debug", "info", "warning", "error", "critical", "exception"] and
        (this.asExpr() = c.getArg(0) or this.asExpr() = c.getAnArg()) and
        logLevel = c.getFunc().(Attribute).getName()
      )
      or
      // print() can also be a logging sink in development
      (
        c.getFunc().(Name).getId() = "print" and
        this.asExpr() = c.getAnArg() and
        logLevel = "print"
      )
    )
  }

  string getLogLevel() { result = logLevel }
}

/**
 * Configuration for tracking sensitive data to logging.
 */
class SensitiveLoggingConfig extends TaintTracking::Configuration {
  SensitiveLoggingConfig() { this = "SensitiveLoggingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveDataSource
    or
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof LoggingSink
  }

  /**
   * Masking or redacting functions are sanitizers.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["mask", "redact", "sanitize", "hash"] and
      node.asExpr() = c
    )
    or
    // Hashing is a form of sanitization
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["md5", "sha1", "sha256", "sha512", "pbkdf2"] and
      node.asExpr() = c
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // f-string formatting
    exists(Fstring fs |
      node1.asExpr() = fs.getAValue() and
      node2.asExpr() = fs
    )
    or
    // str() conversion
    exists(Call c |
      c.getFunc().(Name).getId() = "str" and
      node1.asExpr() = c.getArg(0) and
      node2.asExpr() = c
    )
    or
    // dict() on request objects
    exists(Call c |
      c.getFunc().(Name).getId() = "dict" and
      node1.asExpr() = c.getArg(0) and
      node2.asExpr() = c
    )
    or
    // % formatting
    exists(BinaryExpr binop |
      binop.getOp() instanceof Mod and
      node1.asExpr() = binop.getRight() and
      node2.asExpr() = binop
    )
  }
}

from SensitiveLoggingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Sensitive data from $@ may be logged, potentially exposing credentials in log files.",
  source.getNode(), "sensitive source"
