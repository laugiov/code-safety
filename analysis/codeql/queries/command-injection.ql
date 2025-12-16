/**
 * @name Command Injection
 * @description Detects OS command injection vulnerabilities where user input
 *              flows to command execution functions without proper sanitization.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/vulnshop-command-injection
 * @tags security
 *       external/cwe/cwe-78
 *       external/owasp/owasp-a03
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A call to an OS command execution function.
 */
class CommandExecutionSink extends DataFlow::Node {
  CommandExecutionSink() {
    exists(Call c |
      // os.system
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
        c.getFunc().(Attribute).getName() = "system" and
        this.asExpr() = c.getArg(0)
      )
      or
      // os.popen
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
        c.getFunc().(Attribute).getName() = "popen" and
        this.asExpr() = c.getArg(0)
      )
      or
      // subprocess functions with shell=True
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "subprocess" and
        c.getFunc().(Attribute).getName() in ["call", "run", "Popen", "check_output", "check_call"] and
        // Check if shell=True is passed
        exists(Keyword kw |
          kw = c.getAKeyword() and
          kw.getArg() = "shell" and
          kw.getValue().(NameConstant).getValue() = true
        ) and
        this.asExpr() = c.getArg(0)
      )
      or
      // subprocess with string command and shell=True implicit
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "subprocess" and
        c.getFunc().(Attribute).getName() in ["call", "run", "Popen", "check_output"] and
        c.getArg(0) instanceof StrConst = false and  // Not a list
        this.asExpr() = c.getArg(0)
      )
    )
  }
}

/**
 * Configuration for tracking command injection vulnerabilities.
 */
class CommandInjectionConfig extends TaintTracking::Configuration {
  CommandInjectionConfig() { this = "CommandInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandExecutionSink
  }

  /**
   * shlex.quote sanitizes input for shell commands
   */
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Attribute).getObject().(Name).getId() = "shlex" and
      c.getFunc().(Attribute).getName() = "quote" and
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
    // String concatenation
    exists(BinaryExpr binop |
      binop.getOp() instanceof Add and
      (node1.asExpr() = binop.getLeft() or node1.asExpr() = binop.getRight()) and
      node2.asExpr() = binop
    )
  }
}

from CommandInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Command injection vulnerability: user input from $@ flows to OS command execution.",
  source.getNode(), "user-controlled data"
