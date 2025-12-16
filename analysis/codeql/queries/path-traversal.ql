/**
 * @name Path Traversal
 * @description Detects path traversal vulnerabilities where user input is used
 *              in file paths without proper validation.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/vulnshop-path-traversal
 * @tags security
 *       external/cwe/cwe-22
 *       external/owasp/owasp-a01
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A file system operation that takes a path argument.
 */
class FileSystemSink extends DataFlow::Node {
  FileSystemSink() {
    exists(Call c |
      // Built-in open()
      (
        c.getFunc().(Name).getId() = "open" and
        this.asExpr() = c.getArg(0)
      )
      or
      // io.open()
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "io" and
        c.getFunc().(Attribute).getName() = "open" and
        this.asExpr() = c.getArg(0)
      )
      or
      // os.path.join() - often used before open()
      (
        c.getFunc().(Attribute).getName() = "join" and
        c.getFunc().(Attribute).getObject().(Attribute).getName() = "path" and
        this.asExpr() = c.getAnArg()
      )
      or
      // pathlib.Path operations
      (
        c.getFunc().(Name).getId() = "Path" and
        this.asExpr() = c.getArg(0)
      )
      or
      // File deletion
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "os" and
        c.getFunc().(Attribute).getName() in ["remove", "unlink", "rmdir"] and
        this.asExpr() = c.getArg(0)
      )
      or
      // shutil operations
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "shutil" and
        c.getFunc().(Attribute).getName() in ["copy", "move", "rmtree", "copytree"] and
        this.asExpr() = c.getAnArg()
      )
      or
      // File reading/writing helpers
      (
        c.getFunc().(Attribute).getName() in ["read_text", "read_bytes", "write_text", "write_bytes"] and
        this.asExpr() = c
      )
    )
  }
}

/**
 * Configuration for tracking path traversal vulnerabilities.
 */
class PathTraversalConfig extends TaintTracking::Configuration {
  PathTraversalConfig() { this = "PathTraversalConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof FileSystemSink
  }

  /**
   * os.path.basename() removes directory components, sanitizing traversal.
   * Also, validation that path is within allowed directory.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      (
        // os.path.basename strips directory components
        c.getFunc().(Attribute).getName() = "basename" and
        node.asExpr() = c
      )
      or
      (
        // os.path.normpath + validation could be a sanitizer
        // but requires additional startswith check
        c.getFunc().(Attribute).getName() = "normpath" and
        node.asExpr() = c
      )
      or
      (
        // secure_filename from werkzeug
        c.getFunc().(Name).getId() = "secure_filename" and
        node.asExpr() = c
      )
      or
      (
        // Django's get_valid_filename
        c.getFunc().(Name).getId() = "get_valid_filename" and
        node.asExpr() = c
      )
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // os.path.join propagates taint
    exists(Call c |
      c.getFunc().(Attribute).getName() = "join" and
      node1.asExpr() = c.getAnArg() and
      node2.asExpr() = c
    )
    or
    // Path / operator
    exists(BinaryExpr binop |
      binop.getOp() instanceof Div and
      (node1.asExpr() = binop.getLeft() or node1.asExpr() = binop.getRight()) and
      node2.asExpr() = binop
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

from PathTraversalConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Path traversal vulnerability: user input from $@ used in file path.",
  source.getNode(), "user input"
