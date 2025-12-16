/**
 * @name Insecure Deserialization
 * @description Detects insecure deserialization vulnerabilities where untrusted data
 *              is passed to deserialization functions like pickle.loads().
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id py/vulnshop-insecure-deserialization
 * @tags security
 *       external/cwe/cwe-502
 *       external/owasp/owasp-a08
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * A cookie access which can be a source of serialized data.
 */
class CookieSource extends DataFlow::Node {
  CookieSource() {
    exists(Subscript s |
      (
        s.getObject().(Attribute).getName() = "COOKIES"
        or
        s.getObject().(Attribute).getName() = "cookies"
      ) and
      this.asExpr() = s
    )
    or
    exists(Call c |
      (
        c.getFunc().(Attribute).getName() = "get" and
        c.getFunc().(Attribute).getObject().(Attribute).getName() = "COOKIES"
      ) and
      this.asExpr() = c
    )
  }
}

/**
 * A deserialization function call that can execute arbitrary code.
 */
class DeserializationSink extends DataFlow::Node {
  string serializerName;

  DeserializationSink() {
    exists(Call c |
      // pickle.loads / pickle.load
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "pickle" and
        c.getFunc().(Attribute).getName() in ["loads", "load"] and
        this.asExpr() = c.getArg(0) and
        serializerName = "pickle"
      )
      or
      // _pickle (C implementation)
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "_pickle" and
        c.getFunc().(Attribute).getName() = "loads" and
        this.asExpr() = c.getArg(0) and
        serializerName = "pickle"
      )
      or
      // cPickle (Python 2 compatibility)
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "cPickle" and
        c.getFunc().(Attribute).getName() in ["loads", "load"] and
        this.asExpr() = c.getArg(0) and
        serializerName = "pickle"
      )
      or
      // yaml.load without SafeLoader
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "yaml" and
        c.getFunc().(Attribute).getName() in ["load", "unsafe_load", "full_load"] and
        // Check if Loader is not SafeLoader
        not exists(Keyword kw |
          kw = c.getAKeyword() and
          kw.getArg() = "Loader" and
          kw.getValue().(Attribute).getName() = "SafeLoader"
        ) and
        this.asExpr() = c.getArg(0) and
        serializerName = "yaml"
      )
      or
      // marshal.loads
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "marshal" and
        c.getFunc().(Attribute).getName() = "loads" and
        this.asExpr() = c.getArg(0) and
        serializerName = "marshal"
      )
      or
      // jsonpickle.decode
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "jsonpickle" and
        c.getFunc().(Attribute).getName() = "decode" and
        this.asExpr() = c.getArg(0) and
        serializerName = "jsonpickle"
      )
      or
      // shelve.open
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "shelve" and
        c.getFunc().(Attribute).getName() = "open" and
        this.asExpr() = c.getArg(0) and
        serializerName = "shelve"
      )
    )
  }

  string getSerializerName() { result = serializerName }
}

/**
 * Configuration for tracking insecure deserialization vulnerabilities.
 */
class DeserializationConfig extends TaintTracking::Configuration {
  DeserializationConfig() { this = "DeserializationConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    source instanceof CookieSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof DeserializationSink
  }

  /**
   * json.loads is safe and doesn't execute code.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Attribute).getObject().(Name).getId() = "json" and
      c.getFunc().(Attribute).getName() = "loads" and
      node.asExpr() = c
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getObject().(Name).getId() = "yaml" and
      c.getFunc().(Attribute).getName() = "safe_load" and
      node.asExpr() = c
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // base64.b64decode propagates taint
    exists(Call c |
      c.getFunc().(Attribute).getName() = "b64decode" and
      node1.asExpr() = c.getArg(0) and
      node2.asExpr() = c
    )
    or
    // .encode() / .decode() propagate taint
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["encode", "decode"] and
      node1.asExpr() = c.getFunc().(Attribute).getObject() and
      node2.asExpr() = c
    )
  }
}

from DeserializationConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Insecure deserialization: untrusted data from $@ passed to deserialization function.",
  source.getNode(), "untrusted source"
