/**
 * @name XML External Entity Injection (XXE)
 * @description Detects XXE vulnerabilities where user-controlled XML data is parsed
 *              without disabling external entity processing.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id py/vulnshop-xxe
 * @tags security
 *       external/cwe/cwe-611
 *       external/owasp/owasp-a05
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import DataFlow::PathGraph

/**
 * An XML parsing function that may be vulnerable to XXE.
 */
class XmlParsingSink extends DataFlow::Node {
  string parserName;

  XmlParsingSink() {
    exists(Call c |
      // lxml.etree.fromstring (vulnerable by default)
      (
        (
          c.getFunc().(Attribute).getObject().(Attribute).getName() = "etree" and
          c.getFunc().(Attribute).getName() in ["fromstring", "parse", "XML"]
        )
        or
        (
          c.getFunc().(Attribute).getObject().(Name).getId() = "etree" and
          c.getFunc().(Attribute).getName() in ["fromstring", "parse", "XML"]
        )
      ) and
      // Check if secure parser is not used
      not exists(Keyword kw |
        kw = c.getAKeyword() and
        kw.getArg() = "parser"
        // Note: Even with parser, lxml can be vulnerable without proper config
      ) and
      this.asExpr() = c.getArg(0) and
      parserName = "lxml"
    )
    or
    exists(Call c |
      // xml.etree.ElementTree.fromstring
      (
        c.getFunc().(Attribute).getName() in ["fromstring", "parse", "XML"] and
        this.asExpr() = c.getArg(0) and
        parserName = "ElementTree"
      )
    )
    or
    exists(Call c |
      // xml.dom.minidom.parseString
      (
        c.getFunc().(Attribute).getName() in ["parseString", "parse"] and
        this.asExpr() = c.getArg(0) and
        parserName = "minidom"
      )
    )
    or
    exists(Call c |
      // xml.sax.parseString
      (
        c.getFunc().(Attribute).getObject().(Name).getId() = "sax" and
        c.getFunc().(Attribute).getName() in ["parseString", "parse"] and
        this.asExpr() = c.getArg(0) and
        parserName = "sax"
      )
    )
  }

  string getParserName() { result = parserName }
}

/**
 * Configuration for tracking XXE vulnerabilities.
 */
class XxeConfig extends TaintTracking::Configuration {
  XxeConfig() { this = "XxeConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof XmlParsingSink
  }

  /**
   * defusedxml library is safe against XXE.
   */
  override predicate isSanitizer(DataFlow::Node node) {
    exists(Call c |
      c.getFunc().(Attribute).getObject().(Name).getId() = "defusedxml" and
      node.asExpr() = c
    )
    or
    // Secure lxml parser configuration
    exists(Call c |
      c.getFunc().(Name).getId() = "XMLParser" and
      exists(Keyword kw |
        kw = c.getAKeyword() and
        kw.getArg() = "resolve_entities" and
        kw.getValue().(NameConstant).getValue() = false
      ) and
      node.asExpr() = c
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // .encode() / .decode() propagate taint
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["encode", "decode"] and
      node1.asExpr() = c.getFunc().(Attribute).getObject() and
      node2.asExpr() = c
    )
    or
    // Reading request body
    exists(Attribute attr |
      attr.getName() = "body" and
      node1.asExpr() = attr.getObject() and
      node2.asExpr() = attr
    )
  }
}

from XxeConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "XXE vulnerability: user-controlled XML from $@ parsed without disabling external entities.",
  source.getNode(), "user input"
