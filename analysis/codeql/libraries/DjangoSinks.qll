/**
 * Django-specific sink definitions for taint analysis.
 *
 * This library defines dangerous operations (sinks) that should not
 * receive untrusted user input directly.
 */

import python
import semmle.python.dataflow.new.DataFlow

/**
 * A SQL execution sink in Django.
 */
class DjangoSqlSink extends DataFlow::Node {
  DjangoSqlSink() {
    // cursor.execute(sql)
    exists(Call c |
      c.getFunc().(Attribute).getName() = "execute" and
      this.asExpr() = c.getArg(0)
    )
    or
    // Model.objects.raw(sql)
    exists(Call c |
      c.getFunc().(Attribute).getName() = "raw" and
      this.asExpr() = c.getArg(0)
    )
    or
    // QuerySet.extra(where=[...])
    exists(Call c, Keyword kw |
      c.getFunc().(Attribute).getName() = "extra" and
      kw = c.getAKeyword() and
      kw.getArg() in ["where", "select", "tables"] and
      this.asExpr() = kw.getValue()
    )
  }
}

/**
 * A template construction sink for SSTI.
 */
class DjangoTemplateSink extends DataFlow::Node {
  DjangoTemplateSink() {
    // Template(template_string)
    exists(Call c |
      (
        c.getFunc().(Name).getId() = "Template"
        or
        c.getFunc().(Attribute).getName() = "Template"
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * A mark_safe sink for XSS.
 */
class DjangoMarkSafeSink extends DataFlow::Node {
  DjangoMarkSafeSink() {
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
 * A redirect sink for open redirect.
 */
class DjangoRedirectSink extends DataFlow::Node {
  DjangoRedirectSink() {
    exists(Call c |
      (
        c.getFunc().(Name).getId() = "redirect"
        or
        c.getFunc().(Name).getId() = "HttpResponseRedirect"
        or
        c.getFunc().(Name).getId() = "HttpResponsePermanentRedirect"
      ) and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * File operation sinks for path traversal.
 */
class DjangoFileSink extends DataFlow::Node {
  DjangoFileSink() {
    // FileResponse with user-controlled path
    exists(Call c |
      c.getFunc().(Name).getId() = "FileResponse" and
      this.asExpr() = c.getArg(0)
    )
    or
    // default_storage.open with user path
    exists(Call c |
      c.getFunc().(Attribute).getName() = "open" and
      this.asExpr() = c.getArg(0)
    )
  }
}

/**
 * An email construction sink (for potential email injection).
 */
class DjangoEmailSink extends DataFlow::Node {
  DjangoEmailSink() {
    exists(Call c |
      c.getFunc().(Name).getId() in ["send_mail", "EmailMessage", "EmailMultiAlternatives"] and
      this.asExpr() = c.getAnArg()
    )
  }
}

/**
 * A cache key sink (cache poisoning).
 */
class DjangoCacheSink extends DataFlow::Node {
  DjangoCacheSink() {
    exists(Call c |
      c.getFunc().(Attribute).getName() in ["get", "set", "delete"] and
      c.getFunc().(Attribute).getObject().(Name).getId() = "cache" and
      this.asExpr() = c.getArg(0)
    )
  }
}
