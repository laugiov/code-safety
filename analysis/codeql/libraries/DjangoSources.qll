/**
 * Django-specific source definitions for taint analysis.
 *
 * This library extends CodeQL's standard RemoteFlowSource to include
 * Django-specific sources of user-controlled data.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources

/**
 * A Django HTTP request source.
 * Includes GET, POST, COOKIES, FILES, META, headers, and body.
 */
class DjangoRequestSource extends RemoteFlowSource::Range {
  DjangoRequestSource() {
    // request.GET[key] or request.GET.get(key)
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "GET" and
      this.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "GET" and
      this.asExpr() = c
    )
    or
    // request.POST[key] or request.POST.get(key)
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "POST" and
      this.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "POST" and
      this.asExpr() = c
    )
    or
    // request.COOKIES
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "COOKIES" and
      this.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "COOKIES" and
      this.asExpr() = c
    )
    or
    // request.FILES
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "FILES" and
      this.asExpr() = s
    )
    or
    // request.META (headers)
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "META" and
      this.asExpr() = s
    )
    or
    // request.body
    exists(Attribute a |
      a.getName() = "body" and
      this.asExpr() = a
    )
    or
    // request.headers
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "headers" and
      this.asExpr() = s
    )
    or
    // request.path, request.path_info
    exists(Attribute a |
      a.getName() in ["path", "path_info", "get_full_path"] and
      this.asExpr() = a
    )
  }

  override string getSourceType() { result = "Django HTTP request" }
}

/**
 * Django REST Framework request source.
 */
class DRFRequestSource extends RemoteFlowSource::Range {
  DRFRequestSource() {
    // request.data[key] or request.data.get(key)
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "data" and
      this.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "data" and
      this.asExpr() = c
    )
    or
    // request.query_params
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "query_params" and
      this.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "query_params" and
      this.asExpr() = c
    )
  }

  override string getSourceType() { result = "Django REST Framework request" }
}

/**
 * URL path parameters captured from URL patterns.
 * In Django, these are passed as keyword arguments to view functions.
 */
class DjangoUrlParameterSource extends RemoteFlowSource::Range {
  DjangoUrlParameterSource() {
    // Function parameters that are likely URL captures
    exists(Function f, Parameter p |
      f.getAParameter() = p and
      p.getName() in [
          "pk", "id", "slug", "uuid", "user_id", "product_id", "order_id", "review_id", "profile_id",
          "category_id", "item_id", "article_id", "post_id", "comment_id", "file_id", "token"
        ] and
      this.asExpr() = p.asName().getAFlowNode()
    )
  }

  override string getSourceType() { result = "Django URL parameter" }
}

/**
 * Form data from Django forms.
 */
class DjangoFormSource extends RemoteFlowSource::Range {
  DjangoFormSource() {
    // form.cleaned_data[key]
    exists(Subscript s |
      s.getObject().(Attribute).getName() = "cleaned_data" and
      this.asExpr() = s
    )
    or
    exists(Call c |
      c.getFunc().(Attribute).getName() = "get" and
      c.getFunc().(Attribute).getObject().(Attribute).getName() = "cleaned_data" and
      this.asExpr() = c
    )
  }

  override string getSourceType() { result = "Django form data" }
}
