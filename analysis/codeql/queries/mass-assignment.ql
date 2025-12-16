/**
 * @name Mass Assignment
 * @description Detects mass assignment vulnerabilities where user input is used
 *              to set multiple model attributes without proper filtering.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id py/vulnshop-mass-assignment
 * @tags security
 *       external/cwe/cwe-915
 *       external/owasp/owasp-a04
 */

import python

/**
 * A setattr call that could allow mass assignment.
 */
class SetattrMassAssignment extends Call {
  SetattrMassAssignment() {
    this.getFunc().(Name).getId() = "setattr"
  }
}

/**
 * A loop that iterates over request data and sets attributes.
 */
class MassAssignmentLoop extends For {
  MassAssignmentLoop() {
    // Loop iterating over request.POST.items() or similar
    exists(Call c |
      this.getIter() = c and
      c.getFunc().(Attribute).getName() in ["items", "keys", "values"] and
      (
        c.getFunc().(Attribute).getObject().(Attribute).getName() in ["POST", "GET", "data"]
        or
        c.getFunc().(Attribute).getObject().(Name).getId() in ["data", "kwargs", "params"]
      )
    )
    and
    // Contains setattr in the body
    exists(SetattrMassAssignment sa |
      sa.getEnclosingStmt().getParentNode*() = this.getBody()
    )
  }
}

/**
 * Model.objects.create(**request.POST) or similar patterns.
 */
class DictUnpackingMassAssignment extends Call {
  DictUnpackingMassAssignment() {
    // create() or update() with ** unpacking of request data
    this.getFunc().(Attribute).getName() in ["create", "update", "update_or_create", "get_or_create"]
    and
    exists(Starred s |
      this.getAnArg() = s and
      (
        s.getValue().(Attribute).getName() in ["POST", "GET", "data"]
        or
        s.getValue().(Call).getFunc().(Attribute).getName() = "dict"
      )
    )
  }
}

/**
 * Direct form_data unpacking into model fields.
 */
class FormDataUnpacking extends Call {
  FormDataUnpacking() {
    // Model(**form.cleaned_data) without field whitelist
    this.getFunc().(Name).getId() != "dict" and
    exists(Starred s |
      this.getAnArg() = s and
      s.getValue().(Attribute).getName() in ["cleaned_data", "data", "validated_data"]
    )
  }
}

/**
 * setattr in a loop iterating over user input.
 */
predicate setattrInUserInputLoop(SetattrMassAssignment setattr, For loop) {
  setattr.getEnclosingStmt().getParentNode*() = loop.getBody() and
  (
    // Iterating over POST items
    exists(Call c |
      loop.getIter() = c and
      c.getFunc().(Attribute).getName() = "items"
    )
    or
    // Iterating over a dict from user input
    loop.getIter().(Name).getId() in ["data", "kwargs", "params", "fields"]
  )
}

from AstNode node, string description
where
  (
    node instanceof MassAssignmentLoop and
    description = "Mass assignment via setattr in loop over user input"
  )
  or
  (
    node instanceof DictUnpackingMassAssignment and
    description = "Mass assignment via dict unpacking of user input into model"
  )
  or
  (
    exists(SetattrMassAssignment sa, For loop |
      setattrInUserInputLoop(sa, loop) and
      node = sa and
      description = "setattr called in loop over user-controlled data"
    )
  )
  or
  (
    node instanceof FormDataUnpacking and
    description = "Unpacking form data directly into model without field whitelist"
  )
select node,
  description +
    ". Use explicit field assignment or a whitelist to prevent unauthorized attribute modification."
