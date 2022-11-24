/**
 * @name Deferred call may return an error
 * @description Deferring a call to a function which may return an error means that an error may not be handled.
 * @kind problem
 * @problem.severity warning
 * @id go/deferred-error-call
 * @tags maintainability
 *  correctness
 *  call
 *  defer
 */

import go

from DeferStmt defer, SignatureType sig
where
  // match all deferred function calls and obtain their type signatures
  sig = defer.getCall().getCalleeExpr().getType().(SignatureType) and
  // check that one of the results is an error
  sig.getResultType(_).implements(Builtin::error().getType().getUnderlyingType())
select defer,
  "Deferred a call to " + defer.getCall().getCalleeName() + ", which may return an error."
