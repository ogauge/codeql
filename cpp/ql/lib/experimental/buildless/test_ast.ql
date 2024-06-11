import AST
import types

query TestAST::SourceFunction lua_copy() { result.getName() = "lua_copy" }

query int lua_copy_count() { result = count(lua_copy()) }

query predicate variables(TestAST::SourceVariableDeclaration decl, TestAST::SourceType sourceType) {
  sourceType = decl.getType()
}

query predicate naiveCallTargets(TestAST::CallExpr call, TestAST::SourceFunction target) {
  call.getReceiver().(TestAST::AccessExpr).getName() = target.getName() and
  target.getName() = "max"
}

query predicate fnParents(TestAST::SourceFunction fn, TestAST::SourceNamespace parent) {
  parent = fn.getParent()
}

query predicate includes(TestAST::Include include, File target) { target = include.getATarget() }

query predicate unresolvedIncludes(TestAST::Include include) { not exists(include.getATarget()) }

from TestAST::SourceFunction fn
select fn, fn.getReturnType(), count(fn.getReturnType()), fn.getReturnType().getAQlClass()
