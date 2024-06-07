// generated by codegen/codegen.py
import codeql.swift.elements
import TestUtils

from
  EnumDecl x, int getNumberOfGenericTypeParams, ModuleDecl getModule, int getNumberOfMembers,
  Type getInterfaceType, string getName, int getNumberOfInheritedTypes, Type getType
where
  toBeTested(x) and
  not x.isUnknown() and
  getNumberOfGenericTypeParams = x.getNumberOfGenericTypeParams() and
  getModule = x.getModule() and
  getNumberOfMembers = x.getNumberOfMembers() and
  getInterfaceType = x.getInterfaceType() and
  getName = x.getName() and
  getNumberOfInheritedTypes = x.getNumberOfInheritedTypes() and
  getType = x.getType()
select x, "getNumberOfGenericTypeParams:", getNumberOfGenericTypeParams, "getModule:", getModule,
  "getNumberOfMembers:", getNumberOfMembers, "getInterfaceType:", getInterfaceType, "getName:",
  getName, "getNumberOfInheritedTypes:", getNumberOfInheritedTypes, "getType:", getType
