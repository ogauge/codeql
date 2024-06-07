// generated by codegen/codegen.py
/**
 * This module provides the generated definition of `ModuleDecl`.
 * INTERNAL: Do not import directly.
 */

private import codeql.swift.generated.Synth
private import codeql.swift.generated.Raw
import codeql.swift.elements.decl.TypeDecl

/**
 * INTERNAL: This module contains the fully generated definition of `ModuleDecl` and should not
 * be referenced directly.
 */
module Generated {
  /**
   * INTERNAL: Do not reference the `Generated::ModuleDecl` class directly.
   * Use the subclass `ModuleDecl`, where the following predicates are available.
   */
  class ModuleDecl extends Synth::TModuleDecl, TypeDecl {
    override string getAPrimaryQlClass() { result = "ModuleDecl" }

    /**
     * Holds if this module is the built-in one.
     */
    predicate isBuiltinModule() {
      Synth::convertModuleDeclToRaw(this).(Raw::ModuleDecl).isBuiltinModule()
    }

    /**
     * Holds if this module is a system one.
     */
    predicate isSystemModule() {
      Synth::convertModuleDeclToRaw(this).(Raw::ModuleDecl).isSystemModule()
    }

    /**
     * Gets the `index`th imported module of this module declaration (0-based).
     *Gets any of the imported modules of this module declaration.
     */
    ModuleDecl getAnImportedModule() {
      result =
        Synth::convertModuleDeclFromRaw(Synth::convertModuleDeclToRaw(this)
              .(Raw::ModuleDecl)
              .getAnImportedModule())
    }

    /**
     * Gets the number of imported modules of this module declaration.
     */
    final int getNumberOfImportedModules() { result = count(this.getAnImportedModule()) }

    /**
     * Gets the `index`th exported module of this module declaration (0-based).
     *Gets any of the exported modules of this module declaration.
     */
    ModuleDecl getAnExportedModule() {
      result =
        Synth::convertModuleDeclFromRaw(Synth::convertModuleDeclToRaw(this)
              .(Raw::ModuleDecl)
              .getAnExportedModule())
    }

    /**
     * Gets the number of exported modules of this module declaration.
     */
    final int getNumberOfExportedModules() { result = count(this.getAnExportedModule()) }
  }
}
