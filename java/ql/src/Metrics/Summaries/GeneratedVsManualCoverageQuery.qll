private import semmle.code.java.dataflow.FlowSummary
private import utils.modelgenerator.internal.CaptureModels
private import semmle.code.java.metrics.summaries.TopJdkApis

/**
 * Returns the number of `DataFlowTargetApi`s with Summary MaD models
 * for a given package and provenance.
 */
bindingset[package, apiSubset]
private int getNumMadModeledApis(string package, string provenance, string apiSubset) {
  provenance in ["generated", "manual", "both"] and
  result =
    count(SummarizedCallable sc |
      callableSubset(sc.asCallable(), apiSubset) and
      package = sc.asCallable().getCompilationUnit().getPackage().getName() and
      sc.asCallable() instanceof DataFlowTargetApi and
      (
        // "auto-only"
        sc.isAutoGenerated() and
        provenance = "generated"
        or
        sc.isManual() and
        (
          if sc.hasProvenance(["generated", "ai-generated"])
          then
            // "both"
            provenance = "both"
          else
            // "manual-only"
            provenance = "manual"
        )
      )
    )
}

/** Returns the total number of `DataFlowTargetApi`s for a given package. */
private int getNumApis(string package, string apiSubset) {
  result =
    strictcount(DataFlowTargetApi dataFlowTargApi |
      callableSubset(dataFlowTargApi, apiSubset) and
      package = dataFlowTargApi.getCompilationUnit().getPackage().getName()
    )
}

/** TODO */
private predicate callableSubset(Callable callable, string apiSubset) {
  apiSubset in ["topJdkApis", "allApis"] and
  (
    if apiSubset = "topJdkApis"
    then exists(TopJdkApi topJdkApi | callable = topJdkApi.asCallable())
    else apiSubset = "allApis"
  )
}

/** TODO */
predicate modelCoverageGenVsMan(
  string package, int generatedOnly, int both, int manualOnly, int non, int all, float coverage,
  float generatedCoverage, float manualCoverage, float manualCoveredByGenerated,
  float generatedCoveredByManual, float match, string apiSubset
) {
  exists(int generated, int manual |
    // count the number of APIs with generated-only, both, and manual-only MaD models for each package
    generatedOnly = getNumMadModeledApis(package, "generated", apiSubset) and
    both = getNumMadModeledApis(package, "both", apiSubset) and
    manualOnly = getNumMadModeledApis(package, "manual", apiSubset) and
    // calculate the total generated and total manual numbers
    generated = generatedOnly + both and
    manual = manualOnly + both and
    // count the total number of `DataFlowTargetApi`s for each package
    all = getNumApis(package, apiSubset) and
    non = all - (generatedOnly + both + manualOnly) and
    // Proportion of coverage
    coverage = (generatedOnly + both + manualOnly).(float) / all and
    generatedCoverage = generated.(float) / all and
    manualCoverage = manual.(float) / all and
    // Proportion of manual models covered by generated ones
    manualCoveredByGenerated = both.(float) / (both + manualOnly) and
    // Proportion of generated models covered by manual ones
    generatedCoveredByManual = both.(float) / (both + generatedOnly) and
    // Proportion of data points that match
    match = (both.(float) + non) / all
  )
}
