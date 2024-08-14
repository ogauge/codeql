/**
 * Provides a Java-specific instantiation of the `AlertFiltering` module.
 */

private import codeql.util.AlertFiltering
private import semmle.code.Location

/** Module for applying alert location filtering. */
module AlertFiltering {
  import AlertFilteringImpl<Location>

  /** Applies alert filtering to the given `Top` locatable. */
  predicate filterByLocatable(Top locatable) { filterByLocation(locatable.getLocation()) }
}
