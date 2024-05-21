/**
 * Provides classes and predicates related to contextual queries
 * in the code viewer.
 */

import go
private import codeql.util.FileSystem

/**
 * Returns the `File` matching the given source file name as encoded by the VS
 * Code extension.
 */
cached
File getFileBySourceArchiveName(string name) {
  result = IdeContextual<File>::getFileBySourceArchiveName(name)
}
