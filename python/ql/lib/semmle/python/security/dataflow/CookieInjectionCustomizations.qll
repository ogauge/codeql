/**
 * Provides default sources, sinks and sanitizers for detecting
 * "cookie injection"
 * vulnerabilities, as well as extension points for adding your own.
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.Concepts
private import semmle.python.dataflow.new.RemoteFlowSources

/**
 * Provides default sources, sinks and sanitizers for detecting
 * "cookie injection"
 * vulnerabilities, as well as extension points for adding your own.
 */
module CookieInjection {
  /**
   * A data flow source for "cookie injection" vulnerabilities.
   */
  abstract class Source extends DataFlow::Node { }

  /**
   * A data flow sink for "cookie injection" vulnerabilities.
   */
  abstract class Sink extends DataFlow::Node { }

  /**
   * A sanitizer for "cookie injection" vulnerabilities.
   */
  abstract class Sanitizer extends DataFlow::Node { }

  /**
   * A source of remote user input, considered as a flow source.
   */
  class RemoteFlowSourceAsSource extends Source, RemoteFlowSource { }

  /**
   * A write to a cookie, considered as a sink.
   */
  class CookieWriteSink extends Sink {
    CookieWriteSink() {
      exists(Http::Server::CookieWrite cw |
        this = [cw.getNameArg(), cw.getValueArg(), cw.getHeaderArg()]
      )
    }
  }
}
