import python
import semmle.python.ApiGraphs
import TlsLibraryModel

class PyOpenSSLContextCreation extends ContextCreation {
  override CallNode node;

  PyOpenSSLContextCreation() {
    this = API::moduleImport("OpenSSL").getMember("SSL").getMember("Context").getACall()
  }

  override string getProtocol() {
    exists(ControlFlowNode protocolArg, PyOpenSSL pyo |
      protocolArg in [node.getArg(0), node.getArgByName("method")]
    |
      protocolArg = [pyo.specific_version(result), pyo.unspecific_version(result)].asCfgNode()
    )
  }
}

class ConnectionCall extends ConnectionCreation {
  override CallNode node;

  ConnectionCall() {
    this = API::moduleImport("OpenSSL").getMember("SSL").getMember("Connection").getACall()
  }

  override DataFlow::CfgNode getContext() {
    result.getNode() in [node.getArg(0), node.getArgByName("context")]
  }
}

// This cannot be used to unrestrict,
// see https://www.pyopenssl.org/en/stable/api/ssl.html#OpenSSL.SSL.Context.set_options
class SetOptionsCall extends ProtocolRestriction {
  override CallNode node;

  SetOptionsCall() { node.getFunction().(AttrNode).getName() = "set_options" }

  override DataFlow::CfgNode getContext() {
    result.getNode() = node.getFunction().(AttrNode).getObject()
  }

  override ProtocolVersion getRestriction() {
    API::moduleImport("OpenSSL").getMember("SSL").getMember("OP_NO_" + result).getAUse().asCfgNode() in [
        node.getArg(0), node.getArgByName("options")
      ]
  }
}

class UnspecificPyOpenSSLContextCreation extends PyOpenSSLContextCreation, UnspecificContextCreation {
  UnspecificPyOpenSSLContextCreation() { library = "pyOpenSSL" }
}

class PyOpenSSL extends TlsLibrary {
  PyOpenSSL() { this = "pyOpenSSL" }

  override string specific_version_name(ProtocolVersion version) { result = version + "_METHOD" }

  override string unspecific_version_name(ProtocolFamily family) {
    // `"TLS_METHOD"` is not actually available in pyOpenSSL yet, but should be coming soon..
    result = family + "_METHOD"
  }

  override API::Node version_constants() { result = API::moduleImport("OpenSSL").getMember("SSL") }

  override ContextCreation default_context_creation() { none() }

  override ContextCreation specific_context_creation() {
    result instanceof PyOpenSSLContextCreation
  }

  override DataFlow::CfgNode insecure_connection_creation(ProtocolVersion version) { none() }

  override ConnectionCreation connection_creation() { result instanceof ConnectionCall }

  override ProtocolRestriction protocol_restriction() { result instanceof SetOptionsCall }

  override ProtocolUnrestriction protocol_unrestriction() {
    result instanceof UnspecificPyOpenSSLContextCreation
  }
}
