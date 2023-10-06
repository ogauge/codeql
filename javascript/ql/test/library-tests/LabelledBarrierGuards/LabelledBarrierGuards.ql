import javascript

class CustomFlowLabel extends DataFlow::FlowLabel {
  CustomFlowLabel() { this = "A" or this = "B" }
}

module TestConfig implements DataFlow::StateConfigSig {
  class FlowState = DataFlow::FlowLabel;

  predicate isSource(DataFlow::Node node, DataFlow::FlowLabel lbl) {
    node.(DataFlow::CallNode).getCalleeName() = "source" and
    lbl instanceof CustomFlowLabel
  }

  predicate isSink(DataFlow::Node node, DataFlow::FlowLabel lbl) {
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "sink" and
      node = call.getAnArgument() and
      lbl instanceof CustomFlowLabel
    )
  }

  additional predicate isBarrierGuard(DataFlow::BarrierGuardNode node) {
    node instanceof IsTypeAGuard or
    node instanceof IsSanitizedGuard
  }

  predicate isBarrier(DataFlow::Node node, DataFlow::FlowLabel lbl) {
    node = DataFlow::MakeLegacyBarrierGuardLabeled<isBarrierGuard/1>::getABarrierNode(lbl)
  }
}

module TestFlow = TaintTracking::GlobalWithState<TestConfig>;

class LegacyConfig extends TaintTracking::Configuration {
  LegacyConfig() { this = "LegacyConfig" }

  override predicate isSource(DataFlow::Node node, DataFlow::FlowLabel lbl) {
    TestConfig::isSource(node, lbl)
  }

  override predicate isSink(DataFlow::Node node, DataFlow::FlowLabel lbl) {
    TestConfig::isSink(node, lbl)
  }

  override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode node) {
    TestConfig::isBarrierGuard(node)
  }
}

/**
 * A condition that checks what kind of value the input is. Not enough to
 * sanitize the value, but later sanitizers only need to handle the relevant case.
 */
class IsTypeAGuard extends TaintTracking::LabeledSanitizerGuardNode, DataFlow::CallNode {
  IsTypeAGuard() { this.getCalleeName() = "isTypeA" }

  override predicate sanitizes(boolean outcome, Expr e, DataFlow::FlowLabel lbl) {
    this.blocksExpr(outcome, e, lbl)
  }

  predicate blocksExpr(boolean outcome, Expr e, DataFlow::FlowLabel lbl) {
    e = this.getArgument(0).asExpr() and
    (
      outcome = true and lbl = "B"
      or
      outcome = false and lbl = "A"
    )
  }
}

class IsSanitizedGuard extends TaintTracking::LabeledSanitizerGuardNode, DataFlow::CallNode {
  IsSanitizedGuard() { this.getCalleeName() = "sanitizeA" or this.getCalleeName() = "sanitizeB" }

  override predicate sanitizes(boolean outcome, Expr e, DataFlow::FlowLabel lbl) {
    this.blocksExpr(outcome, e, lbl)
  }

  predicate blocksExpr(boolean outcome, Expr e, DataFlow::FlowLabel lbl) {
    e = this.getArgument(0).asExpr() and
    outcome = true and
    (
      this.getCalleeName() = "sanitizeA" and lbl = "A"
      or
      this.getCalleeName() = "sanitizeB" and lbl = "B"
    )
  }
}

import testUtilities.LegacyDataFlowDiff::DataFlowDiff<TestFlow, LegacyConfig>

from DataFlow::Node source, DataFlow::Node sink
where TestFlow::flow(source, sink)
select source, sink
