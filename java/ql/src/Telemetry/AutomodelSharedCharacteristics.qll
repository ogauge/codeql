float maximalConfidence() { result = 1.0 }

float highConfidence() { result = 0.9 }

float mediumConfidence() { result = 0.6 }

/**
 * A specification of how to  instantiate the shared characteristics for a given candidate class.
 *
 * The `CandidateSig` implementation specifies a type to use for Endpoints (eg., `ParameterNode`), as well as a type
 * to label endpoint classes (the `EndpointType`). One of the endpoint classes needs to be a 'negative' class, meaning
 *   "not any of the other known endpoint types".
 */
signature module CandidateSig {
  /**
   * An endpoint is a potential candidate for modelling. This will typically be bound to the language's
   * DataFlow node class, or a subtype thereof.
   */
  class Endpoint;

  /**
   * A related location for an endpoint. This will typically be bound to the supertype of all AST nodes.
   */
  class RelatedLocation;

  /**
   * A class label for an endpoint.
   */
  class EndpointType;

  /**
   * An EndpointType that denotes the absence of any sink.
   */
  class NegativeEndpointType extends EndpointType;

  RelatedLocation toRelatedLocation(Endpoint e);

  /**
   * Defines what labels are known, and what endpoint type they correspond to.
   */
  predicate isKnownLabel(string label, string humanReadableLabel, EndpointType type);

  /**
   * Should hold for any endpoint that is a flow sanitizer.
   */
  predicate isSanitizer(Endpoint e, EndpointType t);

  /**
   * Should hold for any endpoint that is a sink of the given (known or unknown) label.
   */
  predicate isSink(Endpoint e, string label);

  /**
   * Should hold for any endpoint that is known to not be any sink.
   */
  predicate isNeutral(Endpoint e);

  /**
   * Holds if `e` has the given metadata.
   *
   * This is a helper function to extract and export needed information about each endpoint in the sink candidate query
   * as well as the queries that extract positive and negative examples for the prompt / training set. The metadata is
   * extracted as a string in the format of a Python dictionary, eg.:
   *
   *     `{'Package': 'com.foo.util', 'Type': 'HelperClass', ... }`.
   *
   * The meta data will be passed on to the machine learning code by the extraction queries.
   */
  predicate hasMetadata(Endpoint e, string metadata);

  RelatedLocation getRelatedLocation(Endpoint e, string name);
}

/**
 * A set of shared characteristics for a given candidate class.
 *
 * This module is language-agnostic, although the `CandidateSig` module will be language-specific.
 *
 * The language specific implementation can also further extend the behavior of this module by adding additional
 *   implementations of endpoint characteristics exported by this module.
 */
module SharedCharacteristics<CandidateSig Candidate> {
  predicate isSink = Candidate::isSink/2;

  predicate isNeutral = Candidate::isNeutral/1;

  /**
   * Holds if `sink` is a known sink of type `endpointType`.
   */
  predicate isKnownSink(Candidate::Endpoint sink, Candidate::EndpointType endpointType) {
    // If the list of characteristics includes positive indicators with maximal confidence for this class, then it's a
    // known sink for the class.
    not endpointType instanceof Candidate::NegativeEndpointType and
    exists(EndpointCharacteristic characteristic |
      characteristic.appliesToEndpoint(sink) and
      characteristic.hasImplications(endpointType, true, maximalConfidence())
    )
  }

  /**
   * Holds if the candidate sink `candidateSink` should be considered as a possible sink of type `sinkType`, and
   * classified by the ML model. A candidate sink is a node that cannot be excluded from `sinkType` based on its
   * characteristics.
   */
  predicate isSinkCandidate(Candidate::Endpoint candidateSink, Candidate::EndpointType sinkType) {
    not sinkType instanceof Candidate::NegativeEndpointType and
    not exists(getAReasonSinkExcluded(candidateSink, sinkType))
  }

  predicate hasMetadata = Candidate::hasMetadata/2;

  /**
   * If it exists, gets a related location for a given endpoint or candidate.
   * If it doesn't exist, returns the candidate itself as a 'null' value.
   */
  bindingset[name]
  Candidate::RelatedLocation getRelatedLocationOrCandidate(Candidate::Endpoint e, string name) {
    if exists(Candidate::getRelatedLocation(e, name))
    then result = Candidate::getRelatedLocation(e, name)
    else result = Candidate::toRelatedLocation(e)
  }

  /**
   * Gets the list of characteristics that cause `candidateSink` to be excluded as an effective sink for a given sink
   * type.
   */
  EndpointCharacteristic getAReasonSinkExcluded(
    Candidate::Endpoint candidateSink, Candidate::EndpointType sinkType
  ) {
    // An endpoint is a sink candidate if none of its characteristics give much indication whether or not it is a sink.
    not sinkType instanceof Candidate::NegativeEndpointType and
    result.appliesToEndpoint(candidateSink) and
    // Exclude endpoints that have a characteristic that implies they're not sinks for _any_ sink type.
    (
      exists(float confidence |
        confidence >= mediumConfidence() and
        result.hasImplications(any(Candidate::NegativeEndpointType t), true, confidence)
      )
      or
      // Exclude endpoints that have a characteristic that implies they're not sinks for _this particular_ sink type.
      exists(float confidence |
        confidence >= mediumConfidence() and
        result.hasImplications(sinkType, false, confidence)
      )
    )
  }

  /**
   * A set of characteristics that a particular endpoint might have. This set of characteristics is used to make decisions
   * about whether to include the endpoint in the training set and with what label, as well as whether to score the
   * endpoint at inference time.
   */
  abstract class EndpointCharacteristic extends string {
    /**
     * Holds when the string matches the name of the characteristic, which should describe some characteristic of the
     * endpoint that is meaningful for determining whether it's a sink and if so of which type
     */
    bindingset[this]
    EndpointCharacteristic() { any() }

    /**
     * Holds for parameters that have this characteristic. This predicate contains the logic that applies characteristics
     * to the appropriate set of dataflow parameters.
     */
    abstract predicate appliesToEndpoint(Candidate::Endpoint n);

    /**
     * This predicate describes what the characteristic tells us about an endpoint.
     *
     * Params:
     * endpointType: The sink/source type.
     * isPositiveIndicator: If true, this characteristic indicates that this endpoint _is_ a member of the class; if
     * false, it indicates that it _isn't_ a member of the class.
     * confidence: A float in [0, 1], which tells us how strong an indicator this characteristic is for the endpoint
     * belonging / not belonging to the given class. A confidence near zero means this characteristic is a very weak
     * indicator of whether or not the endpoint belongs to the class. A confidence of 1 means that all endpoints with
     * this characteristic definitively do/don't belong to the class.
     */
    abstract predicate hasImplications(
      Candidate::EndpointType endpointType, boolean isPositiveIndicator, float confidence
    );

    /** Indicators with confidence at or above this threshold are considered to be high-confidence indicators. */
    final float getHighConfidenceThreshold() { result = 0.8 }
  }

  /**
   * A high-confidence characteristic that indicates that an endpoint is a sink of a specified type. These endpoints can
   * be used as positive samples for training or for a few-shot prompt.
   */
  abstract class SinkCharacteristic extends EndpointCharacteristic {
    bindingset[this]
    SinkCharacteristic() { any() }

    abstract Candidate::EndpointType getSinkType();

    final override predicate hasImplications(
      Candidate::EndpointType endpointType, boolean isPositiveIndicator, float confidence
    ) {
      endpointType = this.getSinkType() and
      isPositiveIndicator = true and
      confidence = maximalConfidence()
    }
  }

  /**
   * A high-confidence characteristic that indicates that an endpoint is not a sink of any type. These endpoints can be
   * used as negative samples for training or for a few-shot prompt.
   */
  abstract class NotASinkCharacteristic extends EndpointCharacteristic {
    bindingset[this]
    NotASinkCharacteristic() { any() }

    override predicate hasImplications(
      Candidate::EndpointType endpointType, boolean isPositiveIndicator, float confidence
    ) {
      endpointType instanceof Candidate::NegativeEndpointType and
      isPositiveIndicator = true and
      confidence = highConfidence()
    }
  }

  /**
   * A medium-confidence characteristic that indicates that an endpoint is unlikely to be a sink of any type. These
   * endpoints can be excluded from scoring at inference time, both to save time and to avoid false positives. They should
   * not, however, be used as negative samples for training or for a few-shot prompt, because they may include a small
   * number of sinks.
   */
  abstract class LikelyNotASinkCharacteristic extends EndpointCharacteristic {
    bindingset[this]
    LikelyNotASinkCharacteristic() { any() }

    override predicate hasImplications(
      Candidate::EndpointType endpointType, boolean isPositiveIndicator, float confidence
    ) {
      endpointType instanceof Candidate::NegativeEndpointType and
      isPositiveIndicator = true and
      confidence = mediumConfidence()
    }
  }

  /**
   * A characteristic that indicates not necessarily that an endpoint is not a sink, but rather that it is not a sink
   * that's interesting to model in the standard Java libraries. These filters should be removed when extracting sink
   * candidates within a user's codebase for customized modeling.
   *
   * These endpoints should not be used as negative samples for training or for a few-shot prompt, because they are not
   * necessarily non-sinks.
   */
  abstract class UninterestingToModelCharacteristic extends EndpointCharacteristic {
    bindingset[this]
    UninterestingToModelCharacteristic() { any() }

    override predicate hasImplications(
      Candidate::EndpointType endpointType, boolean isPositiveIndicator, float confidence
    ) {
      endpointType instanceof Candidate::NegativeEndpointType and
      isPositiveIndicator = true and
      confidence = mediumConfidence()
    }
  }

  /**
   * Contains default implementations that are derived solely from the `CandidateSig` implementation.
   */
  private module DefaultCharacteristicImplementations {
    /**
     * Endpoints identified as sinks by the `CandidateSig` implementation are sinks with maximal confidence.
     */
    private class KnownSinkCharacteristic extends SinkCharacteristic {
      string madLabel;
      Candidate::EndpointType endpointType;

      KnownSinkCharacteristic() { Candidate::isKnownLabel(madLabel, this, endpointType) }

      override predicate appliesToEndpoint(Candidate::Endpoint e) { Candidate::isSink(e, madLabel) }

      override Candidate::EndpointType getSinkType() { result = endpointType }
    }

    /**
     * A negative characteristic that indicates that an endpoint was manually modeled as a neutral model.
     */
    private class NeutralModelCharacteristic extends NotASinkCharacteristic {
      NeutralModelCharacteristic() { this = "known non-sink" }

      override predicate appliesToEndpoint(Candidate::Endpoint e) { Candidate::isNeutral(e) }
    }

    /**
     * A negative characteristic that indicates that an endpoint is not part of the source code for the project being
     * analyzed.
     */
    private class IsSanitizerCharacteristic extends NotASinkCharacteristic {
      IsSanitizerCharacteristic() { this = "external" }

      override predicate appliesToEndpoint(Candidate::Endpoint e) { Candidate::isSanitizer(e, _) }
    }
  }
}
