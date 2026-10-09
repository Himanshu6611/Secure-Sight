# Confidence engine 6.0.0

Confidence is a **provisional evidence-quality index**, not a calibrated probability that the verdict is correct. Every assessment says confidence_calibrated=false. It is distinct from URL phishing probability, observed risk, coverage and completeness.

## Formula

Using values in 0–1:

    raw confidence = 100 × (
        0.55 × weighted evidence coverage
      + 0.20 × mean selected measurement quality
      + 0.15 × agreement
      + 0.10 × calibrated-model decisiveness
    )
    final confidence = min(coverage_percent, max(0, raw confidence − contradiction penalty))

Decisiveness = 2 × abs(p−0.5), only for a validated model whose calibration method is explicitly sigmoid or isotonic. Missing/unconfirmed calibration gives no model confidence component.

Agreement is 1 for at least two independent risk sources without contradictions; 0.5 for a completed baseline without contradictions; otherwise 0. This is a policy index, not statistically established source independence. URL/model share a source, and all static-page cues share a source.

Selected source qualities come from configuration, capped by provider confidence. Missing sources are not selected and receive no quality. Evidence coverage bounds confidence; most missing inputs therefore cannot become a high-confidence result.

One critical contradiction applies a 25-point penalty rather than multiplying penalties for correlated expressions of the same conflict. Contradictions are separately retained, and any of them prevents PHISHING.

## Contradictions

- Strong calibrated URL-model estimate with reliable SAFE provider report.
- Low calibrated URL-only probability with confirmed malicious reputation or corroborated cross-domain credential/brand observations.
- Reliable SAFE provider report with corroborated harvesting observations.

A long-established domain or valid certificate is not asserted to prove safety; compromised established sites exist. Contrary provider/observed evidence is represented rather than silently discarded.

The audit includes the four weighted terms, penalty, uncapped total and coverage cap. Bounds 0 and 100 are directly tested, as are missing data, high agreement and contradictions.

## Validation status

17,037 labeled development rows contain lexical/model observations only. They correctly remain UNKNOWN with confidence at most 30. No definitive predictions exist in that evaluation, so confidence-bucket correctness is null, not manufactured as 100%.

Representative full-intelligence labeled snapshots are still required to measure confidence bucket reliability, adjust coefficients and justify calibrated confidence. This release must not describe the confidence field as a safety percentage or calibrated correctness probability.
