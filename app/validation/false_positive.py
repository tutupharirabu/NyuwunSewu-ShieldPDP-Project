import difflib
import statistics
from dataclasses import dataclass

from app.validation.types import HttpObservation, ReductionDecision


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a[:8000], b[:8000]).ratio()


@dataclass(slots=True)
class SignalSet:
    status_changed: bool = False
    sql_error: bool = False
    boolean_delta: bool = False
    timing_delta: bool = False
    reflected_payload: bool = False
    sensitive_fields: bool = False
    auth_context_changed: bool = False
    authentication_bypass: bool = False


class FalsePositiveReducer:
    SOFT_404_MARKERS = (
        "not found",
        "page not found",
        "route not found",
        "does not exist",
        "cannot get",
        "no such endpoint",
    )

    def is_soft_404(self, observation: HttpObservation) -> bool:
        body = observation.body_sample.lower()
        return observation.status_code == 200 and any(marker in body for marker in self.SOFT_404_MARKERS)

    def timing_is_consistent(self, baseline_ms: list[float], candidate_ms: list[float]) -> bool:
        if len(candidate_ms) < 2 or not baseline_ms:
            return False
        baseline_median = statistics.median(baseline_ms)
        candidate_median = statistics.median(candidate_ms)
        baseline_jitter = statistics.pstdev(baseline_ms) if len(baseline_ms) > 1 else 0
        return candidate_median > max(2500.0, baseline_median + 2500.0 + baseline_jitter * 2)

    def reduce(
        self,
        baseline: HttpObservation,
        candidates: list[HttpObservation],
        signals: SignalSet,
        minimum_confidence: float = 70.0,
    ) -> ReductionDecision:
        if not candidates:
            return ReductionDecision(False, 0.0, 0.0, ["No candidate observations to validate"])

        reasoning: list[str] = []
        confidence = 0.0
        anomaly_score = 0.0

        if self.is_soft_404(baseline):
            return ReductionDecision(False, 0.0, 20.0, ["Baseline resembles a soft 404 response"])

        status_codes = {candidate.status_code for candidate in candidates}
        similarities = [similarity(baseline.body_sample, c.body_sample) for c in candidates]
        length_deltas = [
            abs(baseline.content_length - c.content_length) / max(baseline.content_length, 1)
            for c in candidates
        ]

        precise_auth_sqli_sequence = signals.sql_error and signals.authentication_bypass
        if len(status_codes) > 2 and not precise_auth_sqli_sequence:
            return ReductionDecision(False, 0.0, 80.0, ["Candidate responses were unstable across retries"])
        if len(status_codes) > 2 and precise_auth_sqli_sequence:
            reasoning.append(
                "Distinct error, success, and denial statuses corroborated the authentication SQL validation"
            )

        if signals.sql_error:
            confidence += 76
            reasoning.append("Database error signature was detected")
        if signals.boolean_delta:
            confidence += 74
            reasoning.append("Boolean payload produced a stable response delta")
        if signals.timing_delta:
            confidence += 78
            reasoning.append("Timing anomaly was consistent across retries")
        if signals.status_changed:
            confidence += 6
            reasoning.append("HTTP status changed under validation payload")
        if signals.reflected_payload:
            confidence -= 8
            anomaly_score += 10
            reasoning.append("Payload reflection reduced confidence")
        if signals.sensitive_fields:
            confidence += 76
            reasoning.append("Sensitive fields remained visible under altered authorization context")
        if signals.auth_context_changed:
            confidence += 20
            reasoning.append("Authorization context changed but protected content remained accessible")
        if signals.authentication_bypass:
            confidence += 92
            reasoning.append("Validation payload produced an authenticated-state transition")

        if not (
            signals.sql_error
            or signals.boolean_delta
            or signals.timing_delta
            or signals.authentication_bypass
            or signals.sensitive_fields
        ):
            confidence = min(confidence, 35.0)
            reasoning.append("Response differences without a precise validation signal were not trusted")

        if similarities and min(similarities) < 0.35 and not (
            signals.sql_error or signals.sensitive_fields or signals.authentication_bypass
        ):
            anomaly_score += 35
            confidence -= 10
            reasoning.append("Large body difference may indicate application instability")

        if any(delta > 0.8 for delta in length_deltas) and not (
            signals.sql_error or signals.authentication_bypass
        ):
            anomaly_score += 25
            reasoning.append("Extreme response length delta without a precise signal")

        confidence = max(0.0, min(99.0, confidence - anomaly_score * 0.15))
        if not reasoning:
            reasoning.append("No stable validation signal survived false-positive reduction")

        accepted = confidence >= minimum_confidence and anomaly_score < 70.0
        if not accepted:
            reasoning.append("Finding discarded because confidence did not meet the production threshold")

        return ReductionDecision(accepted, confidence, anomaly_score, reasoning)
