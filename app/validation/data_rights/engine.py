"""Composed data-subject-rights validation engine (Pasal 22 UU PDP).

Assembles the per-right mixins onto the shared base. Each right lives in its
own module; this file only wires them together and runs the full assessment.
"""

from __future__ import annotations

from app.validation.data_rights.access import RightToAccessMixin
from app.validation.data_rights.base import DataRightsTestResult, _DataRightsBase
from app.validation.data_rights.forgotten import RightToBeForgottenMixin
from app.validation.data_rights.rectification import RightToRectificationMixin

__all__ = ["DataRightsValidationEngine", "DataRightsTestResult"]


class DataRightsValidationEngine(
    RightToBeForgottenMixin,
    RightToAccessMixin,
    RightToRectificationMixin,
    _DataRightsBase,
):
    """Validates data subject rights implementation per Pasal 22 UU PDP."""

    async def assess_all_rights(
        self,
        target: str,
        auth_headers: dict[str, str] | None = None,
    ) -> dict:
        """
        Run all data rights tests and return combined assessment.

        Executes tests for the right to be forgotten, right to access,
        and right to rectification, then produces an overall compliance
        summary aligned with Pasal 22 UU PDP.
        """
        forgotten = await self.test_right_to_be_forgotten(target, auth_headers)
        access = await self.test_right_to_access(target, auth_headers)
        rectification = await self.test_right_to_rectification(target, auth_headers)

        scores = [forgotten.score, access.score, rectification.score]
        overall_score = sum(scores) / len(scores)
        overall_status = self._determine_status(overall_score)

        # Identify gaps
        gaps: list[str] = []
        if forgotten.score < 80:
            gaps.append(
                f"Right to be forgotten is not fully compliant (score: {forgotten.score:.0f}/100). "
                f"Status: {forgotten.status}."
            )
        if not forgotten.deletion_verified and forgotten.score >= 20:
            gaps.append("Data deletion could not be verified after request.")
        if access.score < 80:
            gaps.append(
                f"Right to access is not fully compliant (score: {access.score:.0f}/100). "
                f"Status: {access.status}."
            )
        if rectification.score < 80:
            gaps.append(
                f"Right to rectification is not fully compliant (score: {rectification.score:.0f}/100). "
                f"Status: {rectification.status}."
            )
        if not gaps:
            gaps.append(
                "No significant gaps identified in data subject rights implementation."
            )

        return {
            "overall_score": overall_score,
            "overall_status": overall_status,
            "right_to_be_forgotten": forgotten,
            "right_to_access": access,
            "right_to_rectification": rectification,
            "uu_pdp_pasal_22_compliance": {
                "status": overall_status,
                "score": overall_score,
                "gaps": gaps,
            },
        }
