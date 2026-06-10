from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from typing import Any

import aiohttp
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.classifier import EndpointClassifier
from app.compliance.engine import ComplianceMappingEngine
from app.core.config import get_settings
from app.core.security import utcnow
from app.database.session import get_sessionmaker
from app.evidence.engine import EvidenceEngine
from app.models import (
    ComplianceMapping,
    Endpoint,
    Evidence,
    Finding,
    Policy,
    Project,
    RemediationTracking,
    Scan,
    ScanStatus,
    Target,
    User,
)
from app.pii_detection.engine import PIIDetectionEngine
from app.recon import AsyncReconEngine, CrawledEndpoint
from app.reporting.engine import ReportingEngine
from app.services.audit_service import AuditService
from app.services.discovery_validation import DiscoveryValidationService
from app.services.policy_engine import PolicyEngine, ScanPolicyConfig
from app.services.risk_engine import RiskPrioritizationEngine
from app.utils.redaction import redact_text, sanitize_json
from app.validation.access_matrix import AccessControlMatrixValidator, RoleContext
from app.validation.api_exposure import SafeAPIExposureValidator
from app.validation.auth import AuthValidator
from app.validation.bola import BOLAValidator
from app.validation.cors import CorsValidationEngine
from app.validation.data_rights import DataRightsValidationEngine
from app.validation.exploit_chains import ActiveExploitChainValidator
from app.validation.path_traversal import PathTraversalValidator
from app.validation.reflected_html import ReflectedHTMLInjectionValidator
from app.validation.sqli import LightweightSQLiValidator
from app.validation.types import ValidationResult
from app.validation.username_enumeration import UsernameEnumerationValidator

logger = logging.getLogger(__name__)
from app.services.scan_crud import ScanService
from app.services.scan_reporting import _ReportingMixin
from app.services.scan_scoring import _ScoringMixin

logger = logging.getLogger(__name__)


async def run_scan_by_id(
    scan_id: str, runtime_options: dict[str, Any] | None = None
) -> None:
    runtime_options = runtime_options or {}
    async with get_sessionmaker()() as session:
        runner = ScanRunner(session)
        await runner.run(scan_id, runtime_options)


class ScanRunner(_ScoringMixin, _ReportingMixin):
    def __init__(self, session: AsyncSession):
        self.session = session
        self.classifier = EndpointClassifier()
        self.pii = PIIDetectionEngine()
        self.compliance = ComplianceMappingEngine()
        self.risk = RiskPrioritizationEngine()
        self.evidence = EvidenceEngine()
        self.reporting = ReportingEngine()
        self.discovery = DiscoveryValidationService()
        self.api_exposure = SafeAPIExposureValidator()

    async def run(self, scan_id: str, runtime_options: dict[str, Any]) -> None:
        scan = await self.session.get(Scan, scan_id)
        if scan is None:
            return
        try:
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = utcnow()
            scan.stats = self._progress(
                phase="Target Validation",
                progress=3,
                message="Validating target scope and policy",
            )
            await self.session.commit()

            target = await self.session.get(Target, scan.target_id)
            policy_model = await self.session.get(Policy, scan.policy_id)
            if target is None or policy_model is None:
                raise RuntimeError("Scan target or policy is missing")

            policy = PolicyEngine(self._policy_config(policy_model))
            cookie_jar = aiohttp.CookieJar(unsafe=get_settings().allow_private_targets)
            recon = AsyncReconEngine(
                base_url=target.base_url,
                allowed_domains=target.allowed_domains,
                policy=policy,
                headers=runtime_options.get("primary_headers"),
                cookie_jar=cookie_jar,
                initial_paths=runtime_options.get("initial_paths"),
                credential_auth=runtime_options.get("credential_auth"),
            )
            target_decision = await recon.scope_guard.explain_url_allowed(
                target.base_url
            )
            if not target_decision.allowed:
                await self._fail_no_coverage(
                    scan,
                    reason=target_decision.reason,
                    diagnostics={"blocked_target": asdict(target_decision)},
                )
                return

            credentialed_recon = bool(runtime_options.get("credential_auth"))
            scan.stats = self._progress(
                phase="Guest Recon" if credentialed_recon else "Recon",
                progress=10,
                message=(
                    "Mapping guest-accessible routes before login"
                    if credentialed_recon
                    else "Crawling reachable in-scope routes"
                ),
            )
            await self.session.commit()
            recon_progress = asyncio.create_task(
                self._recon_progress_loop(scan.id, recon, policy)
            )
            try:
                endpoints = await recon.crawl()
            finally:
                recon_progress.cancel()
                await asyncio.gather(recon_progress, return_exceptions=True)
            await self.session.refresh(scan)
            if scan.stop_requested:
                scan.status = ScanStatus.STOPPED.value
                scan.finished_at = utcnow()
                scan.stats = {
                    **(scan.stats or {}),
                    "phase": "Stopped",
                    "message": "Stopped by user during reconnaissance",
                    "coverage_status": "stopped",
                }
                await self.session.commit()
                return
            reachable_endpoints = [
                endpoint for endpoint in endpoints if endpoint.status_code is not None
            ]
            if not reachable_endpoints:
                await self._fail_no_coverage(
                    scan,
                    reason=(
                        "Recon did not receive any reachable in-scope HTTP responses. "
                        "Check target URL, authentication headers/cookies, scope boundaries, private target settings, and excluded paths."
                    ),
                    diagnostics=recon.diagnostics,
                )
                return

            scan.stats = self._progress(
                phase="Endpoint Classification",
                progress=25,
                message="Recon complete; classifying endpoints",
                endpoints_discovered=len(reachable_endpoints),
                parameters_discovered=recon.diagnostics.get("parameters_discovered", 0),
                diagnostics=recon.diagnostics,
            )
            await self.session.commit()

            validation_options = {**runtime_options}
            if recon.authenticated_headers:
                validation_options["primary_headers"] = {
                    **(runtime_options.get("primary_headers") or {}),
                    **recon.authenticated_headers,
                }
            if recon.authenticated_cookie_header:
                validation_options["primary_headers"] = {
                    **(validation_options.get("primary_headers") or {}),
                    "cookie": recon.authenticated_cookie_header,
                }
            validation_options["_reachable_endpoints"] = reachable_endpoints

            timeout = aiohttp.ClientTimeout(
                total=get_settings().request_timeout_seconds
            )
            connector = aiohttp.TCPConnector(
                limit=30, limit_per_host=6, ttl_dns_cache=300
            )
            async with (
                aiohttp.ClientSession(
                    timeout=timeout,
                    connector=connector,
                    cookie_jar=cookie_jar,
                    headers={"user-agent": get_settings().user_agent},
                ) as http_session,
                aiohttp.ClientSession(
                    timeout=timeout,
                    connector=aiohttp.TCPConnector(
                        limit=12, limit_per_host=4, ttl_dns_cache=300
                    ),
                    cookie_jar=aiohttp.DummyCookieJar(),
                    headers={"user-agent": get_settings().user_agent},
                ) as anonymous_session,
            ):
                for index, crawled in enumerate(reachable_endpoints, start=1):
                    await self.session.refresh(scan)
                    if scan.stop_requested:
                        scan.status = ScanStatus.STOPPED.value
                        scan.finished_at = utcnow()
                        scan.stats = {
                            **(scan.stats or {}),
                            "message": "Stopped by user",
                        }
                        await self.session.commit()
                        return
                    endpoint = await self._persist_endpoint(scan, target, crawled)
                    # Do not hold a database write transaction while validation performs network I/O.
                    await self.session.commit()
                    await self._run_discovery_validations(
                        scan, target, endpoint, crawled, policy
                    )
                    await self._detect_pii_findings(scan, target, endpoint, crawled)
                    await self._run_authentication_submission_validations(
                        scan,
                        target,
                        endpoint,
                        crawled,
                        policy,
                        recon,
                        validation_options,
                    )
                    await self._run_validators(
                        scan,
                        target,
                        endpoint,
                        crawled,
                        policy,
                        recon,
                        http_session,
                        anonymous_session,
                        validation_options,
                    )
                    current_finding_count = await self.session.scalar(
                        select(func.count(Finding.id)).where(Finding.scan_id == scan.id)
                    )
                    scan.stats = self._progress(
                        phase="Validation",
                        progress=25
                        + int((index / max(len(reachable_endpoints), 1)) * 55),
                        message="Running safe validation engines",
                        endpoints_discovered=len(reachable_endpoints),
                        validated_endpoints=index,
                        parameters_discovered=recon.diagnostics.get(
                            "parameters_discovered", 0
                        ),
                        findings_discovered=current_finding_count or 0,
                        active_validations=self._active_validations(policy),
                        diagnostics=recon.diagnostics,
                    )
                    await self.session.commit()

            # Run data subject rights assessment (Pasal 22 UU PDP)
            scan.stats = self._progress(
                phase="Data Rights Validation",
                progress=85,
                message="Testing Right to be Forgotten, Access, and Rectification",
            )
            await self.session.commit()
            await self._run_data_rights_validation(
                scan, target, recon, validation_options, policy
            )

            await self._generate_default_reports(scan)
            scan.status = ScanStatus.COMPLETED.value
            scan.finished_at = utcnow()
            scan.stats = await self._scan_stats(scan, phase="Completed", progress=100)
            await self.session.commit()
            await self._dispatch_webhooks(scan, "scan.completed")
        except Exception as exc:
            scan.status = ScanStatus.FAILED.value
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = utcnow()
            scan.stats = {
                **(scan.stats or {}),
                "phase": "Failed",
                "progress_percentage": 100,
                "message": scan.error,
                "coverage_status": "failed",
            }
            await self.session.commit()
            await self._dispatch_webhooks(scan, "scan.failed")
            raise

    def _policy_config(self, model: Policy) -> ScanPolicyConfig:
        return ScanPolicyConfig(
            max_requests_per_second=model.max_requests_per_second,
            allow_sqli_validation=model.allow_sqli_validation,
            allow_auth_validation=model.allow_auth_validation,
            allow_timing_validation=model.allow_timing_validation,
            excluded_paths=model.excluded_paths,
            forbidden_paths=model.forbidden_paths,
            scope_boundaries=model.scope_boundaries,
            max_depth=model.max_depth,
            max_pages=model.max_pages,
        )

    async def _recon_progress_loop(
        self,
        scan_id: str,
        recon: AsyncReconEngine,
        policy: PolicyEngine,
    ) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        while True:
            await asyncio.sleep(1.0)
            async with get_sessionmaker()() as progress_session:
                scan = await progress_session.get(Scan, scan_id)
                if scan is None:
                    return
                if scan.stop_requested:
                    recon.request_stop()
                    return
                elapsed = loop.time() - started
                context = str(recon.diagnostics.get("current_context") or "guest")
                context_count = 2 if recon.credential_auth else 1
                crawl_budget = max(
                    4.0, float(policy.policy.max_depth + 1) * 4.0 * context_count
                )
                elapsed_ratio = min(1.0, elapsed / crawl_budget)
                discovery_ratio = min(
                    1.0,
                    (len(recon.results) + max(0, len(recon.visited) - 1))
                    / max(1.0, min(float(policy.policy.max_pages), 100.0)),
                )
                recon_ratio = max(elapsed_ratio * 0.85, discovery_ratio)
                scan.stats = self._progress(
                    phase="Authenticated Recon"
                    if context == "authenticated"
                    else "Guest Recon",
                    progress=10 + int(min(0.98, recon_ratio) * 14),
                    message=(
                        "Crawling routes available after authenticated session establishment"
                        if context == "authenticated"
                        else "Mapping guest-accessible routes before login"
                    ),
                    endpoints_discovered=len(recon.results),
                    parameters_discovered=recon.diagnostics.get(
                        "parameters_discovered", 0
                    ),
                    diagnostics=recon.diagnostics,
                    visited_urls=len(recon.visited),
                )
                await progress_session.commit()

    async def _persist_endpoint(
        self, scan: Scan, target: Target, crawled: CrawledEndpoint
    ) -> Endpoint:
        classifications = self.classifier.classify(
            crawled.url, crawled.method, crawled.forms
        )
        endpoint_risk = max((item.risk_score for item in classifications), default=0.0)
        endpoint = Endpoint(
            organization_id=scan.organization_id,
            project_id=scan.project_id,
            target_id=target.id,
            scan_id=scan.id,
            url=crawled.url,
            method=crawled.method,
            normalized_path=crawled.normalized_path,
            status_code=crawled.status_code,
            title=crawled.title,
            content_type=crawled.content_type,
            query_parameters=crawled.query_parameters,
            forms=sanitize_json(crawled.forms),
            tech_stack=crawled.tech_stack,
            classifications=[
                {
                    "classification": item.classification,
                    "confidence": item.confidence,
                    "risk": item.risk,
                    "risk_score": item.risk_score,
                    "reasoning": item.reasoning,
                }
                for item in classifications
            ],
            risk_score=endpoint_risk,
        )
        self.session.add(endpoint)
        await self.session.flush()
        return endpoint

    async def _detect_pii_findings(
        self, scan: Scan, target: Target, endpoint: Endpoint, crawled: CrawledEndpoint
    ) -> None:
        detections = self.pii.detect(crawled.response_body_sample)
        material = [item for item in detections if item.confidence >= 70]
        if not material:
            return
        max_confidence = max(item.confidence for item in material)
        pii_types = sorted({item.pii_type for item in material})
        result = ValidationResult(
            finding_type="pii_exposure",
            title="PII Exposure Detected in Endpoint Response",
            severity="high"
            if any(item.sensitivity == "HIGH" for item in material)
            else "medium",
            confidence=max_confidence,
            endpoint=endpoint.url,
            description="The response contained personal data or secret-like identifiers.",
            reasoning=[reason for item in material for reason in item.reasoning],
            evidence={
                "validation_mode": "pii_format_context_validation",
                "pii_types": pii_types,
                "detections": [
                    {
                        "type": item.pii_type,
                        "sensitivity": item.sensitivity,
                        "confidence": item.confidence,
                        "excerpt": item.excerpt,
                    }
                    for item in material[:20]
                ],
            },
            remediation=(
                "Minimize response data, redact sensitive fields by default, and enforce field-level "
                "authorization for personal data."
            ),
            pii_types=pii_types,
        )
        await self._persist_finding(scan, target, endpoint, result, crawled)

    async def _run_discovery_validations(
        self,
        scan: Scan,
        target: Target,
        endpoint: Endpoint,
        crawled: CrawledEndpoint,
        policy: PolicyEngine,
    ) -> None:
        results = [
            self.discovery.internal_api_finding(crawled),
            self.discovery.segmentation_finding(crawled),
        ]
        if policy.is_validation_allowed("auth"):
            results.extend(self.api_exposure.findings(crawled))
        for result in results:
            if result:
                await self._persist_finding(scan, target, endpoint, result, crawled)

    async def _run_authentication_submission_validations(
        self,
        scan: Scan,
        target: Target,
        endpoint: Endpoint,
        crawled: CrawledEndpoint,
        policy: PolicyEngine,
        recon: AsyncReconEngine,
        runtime_options: dict[str, Any],
    ) -> None:
        observation = recon.authentication_observation
        if (
            not policy.is_validation_allowed("auth")
            or runtime_options.get("_authentication_submission_checked")
            or observation is None
            or endpoint.normalized_path != observation.normalized_path
        ):
            return
        runtime_options["_authentication_submission_checked"] = True
        result = self.api_exposure.authentication_cookie_protection(observation)
        if result:
            await self._persist_finding(scan, target, endpoint, result, crawled)

    async def _run_validators(
        self,
        scan: Scan,
        target: Target,
        endpoint: Endpoint,
        crawled: CrawledEndpoint,
        policy: PolicyEngine,
        recon: AsyncReconEngine,
        http_session: aiohttp.ClientSession,
        anonymous_session: aiohttp.ClientSession,
        runtime_options: dict[str, Any],
    ) -> None:
        primary_headers = runtime_options.get("primary_headers") or {}
        secondary_headers = runtime_options.get("secondary_headers") or {}
        contexts = self._role_contexts(runtime_options)

        auth_validator = AuthValidator(policy, recon.scope_guard, recon.rate_limiter)
        if not runtime_options.get("_jwt_checked"):
            for jwt_result in auth_validator.inspect_jwt(primary_headers):
                await self._persist_finding(scan, target, endpoint, jwt_result, crawled)
            runtime_options["_jwt_checked"] = True

        validators = [
            LightweightSQLiValidator(
                policy, recon.scope_guard, recon.rate_limiter
            ).validate(crawled, http_session, primary_headers, anonymous_session),
            PathTraversalValidator(
                policy, recon.scope_guard, recon.rate_limiter
            ).validate(crawled, http_session, primary_headers),
            ReflectedHTMLInjectionValidator(
                policy, recon.scope_guard, recon.rate_limiter
            ).validate(crawled, http_session, primary_headers),
            BOLAValidator(policy, recon.scope_guard, recon.rate_limiter).validate(
                crawled, http_session, primary_headers, secondary_headers
            ),
            auth_validator.validate_missing_authorization(
                crawled, http_session, primary_headers, anonymous_session
            ),
            AccessControlMatrixValidator(
                policy, recon.scope_guard, recon.rate_limiter
            ).validate(crawled, http_session, contexts, anonymous_session),
            CorsValidationEngine(
                policy, recon.scope_guard, recon.rate_limiter
            ).validate(crawled, anonymous_session),
        ]
        exploit_options = runtime_options.get("exploit_chains") or {}
        if exploit_options.get("enabled") and not runtime_options.get(
            "_exploit_chains_checked"
        ):
            runtime_options["_exploit_chains_checked"] = True
            validators.append(
                ActiveExploitChainValidator(
                    policy, recon.scope_guard, recon.rate_limiter
                ).validate(
                    crawled,
                    http_session,
                    anonymous_session,
                    primary_headers,
                    runtime_options.get("credential_auth"),
                    exploit_options,
                    recon.authentication_observation,
                    runtime_options.get("_reachable_endpoints"),
                )
            )
        credentials = runtime_options.get("credential_auth") or {}
        if not runtime_options.get(
            "_username_enumeration_checked"
        ) and crawled.normalized_path.lower().rstrip("/") in {
            "/login",
            "/signin",
            "/sign-in",
            "/session",
        }:
            runtime_options["_username_enumeration_checked"] = True
            validators.append(
                UsernameEnumerationValidator(
                    policy, recon.scope_guard, recon.rate_limiter
                ).validate(
                    crawled,
                    anonymous_session,
                    credentials.get("username"),
                )
            )
        if not runtime_options.get(
            "_jwt_integrity_checked"
        ) and auth_validator.is_privilege_endpoint(crawled):
            runtime_options["_jwt_integrity_checked"] = True
            validators.append(
                auth_validator.validate_tampered_privilege_claim(
                    crawled,
                    anonymous_session,
                    primary_headers,
                )
            )
        results = await asyncio.gather(*validators, return_exceptions=True)
        for result in results:
            if isinstance(result, ValidationResult):
                await self._persist_finding(scan, target, endpoint, result, crawled)
            elif (
                isinstance(result, tuple)
                and result
                and isinstance(result[0], ValidationResult)
            ):
                await self._persist_finding(scan, target, endpoint, result[0], crawled)
            elif isinstance(result, list):
                for item in result:
                    if isinstance(item, ValidationResult):
                        await self._persist_finding(
                            scan, target, endpoint, item, crawled
                        )
            elif isinstance(result, Exception):
                recon.diagnostics.setdefault("validation_errors", []).append(
                    {
                        "endpoint": crawled.url,
                        "error": type(result).__name__,
                        "detail": str(result)[:240],
                    }
                )

    def _role_contexts(self, runtime_options: dict[str, Any]) -> list[RoleContext]:
        candidates: list[tuple[str, dict[str, str]]] = [
            ("primary", runtime_options.get("primary_headers") or {}),
            ("secondary", runtime_options.get("secondary_headers") or {}),
            ("admin", runtime_options.get("admin_headers") or {}),
            ("auditor", runtime_options.get("auditor_headers") or {}),
        ]
        for role, headers in (runtime_options.get("custom_role_headers") or {}).items():
            if isinstance(headers, dict):
                candidates.append((role, headers))
        contexts = [
            RoleContext(name, headers) for name, headers in candidates if headers
        ]
        if runtime_options.get("primary_headers"):
            contexts.append(RoleContext("anonymous", {}))
        return contexts

    async def _persist_finding(
        self,
        scan: Scan,
        target: Target,
        endpoint: Endpoint,
        result: ValidationResult,
        crawled: CrawledEndpoint,
    ) -> Finding:
        compliance = self.compliance.map_finding(result.finding_type, result.pii_types)
        risk = self.risk.score(
            endpoint_risk=endpoint.risk_score,
            confidence=result.confidence,
            has_pii=bool(result.pii_types or result.finding_type == "pii_exposure"),
            auth_weakness=result.finding_type
            in {
                "bola_idor",
                "missing_authorization",
                "jwt_weakness",
                "jwt_privilege_escalation_execution",
                "jwt_forge_endpoint_exposed",
                "token_storage_xss_account_takeover_chain",
                "sqli_auth_bypass",
                "unauthenticated_sensitive_api_exposure",
            },
            public_exposure=True,
            compliance_impact_count=len(compliance),
        )
        metadata = self._finding_metadata(result)
        severity = self._normalize_severity(result, metadata)
        risk_score = min(risk.risk_score, self._severity_score_cap(severity))
        business_impact = (
            self._business_impact(severity, metadata) or risk.business_impact
        )
        finding = Finding(
            organization_id=scan.organization_id,
            project_id=scan.project_id,
            target_id=target.id,
            scan_id=scan.id,
            endpoint_id=endpoint.id,
            finding_type=result.finding_type,
            title=result.title,
            severity=severity,
            confidence=result.confidence,
            risk_score=risk_score,
            description=result.description + f"\n\nBusiness impact: {business_impact}",
            reasoning=result.reasoning,
            evidence_summary=sanitize_json({**result.evidence, **metadata}),
            compliance=[
                {
                    "framework": item.framework,
                    "article_or_control": item.article_or_control,
                    "privacy_risk": item.privacy_risk,
                    "legal_risk": item.legal_risk,
                    "business_risk": item.business_risk,
                }
                for item in compliance
            ],
            remediation_guidance=result.remediation,
        )
        self.session.add(finding)
        await self.session.flush()

        evidence_payload = self.evidence.build(
            method=result.request_method or crawled.method,
            url=result.request_url or result.endpoint,
            request_headers=result.request_headers or crawled.request_headers or None,
            request_body=result.request_body,
            response_status=result.response_status
            if result.response_status is not None
            else crawled.status_code,
            response_headers=result.response_headers or crawled.response_headers,
            response_body=redact_text(
                result.response_body or crawled.response_body_sample
            ),
            steps=[
                "Run an authorized NyuwunSewu validation scan within the recorded scope.",
                f"Review finding '{result.title}'.",
                f"Review endpoint {result.endpoint}.",
                "Compare validation reasoning and sanitized evidence.",
            ],
            http_version=result.http_version or crawled.http_version,
            response_reason=result.response_reason or crawled.response_reason,
        )
        evidence = Evidence(
            organization_id=scan.organization_id,
            finding_id=finding.id,
            **evidence_payload,
        )
        self.session.add(evidence)

        for item in compliance:
            self.session.add(
                ComplianceMapping(
                    organization_id=scan.organization_id,
                    finding_id=finding.id,
                    framework=item.framework,
                    article_or_control=item.article_or_control,
                    privacy_risk=item.privacy_risk,
                    legal_risk=item.legal_risk,
                    business_risk=item.business_risk,
                )
            )

        self.session.add(
            RemediationTracking(
                organization_id=scan.organization_id,
                finding_id=finding.id,
                status=finding.status,
            )
        )
        finding.evidence_summary = {
            **finding.evidence_summary,
            "evidence_id": evidence_payload["immutable_id"],
            "evidence_hash": evidence_payload["evidence_hash"],
        }
        await self.session.commit()
        return finding

    async def _run_data_rights_validation(
        self,
        scan: Scan,
        target: Target,
        recon: AsyncReconEngine,
        runtime_options: dict[str, Any],
        policy: PolicyEngine,
    ) -> None:
        """Run data subject rights assessment (Right to be Forgotten, Access, Rectification).

        This is a post-scan assessment that tests the application's compliance
        with Pasal 22 UU PDP by probing deletion, access, and rectification endpoints.
        """
        engine = DataRightsValidationEngine(scope_guard=recon.scope_guard)
        auth_headers = runtime_options.get("primary_headers") or {}

        try:
            assessment = await engine.assess_all_rights(
                target=target.base_url,
                auth_headers=auth_headers if auth_headers else None,
            )
        except Exception:
            return  # Non-blocking — data rights tests may fail on non-PDP apps

        rtbf = assessment.get("right_to_be_forgotten")
        access = assessment.get("right_to_access")
        rect = assessment.get("right_to_rectification")

        tests_to_report: list[tuple[str, str, object]] = []
        if rtbf:
            tests_to_report.append(
                ("right_to_be_forgotten", "Right to be Forgotten", rtbf)
            )
        if access:
            tests_to_report.append(("right_to_access", "Right to Access", access))
        if rect:
            tests_to_report.append(
                ("right_to_rectification", "Right to Rectification", rect)
            )

        for right_type, right_name, result_obj in tests_to_report:
            status = getattr(result_obj, "status", "not_testable")
            score = float(getattr(result_obj, "score", 0))
            findings_list = getattr(result_obj, "findings", [])
            deletion_verified = getattr(result_obj, "deletion_verified", False)

            if status == "not_testable":
                continue

            if status == "compliant" and score >= 80:
                severity = "info"
            elif status == "partial" or score < 50:
                severity = "medium"
            else:
                severity = "low"

            descriptions: list[str] = []
            for f in findings_list:
                if isinstance(f, dict):
                    detail = f.get("details", "")
                    if detail:
                        descriptions.append(detail)
                elif hasattr(f, "details"):
                    descriptions.append(str(f.details))

            title_suffix = {
                "compliant": "Compliant",
                "partial": "Partially Compliant",
                "non_compliant": "Non-Compliant",
                "not_testable": "Not Testable",
            }.get(status, status)

            from app.models import Finding as FindingModel

            # Build evidence dict
            evidence_dict = {
                "right_type": right_type,
                "status": status,
                "score": score,
                "tests_run": getattr(result_obj, "tests_run", 0),
                "tests_passed": getattr(result_obj, "tests_passed", 0),
                "tests_failed": getattr(result_obj, "tests_failed", 0),
                "deletion_verified": deletion_verified,
                "response_time_ms": getattr(result_obj, "response_time_ms", None),
                "test_details": descriptions,
                "validation_mode": "data_rights_assessment",
            }

            description = (
                f"Assessment of {right_name} per Pasal 22 UU PDP. "
                f"Status: {status}, Score: {score:.0f}/100. "
                f"Tests run: {getattr(result_obj, 'tests_run', 0)}, "
                f"Passed: {getattr(result_obj, 'tests_passed', 0)}, "
                f"Failed: {getattr(result_obj, 'tests_failed', 0)}."
            )

            remediation = (
                "Ensure the application provides a mechanism for data subjects "
                f"to exercise their {right_name.lower()} rights per Pasal 22 UU PDP. "
                "Refer to the test details for specific gaps."
            )

            reasoning = [
                f"{right_name} assessment: {title_suffix}",
                f"Score: {score:.0f}/100",
            ] + descriptions[:3]

            # Build compliance impacts for Pasal 22
            compliance_impacts = [
                {
                    "framework": "UU PDP",
                    "article_or_control": "Pasal 22",
                    "privacy_risk": f"Data subject {right_name.lower()} may not be properly supported.",
                    "legal_risk": "Potential non-compliance with Pasal 22 UU PDP (hak data subjek).",
                    "business_risk": "Regulatory inquiry and data subject complaints.",
                },
                {
                    "framework": "OWASP ASVS",
                    "article_or_control": "V4.2 Data Subject Rights",
                    "privacy_risk": "Application may not support data subject rights mechanisms.",
                    "legal_risk": "ASVS compliance gap for data subject rights controls.",
                    "business_risk": "May affect audit posture for data governance.",
                },
            ]

            finding_model = FindingModel(
                organization_id=scan.organization_id,
                project_id=scan.project_id,
                target_id=scan.target_id,
                scan_id=scan.id,
                endpoint_id=None,
                finding_type=f"data_rights_{right_type}",
                title=f"{right_name}: {title_suffix} (score {score:.0f}/100)",
                severity=severity,
                status="Open",
                confidence=80.0,
                risk_score=round(score * 0.8, 1),
                description=description,
                reasoning=reasoning,
                evidence_summary=evidence_dict,
                compliance=compliance_impacts,
                remediation_guidance=remediation,
            )
            self.session.add(finding_model)
            await self.session.flush()

            # Map to compliance
            compliance_engine = ComplianceMappingEngine()
            impacts = compliance_engine.map_finding(finding_model.finding_type, [])
            for impact in impacts:
                cm = ComplianceMapping(
                    organization_id=scan.organization_id,
                    finding_id=finding_model.id,
                    framework=impact.framework,
                    article_or_control=impact.article_or_control,
                    privacy_risk=impact.privacy_risk,
                    legal_risk=impact.legal_risk,
                    business_risk=impact.business_risk,
                )
                self.session.add(cm)

            await self.session.flush()

