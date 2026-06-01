import asyncio
import json
import re
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import aiohttp

from app.recon import CrawledEndpoint
from app.services.policy_engine import PolicyEngine
from app.services.scope_guard import ScopeGuard
from app.utils.rate_limiter import AdaptiveRateLimiter
from app.validation.false_positive import FalsePositiveReducer, SignalSet, similarity
from app.validation.types import HttpObservation, ValidationResult


class LightweightSQLiValidator:
    ERROR_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
        ("MySQL", re.compile(r"SQL syntax.*MySQL|Warning.*mysql_|MySqlClient|MariaDB", re.I | re.S)),
        ("PostgreSQL", re.compile(r"PostgreSQL.*ERROR|pg_query\(|unterminated quoted string|syntax error at or near", re.I | re.S)),
        ("MSSQL", re.compile(r"SQL Server|ODBC SQL Server Driver|Unclosed quotation mark|Microsoft OLE DB", re.I | re.S)),
        ("Oracle", re.compile(r"ORA-\d{5}|Oracle error|quoted string not properly terminated", re.I | re.S)),
        ("Generic SQL", re.compile(r"SQL syntax|database error|syntax error|SQLException", re.I | re.S)),
    ]
    ERROR_PAYLOADS = ["'", '"', "`)"]
    BOOLEAN_TRUE = "' OR '1'='1"
    BOOLEAN_FALSE = "' OR '1'='2"
    AUTH_BYPASS_TRUE = "admin' OR '1'='1'--"
    AUTH_BYPASS_FALSE = "admin' AND '1'='2'--"
    TIMING_PAYLOAD = "' OR SLEEP(5)--"
    AUTH_SUCCESS_RE = re.compile(r"\b(logout|sign out|signout|welcome|my account|profile|logged in)\b", re.I)
    FETCH_ACTION_RE = re.compile(r"""fetch\s*\(\s*["']([^"']+)["']""", re.I)

    def __init__(
        self,
        policy: PolicyEngine,
        scope_guard: ScopeGuard,
        rate_limiter: AdaptiveRateLimiter,
    ):
        self.policy = policy
        self.scope_guard = scope_guard
        self.rate_limiter = rate_limiter
        self.reducer = FalsePositiveReducer()

    async def validate(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None = None,
        anonymous_session: aiohttp.ClientSession | None = None,
    ) -> ValidationResult | None:
        if not self.policy.is_validation_allowed("sqli"):
            return None
        query_result = await self._validate_query_params(endpoint, session, headers)
        if query_result:
            return query_result
        return await self._validate_forms(endpoint, session, headers, anonymous_session)

    async def _validate_query_params(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None = None,
    ) -> ValidationResult | None:
        parsed = urlparse(endpoint.url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return None

        parameter = next(iter(params.keys()))
        if len(parameter) > 100:
            return None

        baseline = await self._observe(session, endpoint.url, headers=headers)
        if baseline is None or baseline.status_code >= 500:
            return None

        observations: list[HttpObservation] = []
        signals = SignalSet()
        dbms: str | None = None
        reasoning: list[str] = []
        proof_observation: HttpObservation | None = None
        proof_request_url: str | None = None
        proof_payload: str | None = None

        for payload in self.ERROR_PAYLOADS:
            candidate_url = self._mutate_query(endpoint.url, parameter, payload)
            candidate = await self._observe(session, candidate_url, headers=headers)
            if candidate is None:
                continue
            observations.append(candidate)
            detected_dbms = self._detect_dbms(candidate.body_sample)
            if detected_dbms:
                dbms = detected_dbms
                signals.sql_error = True
                reasoning.append(f"{detected_dbms} error pattern detected for parameter '{parameter}'")
                proof_observation = candidate
                proof_request_url = candidate_url
                proof_payload = payload
            if candidate.status_code != baseline.status_code:
                signals.status_changed = True
            if payload in candidate.body_sample:
                signals.reflected_payload = True

        true_obs = await self._observe(
            session, self._mutate_query(endpoint.url, parameter, self.BOOLEAN_TRUE), headers=headers
        )
        false_obs = await self._observe(
            session, self._mutate_query(endpoint.url, parameter, self.BOOLEAN_FALSE), headers=headers
        )
        repeat_true_obs = await self._observe(
            session, self._mutate_query(endpoint.url, parameter, self.BOOLEAN_TRUE), headers=headers
        )
        repeat_false_obs = await self._observe(
            session, self._mutate_query(endpoint.url, parameter, self.BOOLEAN_FALSE), headers=headers
        )
        if true_obs and false_obs and repeat_true_obs and repeat_false_obs:
            observations.extend([true_obs, false_obs, repeat_true_obs, repeat_false_obs])
            if self._stable_boolean_delta(true_obs, false_obs, repeat_true_obs, repeat_false_obs):
                signals.boolean_delta = True
                reasoning.append("Boolean true/false probes produced a reproducible response delta")
                if proof_observation is None:
                    proof_observation = true_obs
                    proof_request_url = self._mutate_query(endpoint.url, parameter, self.BOOLEAN_TRUE)
                    proof_payload = self.BOOLEAN_TRUE

        if self.policy.is_validation_allowed("timing"):
            baseline_times = [baseline.elapsed_ms]
            timing_times: list[float] = []
            for _ in range(2):
                timing_obs = await self._observe(
                    session,
                    self._mutate_query(endpoint.url, parameter, self.TIMING_PAYLOAD),
                    headers=headers,
                )
                if timing_obs:
                    observations.append(timing_obs)
                    timing_times.append(timing_obs.elapsed_ms)
                await asyncio.sleep(0.1)
            if self.reducer.timing_is_consistent(baseline_times, timing_times):
                signals.timing_delta = True
                reasoning.append("Timing delay was confirmed across bounded retries")
                if proof_observation is None and timing_obs:
                    proof_observation = timing_obs
                    proof_request_url = self._mutate_query(endpoint.url, parameter, self.TIMING_PAYLOAD)
                    proof_payload = self.TIMING_PAYLOAD

        decision = self.reducer.reduce(baseline, observations, signals, minimum_confidence=72.0)
        if not decision.accepted:
            return None
        proof_observation = proof_observation or observations[0]
        proof_request_url = proof_request_url or proof_observation.url
        proof_payload = proof_payload or "bounded validation probe"

        return ValidationResult(
            finding_type="sqli",
            title="Lightweight SQL Injection Validation",
            severity="high" if decision.confidence >= 85 else "medium",
            confidence=decision.confidence,
            endpoint=endpoint.url,
            description=(
                "A bounded, non-destructive SQL injection validation produced stable evidence. "
                "The platform did not attempt data extraction or exploitation."
            ),
            reasoning=reasoning + decision.reasoning,
            evidence={
                "validation_mode": "bounded_sqli_validation",
                "parameter": parameter,
                "injected_parameter": parameter,
                "injection_location": "query_parameter",
                "payload": proof_payload,
                "dbms": dbms,
                "reflected_payload": signals.reflected_payload,
                "confirmed_signal_count": sum(
                    bool(item)
                    for item in (
                        signals.sql_error,
                        signals.boolean_delta,
                        signals.timing_delta,
                        signals.authentication_bypass,
                    )
                ),
                "baseline_status": baseline.status_code,
                "candidate_statuses": [obs.status_code for obs in observations],
                "anomaly_score": decision.anomaly_score,
            },
            dbms=dbms,
            remediation=(
                "Use parameterized queries or ORM-bound parameters, validate input types, "
                "and add regression tests around this endpoint."
            ),
            request_method="GET",
            request_url=proof_request_url,
            request_headers=proof_observation.request_headers,
            response_status=proof_observation.status_code,
            response_headers=proof_observation.headers,
            response_body=proof_observation.body_sample,
            http_version=proof_observation.http_version,
            response_reason=proof_observation.response_reason,
        )

    async def _validate_forms(
        self,
        endpoint: CrawledEndpoint,
        session: aiohttp.ClientSession,
        headers: dict[str, str] | None = None,
        anonymous_session: aiohttp.ClientSession | None = None,
    ) -> ValidationResult | None:
        if not endpoint.forms:
            return None

        for form in endpoint.forms[:4]:
            action = str(form.get("action") or endpoint.url)
            method = str(form.get("method") or "GET").upper()
            has_password_field = any(
                str(field.get("type") or "").lower() == "password"
                for field in form.get("fields", [])
            )
            json_action = self._javascript_json_login_action(endpoint) if has_password_field else None
            use_json_body = bool(json_action)
            if json_action:
                action = json_action
                method = "POST"
            fields = self._injectable_form_fields(form)
            if not fields or not await self.scope_guard.is_url_allowed(action):
                continue

            validation_session = anonymous_session if use_json_body and anonymous_session else session
            validation_headers = {} if use_json_body and anonymous_session else headers
            parameter = fields[0]
            baseline_payload = self._form_payload(form)
            baseline = await self._observe(
                validation_session,
                action,
                headers=validation_headers,
                method=method,
                data=baseline_payload,
                use_json_body=use_json_body,
            )
            if baseline is None or baseline.status_code >= 500:
                continue

            observations: list[HttpObservation] = []
            signals = SignalSet()
            dbms: str | None = None
            reasoning: list[str] = []
            proof_observation: HttpObservation | None = None
            proof_payload: dict[str, str] | None = None

            quote_payload = self._form_payload(form, {parameter: "'"})
            quote_obs = await self._observe(
                validation_session,
                action,
                headers=validation_headers,
                method=method,
                data=quote_payload,
                use_json_body=use_json_body,
            )
            if quote_obs:
                observations.append(quote_obs)
                dbms = self._detect_dbms(quote_obs.body_sample)
                if dbms:
                    signals.sql_error = True
                    reasoning.append(f"{dbms} error pattern detected for form field '{parameter}'")
                    proof_observation = quote_obs
                    proof_payload = quote_payload
                if quote_obs.status_code != baseline.status_code:
                    signals.status_changed = True
                if "'" in quote_obs.body_sample:
                    signals.reflected_payload = True

            true_payload = self._form_payload(form, {parameter: self.AUTH_BYPASS_TRUE})
            false_payload = self._form_payload(form, {parameter: self.AUTH_BYPASS_FALSE})
            true_obs = await self._observe(
                validation_session,
                action,
                headers=validation_headers,
                method=method,
                data=true_payload,
                use_json_body=use_json_body,
            )
            false_obs = await self._observe(
                validation_session,
                action,
                headers=validation_headers,
                method=method,
                data=false_payload,
                use_json_body=use_json_body,
            )
            repeat_true_obs = await self._observe(
                validation_session,
                action,
                headers=validation_headers,
                method=method,
                data=true_payload,
                use_json_body=use_json_body,
            )
            repeat_false_obs = await self._observe(
                validation_session,
                action,
                headers=validation_headers,
                method=method,
                data=false_payload,
                use_json_body=use_json_body,
            )
            if true_obs and false_obs and repeat_true_obs and repeat_false_obs:
                observations.extend([true_obs, false_obs, repeat_true_obs, repeat_false_obs])
                if self._stable_boolean_delta(
                    true_obs,
                    false_obs,
                    repeat_true_obs,
                    repeat_false_obs,
                    body_similarity_threshold=0.94,
                    length_delta_threshold=0.05,
                ):
                    signals.boolean_delta = True
                    reasoning.append("Form true/false SQL probes produced a reproducible response delta")
                    if proof_observation is None:
                        proof_observation = true_obs
                        proof_payload = true_payload
                if self._auth_state_changed(baseline, true_obs, false_obs):
                    signals.authentication_bypass = True
                    signals.auth_context_changed = True
                    reasoning.append("True-condition form payload changed the authenticated application state")
                    proof_observation = true_obs
                    proof_payload = true_payload

            decision = self.reducer.reduce(
                baseline,
                observations,
                signals,
                minimum_confidence=70.0 if signals.authentication_bypass else 74.0,
            )
            if not decision.accepted:
                continue

            auth_bypass = signals.authentication_bypass
            proof_observation = proof_observation or observations[0]
            proof_payload = proof_payload or quote_payload
            return ValidationResult(
                finding_type="sqli_auth_bypass" if auth_bypass else "sqli",
                title=(
                    "SQL Injection Authentication Bypass"
                    if auth_bypass
                    else "Lightweight SQL Injection Validation"
                ),
                severity="critical" if auth_bypass and decision.confidence >= 88 else "high",
                confidence=decision.confidence,
                endpoint=endpoint.url,
                description=(
                    "A bounded, non-destructive form SQL injection validation produced stable evidence. "
                    "The platform did not attempt data extraction or database dumping."
                ),
                reasoning=reasoning + decision.reasoning,
                evidence={
                    "validation_mode": (
                        "bounded_sqli_auth_bypass_validation"
                        if auth_bypass
                        else "bounded_sqli_validation"
                    ),
                    "form_action": action,
                    "form_method": method,
                    "request_encoding": "application/json" if use_json_body else "form_urlencoded",
                    "field": parameter,
                    "injected_parameter": parameter,
                    "injection_location": "json_body" if use_json_body else "form_body",
                    "payload": proof_payload.get(parameter, ""),
                    "dbms": dbms,
                    "reflected_payload": signals.reflected_payload,
                    "confirmed_signal_count": sum(
                        bool(item)
                        for item in (
                            signals.sql_error,
                            signals.boolean_delta,
                            signals.timing_delta,
                            signals.authentication_bypass,
                        )
                    ),
                    "baseline_status": baseline.status_code,
                    "baseline_url": baseline.url,
                    "candidate_statuses": [obs.status_code for obs in observations],
                    "candidate_urls": [obs.url for obs in observations],
                    "authentication_bypass_signal": auth_bypass,
                    "anomaly_score": decision.anomaly_score,
                },
                dbms=dbms,
                remediation=(
                    "Use parameterized queries for authentication lookups, avoid string-built SQL, "
                    "normalize login error handling, and add regression tests for SQL boolean payloads."
                ),
                request_method=method,
                request_url=action,
                request_headers=proof_observation.request_headers,
                request_body=(
                    json.dumps(proof_payload, separators=(",", ":"))
                    if method == "POST" and use_json_body
                    else urlencode(proof_payload)
                    if method == "POST"
                    else None
                ),
                response_status=proof_observation.status_code,
                response_headers=proof_observation.headers,
                response_body=proof_observation.body_sample,
                http_version=proof_observation.http_version,
                response_reason=proof_observation.response_reason,
            )
        return None

    async def _observe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        headers: dict[str, str] | None = None,
        *,
        method: str = "GET",
        data: dict[str, str] | None = None,
        use_json_body: bool = False,
    ) -> HttpObservation | None:
        if not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            await self.rate_limiter.wait()
            start = time.perf_counter()
            request_method = method.upper()
            request = session.post if request_method == "POST" else session.get
            kwargs = {
                "headers": headers,
                "allow_redirects": True,
            }
            if request_method == "POST":
                if use_json_body:
                    kwargs["json"] = data or {}
                else:
                    kwargs["data"] = data or {}
            async with request(url, **kwargs) as response:
                body = await response.text(errors="replace")
                elapsed = (time.perf_counter() - start) * 1000
                request_headers = {
                    key.lower(): value for key, value in response.request_info.headers.items()
                }
                if request_method == "POST":
                    encoded_body = (
                        json.dumps(data or {}, separators=(",", ":"))
                        if use_json_body
                        else urlencode(data or {})
                    )
                    request_headers.setdefault(
                        "content-type",
                        "application/json" if use_json_body else "application/x-www-form-urlencoded",
                    )
                    request_headers.setdefault("content-length", str(len(encoded_body.encode("utf-8"))))
                return HttpObservation(
                    url=str(response.url),
                    method=request_method,
                    status_code=response.status,
                    elapsed_ms=elapsed,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    body_sample=body[:12000],
                    content_length=len(body),
                    request_headers=request_headers,
                    http_version=f"HTTP/{response.version.major}.{response.version.minor}",
                    response_reason=response.reason or "",
                )
        except (aiohttp.ClientError, asyncio.TimeoutError):
            self.rate_limiter.record_anomaly()
            return None

    def _mutate_query(self, url: str, parameter: str, payload: str) -> str:
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        current = query.get(parameter, [""])[0]
        query[parameter] = [current + payload]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    def _detect_dbms(self, body: str) -> str | None:
        for dbms, pattern in self.ERROR_PATTERNS:
            if pattern.search(body):
                return dbms
        return None

    def _stable_boolean_delta(
        self,
        true_obs: HttpObservation,
        false_obs: HttpObservation,
        repeat_true_obs: HttpObservation,
        repeat_false_obs: HttpObservation,
        *,
        body_similarity_threshold: float = 0.92,
        length_delta_threshold: float = 0.08,
    ) -> bool:
        true_repeat_stable = (
            true_obs.status_code == repeat_true_obs.status_code
            and similarity(true_obs.body_sample, repeat_true_obs.body_sample) > 0.96
        )
        false_repeat_stable = (
            false_obs.status_code == repeat_false_obs.status_code
            and similarity(false_obs.body_sample, repeat_false_obs.body_sample) > 0.96
        )
        if not true_repeat_stable or not false_repeat_stable:
            return False
        bool_similarity = similarity(true_obs.body_sample, false_obs.body_sample)
        length_delta = abs(true_obs.content_length - false_obs.content_length) / max(
            true_obs.content_length,
            false_obs.content_length,
            1,
        )
        return (
            bool_similarity < body_similarity_threshold
            or length_delta > length_delta_threshold
            or true_obs.url != false_obs.url
            or true_obs.status_code != false_obs.status_code
        )

    def _javascript_json_login_action(self, endpoint: CrawledEndpoint) -> str | None:
        path = urlparse(endpoint.url).path.lower()
        if not any(marker in path for marker in ("login", "signin", "sign-in", "session")):
            return None
        text = endpoint.response_body_sample
        lowered = text.lower()
        if "json.stringify" not in lowered or "application/json" not in lowered:
            return None
        match = self.FETCH_ACTION_RE.search(text)
        return urljoin(endpoint.url, match.group(1)) if match else None

    def _injectable_form_fields(self, form: dict) -> list[str]:
        candidates: list[tuple[int, str]] = []
        for field in form.get("fields", []):
            name = str(field.get("name") or "")
            field_type = str(field.get("type") or "text").lower()
            if not name or field_type in {"hidden", "submit", "button", "checkbox", "radio", "file"}:
                continue
            if field_type not in {"text", "password", "search", "email", "url", "tel", "textarea"}:
                continue
            lowered = name.lower()
            priority = 0
            if any(marker in lowered for marker in ("user", "login", "email", "name")):
                priority = 100
            elif "pass" in lowered:
                priority = 80
            candidates.append((priority, name))
        return [name for _, name in sorted(candidates, reverse=True)]

    def _form_payload(self, form: dict, overrides: dict[str, str] | None = None) -> dict[str, str]:
        overrides = overrides or {}
        payload: dict[str, str] = {}
        for field in form.get("fields", []):
            name = str(field.get("name") or "")
            if not name:
                continue
            field_type = str(field.get("type") or "text").lower()
            value = str(field.get("value") or "")
            if field_type in {"text", "password", "search", "email", "url", "tel"}:
                value = "nyuwunsewu"
            if field_type == "password":
                value = "nyuwunsewu"
            payload[name] = value
        payload.update(overrides)
        return payload

    def _auth_state_changed(
        self,
        baseline: HttpObservation,
        true_obs: HttpObservation,
        false_obs: HttpObservation,
    ) -> bool:
        baseline_path = urlparse(baseline.url).path.lower()
        true_path = urlparse(true_obs.url).path.lower()
        false_path = urlparse(false_obs.url).path.lower()
        true_success = self._looks_authenticated(true_obs)
        baseline_success = self._looks_authenticated(baseline)
        false_success = self._looks_authenticated(false_obs)
        path_transition = (
            true_path != baseline_path
            and "login" not in true_path
            and (false_path == baseline_path or "login" in false_path)
        )
        return (true_success and not baseline_success and not false_success) or path_transition

    def _looks_authenticated(self, observation: HttpObservation) -> bool:
        body = observation.body_sample[:12000]
        try:
            payload = json.loads(body)
            if isinstance(payload, dict) and any(
                isinstance(payload.get(name), str) and payload.get(name)
                for name in ("token", "access_token", "jwt")
            ):
                return True
        except json.JSONDecodeError:
            pass
        path = urlparse(observation.url).path.lower()
        if "login" in path:
            return False
        return bool(self.AUTH_SUCCESS_RE.search(body))
