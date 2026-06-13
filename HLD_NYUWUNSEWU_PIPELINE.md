# High-Level Design — NyuwunSewu ShieldPDP Detection & Compliance Pipeline

> **Document type:** High-Level Design (HLD)
> **Scope:** The NyuwunSewu deterministic security-validation engine, its False-Positive (FP) reduction layers, OWASP/UU PDP compliance mapping, and UU PDP scoring — plus the agentic **Phantom** layer that sits on top.
> **Source of truth:** This HLD is reverse-derived from the codebase. Every component cites its `file:path` so the design stays verifiable.
> **Rendering note:** Every diagram below is a self-contained Mermaid block. Each can be rendered directly (GitHub, Mermaid Live), exported to SVG/PNG, or pasted into Gemini / Claude as a design source for image generation.

---

## 1. Positioning (one paragraph)

NyuwunSewu is **not** a surface-level scanner. It is a **deterministic active-validation engine** (11 validators incl. active exploit-chain execution) with a built-in multi-tier **false-positive reducer**, an **OWASP ASVS + UU PDP No. 27/2022 compliance mapper**, and four **UU PDP scoring** subsystems. The **Phantom** agent (LLM-driven, via Hermes) is a *second, agentic layer* that adds recall (catches business-logic false negatives) and a reasoning-based second opinion. The overall thesis is a **hybrid deterministic + agentic** web-application security assessment pipeline that optimizes the precision/recall trade-off of automated DAST.

---

## 2. System Context

```mermaid
flowchart TB
    operator(["Operator / Pentester"])
    target(["Target Web App<br/>(banking-style, authenticated)"])

    subgraph SP["ShieldPDP — NyuwunSewu (FastAPI backend)"]
        recon["Recon Engine<br/>(dual-context crawl)"]
        detect["11 Validators<br/>(deterministic)"]
        fp["FP Reduction<br/>(3 tiers)"]
        comp["Compliance Mapper<br/>(UU PDP + OWASP ASVS)"]
        score["Scoring<br/>(risk / compliance / financial / Pasal 22)"]
        report["Report + Dashboard"]
    end

    subgraph PH["Phantom (agentic layer)"]
        receiver["Webhook Receiver"]
        hermes["Hermes LLM Agent"]
    end

    operator -->|"start scan"| SP
    recon --> detect --> fp --> comp --> score --> report
    target <-->|"HTTP probes"| recon
    target <-->|"HTTP probes"| detect
    report -->|"scan.completed webhook"| receiver
    receiver -->|"one-shot cron job + prompt"| hermes
    hermes <-->|"active validation"| target
    hermes -->|"POST /findings/ingest"| SP
    report -->|"Telegram notify"| operator
```

---

## 3. Component Architecture

```mermaid
flowchart LR
    subgraph ING["Ingestion"]
        RE["AsyncReconEngine<br/>app/recon/engine.py"]
    end

    subgraph ENR["Per-endpoint enrichment"]
        CL["EndpointClassifier<br/>app/classifier/engine.py"]
        PII["PIIDetectionEngine<br/>app/pii_detection/engine.py"]
    end

    subgraph VAL["Validation layer (11 validators)"]
        V["asyncio.gather fan-out<br/>app/validation/*"]
    end

    subgraph TRI["FP reduction + scoring"]
        T1["Tier 1 intrinsic triage<br/>validation/types.py"]
        T2["Tier 2 signal reducer<br/>validation/false_positive.py"]
        T3["Tier 3 severity normalize<br/>services/scan_scoring.py"]
    end

    subgraph GRC["Governance / compliance"]
        CM["ComplianceMappingEngine<br/>app/compliance/engine.py"]
        RK["RiskPrioritizationEngine<br/>app/services/risk_engine.py"]
        FIN["FinancialRiskEngine<br/>app/services/risk_engine.py"]
        DR["DataRightsValidationEngine<br/>validation/data_rights/*"]
    end

    ORCH["ScanRunner orchestrator<br/>app/services/scan_service.py"]

    RE --> CL --> PII --> V --> T1 --> T2 --> T3 --> RK --> CM
    CM --> FIN
    ORCH -. drives .-> RE
    ORCH -. drives .-> V
    ORCH -. drives .-> DR
    DR -.->|"Pasal 22 track"| GRC
```

**Wiring reference:** `app/services/scan_service.py` `ScanRunner.__init__` instantiates `self.classifier / self.pii / self.compliance / self.risk` (lines 74-77); validators imported and fanned out at lines 39-52 and 512-592; data-rights track at lines 279 and 761.

---

## 4. End-to-End Scan Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator
    participant SR as ScanRunner
    participant RE as ReconEngine
    participant VAL as 11 Validators
    participant FP as FP Reduction
    participant GRC as Compliance + Scoring
    participant WH as Phantom Receiver
    participant AG as Hermes Agent
    participant T as Target

    Op->>SR: start scan (target, mode, RoE)
    SR->>RE: crawl (guest -> authenticated)
    RE->>T: HTTP discovery (forms, API, JS routes)
    RE-->>SR: CrawledEndpoint[]
    loop per endpoint
        SR->>SR: classify() + pii.detect()
    end
    SR->>VAL: asyncio.gather(validators)
    VAL->>T: active probes (IDOR swap, JWT, SQLi, ...)
    VAL-->>SR: ValidationResult[]
    SR->>FP: intrinsic triage + signal reducer + severity normalize
    FP-->>SR: accepted findings (+ FP likelihood)
    SR->>GRC: map_finding() + risk.score() + compliance score + financial
    SR->>GRC: DataRights assess (Pasal 22)
    GRC-->>SR: findings + compliance + UU PDP scores
    SR-->>Op: report + dashboard
    SR->>WH: scan.completed webhook
    WH->>AG: one-shot cron job + engagement prompt
    AG->>T: agentic deep validation
    AG->>SR: POST /findings/ingest (confirmed findings)
```

---

## 5. Detection Layer — 11 Validators

```mermaid
flowchart TB
    GA["asyncio.gather (parallel)"]

    GA --> A1["1. LightweightSQLiValidator"]
    GA --> A2["2. BOLAValidator"]
    GA --> A3["3. AccessControlMatrixValidator"]
    GA --> A4["4. AuthValidator (JWT)"]
    GA --> A5["5. SafeAPIExposureValidator"]
    GA --> A6["6. CorsValidationEngine"]
    GA --> A7["7. PathTraversalValidator"]
    GA --> A8["8. ReflectedHTMLInjectionValidator"]
    GA --> A9["9. UsernameEnumerationValidator"]
    GA --> A10["10. impact_validators (SSRF / RateLimit / BusinessLogic)"]
    GA --> A11["11. ActiveExploitChainValidator (opt-in)"]

    A1 --> R["ValidationResult[]"]
    A2 --> R
    A3 --> R
    A4 --> R
    A5 --> R
    A6 --> R
    A7 --> R
    A8 --> R
    A9 --> R
    A10 --> R
    A11 --> R
```

| # | Validator (class · module) | `finding_type` | Severity | Technique | FP-reducer |
|---|---|---|---|---|---|
| 1 | `LightweightSQLiValidator` · `sqli.py` | `sqli`, `sqli_auth_bypass` | high / **critical** | error / boolean / timing delta + auth-bypass | ✅ |
| 2 | `BOLAValidator` · `bola.py` | `bola_idor` | high / medium | cross-account object access | ✅ |
| 3 | `AccessControlMatrixValidator` · `access_matrix.py` | `access_control_matrix` | high | multi-role matrix (`RoleContext`) | ✅ |
| 4 | `AuthValidator` · `auth.py` | `jwt_observed` (info), `jwt_weakness`, `jwt_claim_integrity_bypass` (**critical**), `missing_authorization` | info → critical | alg:none, unsigned token, claim tamper | ✅ |
| 5 | `SafeAPIExposureValidator` · `api_exposure.py` | `unauthenticated_sensitive_api_exposure`, `client_side_auth_token_storage`, `authentication_cookie_protection`, `graphql_schema_exposure` | high / medium | passive (during crawl) | — |
| 6 | `CorsValidationEngine` · `cors.py` | `cors_credentials_misconfiguration` | high | credentialed cross-origin | — |
| 7 | `PathTraversalValidator` · `path_traversal.py` | `path_traversal` | high | bounded file-like input | — |
| 8 | `ReflectedHTMLInjectionValidator` · `reflected_html.py` | `reflected_html_injection` | medium | inert non-executing DOM canary | — |
| 9 | `UsernameEnumerationValidator` · `username_enumeration.py` | `authentication_username_enumeration` | medium | login differential, no valid password | — |
| 10 | `impact_validators.py` **(3 sub-validators)** | `ssrf_inband_url_fetch` (high), `rate_limit_role_misclassification` (medium), `negative_amount_business_logic` (high) | high / medium | SSRF in-band canary; auth-vs-anon bucket; business invariant | — |
| 11 | `ActiveExploitChainValidator` · `exploit_chains.py` | `jwt_privilege_escalation_execution`, `jwt_forge_endpoint_exposed`, `token_storage_xss_account_takeover_chain`, `oauth_open_redirect_authorization_code_theft`, `authentication_username_enumeration_wordlist`, `modern_vuln_bank_attack_surface` (incl. **AI / prompt-injection probes**) | critical → low | active exploit-chain execution; **opt-in** flag `exploit_chains`; lab targets | — |

> **Counting note:** 11 *modules* are wired. `impact_validators` bundles 3 classes (so 13 validator *classes* total). `attack_knowledge.py` (`AttackKnowledgeEngine`) guides techniques but does not emit findings directly. **Data Subject Rights** (§9) is a separate Pasal-22 compliance validator.

---

## 6. False-Positive Reduction — 3 Tiers

This is the precision differentiator and is fully deterministic / explainable.

```mermaid
flowchart TB
    F["Raw ValidationResult"]

    subgraph TIER1["Tier 1 · Intrinsic triage (types.py __post_init__)"]
        t1a["confidence_level: CONFIRMED / HIGH / SUSPECTED / LOW"]
        t1b["evidence_quality: HIGH / MEDIUM / LOW"]
        t1c["reproduction_stability: REPLAYABLE / BOUNDED_RETEST / SINGLE / PASSIVE"]
        t1d["exploitability: CONFIRMED_EXPLOIT / VALIDATED_EXPOSURE / ATTACK_SURFACE / HEURISTIC"]
        t1e["false_positive_likelihood: LOW / MEDIUM / HIGH"]
    end

    subgraph TIER2["Tier 2 · Signal reducer (false_positive.py)"]
        t2a["8-signal SignalSet"]
        t2b["soft-404 + timing consistency + similarity/length anomaly"]
        t2c["GATE: accepted = confidence >= 70 AND anomaly_score < 70"]
    end

    subgraph TIER3["Tier 3 · Severity normalization (scan_scoring.py)"]
        t3a["force <= low if confidence < 65 OR FP_likelihood = HIGH"]
        t3b["per-type gating (e.g. sqli_auth_bypass -> critical only if conf>=95 & CONFIRMED_EXPLOIT)"]
        t3c["severity score cap: crit 100 / high 89 / med 74 / low 49 / info 24"]
    end

    F --> TIER1 --> TIER2
    TIER2 -->|accepted| TIER3 --> OUT["Scored, de-noised finding"]
    TIER2 -->|rejected| DROP["Discarded (below production threshold)"]
```

**Tier 2 detail** (`app/validation/false_positive.py`): `SignalSet` = `{status_changed, sql_error, boolean_delta, timing_delta, reflected_payload, sensitive_fields, auth_context_changed, authentication_bypass}`. Used by `sqli`, `bola`, `auth`, `access_matrix`. Returns `ReductionDecision(accepted, confidence, anomaly_score, reasoning)` — reasoning is audit-friendly text.

---

## 7. Classification & PII Inputs

```mermaid
flowchart LR
    EP["CrawledEndpoint"] --> CL["EndpointClassifier"]
    EP --> PII["PIIDetectionEngine"]
    CL --> R1["endpoint_risk + class<br/>auth/admin/pii/financial/sensitive/..."]
    PII --> R2["pii_types[]<br/>NIK / NPWP / bank acct / phone / JWT / api_key"]
    R1 --> SC["feeds RiskPrioritizationEngine"]
    R2 --> CMP["triggers Pasal 67 (financial penalty)"]
```

- **EndpointClassifier** (`app/classifier/engine.py`): keyword + structure rules → labels (auth, admin, pii, upload, financial, sensitive, internal API, public API); `risk_score` boosted by state-changing method & forms.
- **PIIDetectionEngine** (`app/pii_detection/engine.py`): Indonesia-aware — **NIK** with structural validation (province code + birth-date segment + female day-offset), **NPWP**, `+62` phone, **bank account** (context keywords bca/mandiri/bni/bri/cimb), plus email/JWT/api_key/access_token/UUID. Anti-FP: Luhn test-card filter, dummy-numeric filter, entropy boost.

---

## 8. Compliance Mapping (UU PDP + OWASP ASVS)

`ComplianceMappingEngine.map_finding(finding_type, pii_types)` → list of `ComplianceImpact{framework, article_or_control, privacy_risk, legal_risk, business_risk}`. Source: *UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi*.

```mermaid
flowchart LR
    subgraph FT["Finding categories"]
        ac["Access control (BOLA/IDOR/matrix)"]
        ua["Unauthenticated sensitive API"]
        sq["SQLi"]
        pt["Path traversal"]
        rh["Reflected HTML"]
        pii["PII exposure"]
        jw["JWT / Auth"]
        co["CORS"]
        ss["SSRF"]
        bl["Business logic"]
        rl["Rate limit"]
    end

    subgraph PASAL["UU PDP Articles"]
        p20["Pasal 20 · consent"]
        p22["Pasal 22 · data subject rights"]
        p35["Pasal 35 · security obligation (CORE, weight 2.0)"]
        p46["Pasal 46 · breach notification"]
        p57["Pasal 57 · administrative sanctions"]
        p67["Pasal 67 · fines up to 2% revenue (PII only)"]
    end

    ac --> p22 & p35 & p46 & p57
    ua --> p20 & p35 & p46 & p57
    sq --> p35 & p46 & p57
    pt --> p35 & p46 & p57
    rh --> p35 & p57
    pii --> p35 & p46 & p57 & p67
    jw --> p20 & p35 & p57
    co --> p20 & p35 & p46 & p57
    ss --> p35 & p46 & p57
    bl --> p35 & p57
    rl --> p35
    ac -.PII context.-> p67
    ua -.PII context.-> p67
```

**OWASP ASVS pairing per category:** access-control → V4 · unauth-API → V4 · SQLi → V5 · path-traversal → V5/V8 · reflected-HTML → V5 · PII → V8 · JWT/auth → V2/V3 · CORS → V14/V8 · SSRF → V12/V14 · business-logic → V1/V5 · rate-limit → V2/V7 · fallback → V1.

---

## 9. UU PDP Scoring — 4 Subsystems

```mermaid
flowchart TB
    findings["Scored findings"] --> A & B & C
    rights["Data rights tests"] --> D

    subgraph A["A. Compliance Score (compliance/engine.py)"]
        a1["per-article from highest severity:<br/>crit 0-20 / high 25-45 / med 50-65 / low 70-85"]
        a2["status: non_compliant / partial / compliant"]
        a3["overall = weighted avg (Pasal 35 = 2.0)"]
    end

    subgraph B["B. Risk Prioritization (risk_engine.py)"]
        b1["risk = endpoint_risk*0.25 + confidence*0.35"]
        b2["+ PII(14) + auth_weak(12) + public(8) + min(12, compliance*4)"]
        b3["-> 0..100 -> severity band"]
    end

    subgraph C["C. Financial / Comprehensive (risk_engine.py)"]
        c1["max_penalty = annual_revenue * 0.02 (Pasal 67)"]
        c2["estimated_exposure = severity_weight * min(1, n/10)"]
        c3["overall = tech*0.4 + financial*0.35 + reputational*0.25"]
        c4["executive summary in IDR + actions"]
    end

    subgraph D["D. Data Subject Rights (Pasal 22)"]
        d1["avg(forgotten, access, rectification)"]
        d2["overall_status + gaps"]
    end
```

**Formulas (verbatim from code):**

- **Per-finding risk** — `risk_engine.py:22`:
  `score = endpoint_risk*0.25 + confidence*0.35 + (PII?14) + (auth_weakness?12) + (public?8) + min(12, compliance_count*4)`, clamped 0–100.
- **Compliance article score** — highest severity maps to a band midpoint; overall = weighted average with `COMPLIANCE_WEIGHTS = {Pasal_35: 2.0, Pasal_20/22/46: 1.5, Pasal_57/67: 1.0}`.
- **Comprehensive overall** — `risk_engine.py:251`: `technical*0.4 + (financial.severity_weight*100)*0.35 + reputational*0.25`.

---

## 10. Data Subject Rights — Pasal 22 Track

```mermaid
flowchart LR
    DRE["DataRightsValidationEngine<br/>validation/data_rights/engine.py"]
    DRE --> RF["Right to be forgotten<br/>(deletion verified?)"]
    DRE --> RA["Right to access"]
    DRE --> RR["Right to rectification"]
    RF --> SUM["avg score -> overall_status"]
    RA --> SUM
    RR --> SUM
    SUM --> OUT["uu_pdp_pasal_22_compliance{status, score, gaps}"]
```

Composed via mixins (`RightToBeForgottenMixin`, `RightToAccessMixin`, `RightToRectificationMixin`) on `_DataRightsBase`. Runs as a separate track in `scan_service.py:279`; emits `data_rights_*` finding types.

---

## 11. Phantom Agentic Layer (hybrid recall)

```mermaid
flowchart LR
    SC["scan.completed webhook"] --> RC["phantom_webhook_receiver.py"]
    RC --> CTX["save scan context (endpoint map)"]
    RC --> SESS["create AgentSession"]
    RC --> JOB["one-shot Hermes cron job + engagement prompt"]
    JOB --> AGENT["Hermes LLM agent"]
    AGENT --> DEEP["deep active validation<br/>IDOR replay (userA/userB), JWT, authz, injection-confirm"]
    DEEP --> INGEST["POST /findings/ingest (confirmed only)"]
    INGEST --> SC2["back into ShieldPDP store"]
```

- Two engagement modes: **internal** (owned lab, auth pre-granted) and **external** (live/public, RoE-bound, refusal-first).
- The `feat/phantom-persistent-goal-budget` branch adds **durability** (standing goal + flush-before-spend + checkpoint resume trail) so deep validation survives LLM context compaction — a reliability contribution, not a new attack technique.

---

## Appendix A — Module Map

| Layer | Path |
|---|---|
| Recon | `app/recon/engine.py` |
| Classifier | `app/classifier/engine.py` |
| PII detection | `app/pii_detection/engine.py` |
| Validators (11) | `app/validation/{sqli,bola,access_matrix,auth,api_exposure,cors,path_traversal,reflected_html,username_enumeration,impact_validators,exploit_chains}.py` |
| FP reduction | `app/validation/false_positive.py`, `app/validation/types.py`, `app/services/scan_scoring.py` |
| Compliance | `app/compliance/engine.py` |
| Risk / Financial | `app/services/risk_engine.py` |
| Data rights (Pasal 22) | `app/validation/data_rights/` |
| Orchestrator | `app/services/scan_service.py` |
| Phantom layer | `phantom_webhook_receiver.py` |

## Appendix B — Finding-Type Catalog (by severity ceiling)

- **Critical:** `sqli_auth_bypass`, `jwt_claim_integrity_bypass`, `jwt_privilege_escalation_execution`, `jwt_forge_endpoint_exposed`
- **High:** `sqli`, `bola_idor`, `access_control_matrix`, `missing_authorization`, `unauthenticated_sensitive_api_exposure`, `cors_credentials_misconfiguration`, `path_traversal`, `ssrf_inband_url_fetch`, `negative_amount_business_logic`, `oauth_open_redirect_authorization_code_theft`, `authentication_username_enumeration_wordlist`, `jwt_weakness`
- **Medium:** `reflected_html_injection`, `authentication_username_enumeration`, `rate_limit_role_misclassification`, `client_side_auth_token_storage`, `authentication_cookie_protection`, `graphql_schema_exposure`
- **Info / Low:** `jwt_observed`, `modern_vuln_bank_attack_surface`

---

*Generated as a verifiable HLD: each component is anchored to `file:path` in the ShieldPDP codebase. Diagrams are Mermaid and portable to Gemini / Claude for image generation.*
