# Security controls and honest limits

## Implemented and tested (see tests/)
- Tenant comes from server-side membership; JWT only proves identity. Cross-tenant and non-existent IDs return the same 404 (assessments, findings, reports, evidence, uploads).
- OIDC: RS256 only, issuer, expiry and audience/client_id enforced, ID tokens and `alg=none` rejected. Dev auth refuses to start in staging/prod.
- Roles enforced per endpoint; contributors can answer only assigned sections.
- Idempotency-Key on state-changing POSTs; ETag/If-Match optimistic locking with revision history.
- Questionnaire version pinned and SHA256-verified at start; submit freezes answers with a digest; published reports are immutable.
- Evidence: MIME allow-list, size cap, SHA256 and size match, magic-byte check, EICAR/executable signatures, macro-docx rejection, zip-bomb guard, injection flagging; opaque object keys; only clean evidence can be cited.
- Swaska: tool allow-list, strict output schema, existing question IDs only, compliance/verification claims rejected, deterministic fallback on any failure, untrusted text delimited.
- Reports: every claim links to a question ID and assurance level (always "Self-attested" until evidence is reviewed); findings are candidates; control and bidi characters stripped; drafts are visibly PRELIMINARY.
- POC blueprint: both sign-offs and success criteria required, DRAFT only, runtime blocked, no credentials, execute denied by default.
- Portal: no innerHTML, strict CSP, nosniff, frame-deny, no-store.

## Not done
- No penetration test, DPIA, or independent security review. Required security sign-offs are still open.
- Dev tokens endpoint exists only when `TAAD_ENV=local` with dev auth.
- Rate limiting covers registration only; the WAF supplies a coarse per-IP limit in AWS.
- Portal has 8 Playwright (Chromium) tests: login/resume, stored-XSS, CSP, full customer-to-reviewer flow with PDF/DOCX download, role gating, evidence upload, mobile layout. Firefox/Safari, screen-reader testing and automated axe audits are not done.
- Python 3.9 was used locally; the container and CI use 3.12.
