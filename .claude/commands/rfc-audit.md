---
description: Full RFC compliance audit of this IAM codebase — RFC 9470 (step-up), RFC 7662 (introspection), RFC 9449 (DPoP). Spawns rfc-compliance agent across all relevant packages.
argument-hint: "optional: rfc9470 | rfc7662 | rfc9449 | all (default: all)"
---

# RFC Compliance Audit

Run a compliance audit against the RFCs implemented in this codebase.

Scope: $ARGUMENTS (default: all)

## Phase 1 — Identify Changed Code

Run: `git diff HEAD --name-only` to find modified files.
If no changes, audit the full implementation (all files in `pkg/core/` and `internal/gateway/`).

Use TodoWrite to track audit progress.

## Phase 2 — Spawn RFC-Specific Agents

Launch `rfc-compliance` agents in parallel, one per RFC in scope:

**If scope includes rfc9470 or all:**
- Agent prompt: "Audit `pkg/core/stepup/` and `internal/gateway/guard.go` for RFC 9470 compliance. Check: challenge response format (WWW-Authenticate header, error string, acr_values, max_age), state machine transitions, auth_time enforcement when max_age present."

**If scope includes rfc7662 or all:**
- Agent prompt: "Audit `pkg/core/token/introspect.go` and `internal/gateway/guard.go` for RFC 7662 compliance. Check: active field always present, inactive token response leaks no claims, numeric date fields, scope as space-separated string, introspection endpoint protection."

**If scope includes rfc9449 or all:**
- Agent prompt: "Audit `pkg/core/token/dpop.go` for RFC 9449 compliance. Check: typ header = dpop+jwt, jwk contains public key only, asymmetric alg, jti uniqueness, htm/htu matching, iat freshness, cnf.jkt binding in access token."

## Phase 3 — Synthesize Results

After all agents complete:
1. Collect all MUST violations (compliance failures) — these are blockers
2. Collect all SHOULD violations (best-practice gaps)
3. Deduplicate overlapping findings

## Phase 4 — Report

Output structured report:
```
## RFC Compliance Audit

### MUST Violations (Blockers)
[list with RFC ref, location, fix]

### SHOULD Violations (Recommendations)
[list with RFC ref, location, fix]

### Compliant Sections
[RFC sections verified as correct]
```

If zero violations: confirm compliance clearly and list what was checked.
