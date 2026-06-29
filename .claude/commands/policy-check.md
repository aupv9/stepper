---
description: Validate policy YAML and simulate a request through the policy engine. Usage: /policy-check [path] [method] [acr] — e.g. /policy-check /api/payments POST silver
argument-hint: "[path] [method] [acr_level]  — e.g. /api/payments POST silver"
---

# Policy Check

Validate the policy configuration and optionally simulate a request.

Arguments: $ARGUMENTS

## Step 1 — Load Policy File

Read `config/policy.example.yaml` (or the file at `IAM_POLICY_FILE` if set).

Also read `pkg/core/policy/engine.go`, `pkg/core/policy/matcher.go`, and `pkg/core/policy/types.go` to understand evaluation semantics exactly.

## Step 2 — Validate the Policy File

Check for these issues in the loaded YAML:

1. **Priority conflicts** — two policies with the same `priority` that can match the same resource+method combination. List each conflict.
2. **Shadowed policies** — a higher-priority broader glob makes a lower-priority narrower policy unreachable. Show the shadowing pair.
3. **Public sensitive paths** — any policy with `public: true` whose resource matches `/admin/**`, `/internal/**`, or similar privileged prefixes.
4. **max_age without ACR** — `max_age` set but no `acr` requirement (pointless freshness check).
5. **Missing default-deny** — no lowest-priority catch-all policy that denies everything. Warn if absent.
6. **ACR level validity** — all `require.acr` values exist in the `acr_levels` list.

Report each issue with the policy name, field, and recommended fix.

## Step 3 — Simulate Request (if arguments provided)

If $ARGUMENTS contains a path, method, and optionally an ACR level, simulate the policy evaluation:

Parse arguments: first token = path, second = HTTP method (default GET), third = ACR level (default none/anonymous).

Walk the policies in priority order:
1. Test resource glob match against path
2. Test method match
3. If matched: evaluate `require` block against the simulated token (acr, no scopes, no MFA unless specified)
4. Show the first matching policy, the decision (ALLOW / DENY / CHALLENGE), and the reason

If no policy matches → show "no match → default deny".

## Step 4 — Summary

Print:
- Total policies: N
- Issues found: N (list them)
- Simulation result (if requested): ALLOW / DENY / CHALLENGE with the matching policy name
