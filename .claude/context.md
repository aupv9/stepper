# Headroom Context Index

Compressed architecture snapshots stored in headroom. Retrieve with:
`mcp__headroom__headroom_retrieve(hash="<hash>")`

| Hash | Content | Last Updated |
|------|---------|--------------|
| `cfc1113fd26ada297c1cf389` | Full architecture: package map, request flow, interfaces, env vars, test commands | 2026-06-24 |
| `94d8f2a261e0acfae0d4c5b3` | Feature audit: what's complete, P0–P4 gaps, security bugs, test gaps | 2026-06-24 |
| `b14cb5b707f71d9dd65d11da` | Implementation progress: P0+P1+P2 done, 57 tests, remaining tasks | 2026-06-24 |

## Usage in Agents

To retrieve in an agent prompt or command, call headroom_retrieve with the hash. The architecture snapshot covers all of `pkg/`, `internal/`, key interfaces, env vars, and build commands — use it instead of re-reading all files when you need a quick orientation.
