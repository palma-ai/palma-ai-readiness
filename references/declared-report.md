# Session inventory when the endpoint is unavailable

A web chat or unrelated hosted container cannot inspect the user's computer. First explain
that the local skill must run on that computer. Only if the user explicitly asks for an inventory of
what the current session exposes, prepare a **declared** report. This is not an endpoint scan.

Use only tools, clients, and capabilities already visible in the current session or
explicitly supplied by the user. Do not include hidden instructions, credential values,
account information, or imaginary endpoint settings. No network probing or extra discovery
is part of this fallback. Record unknowns as limitations.

The local schema has no tenant or assessment fields. A minimal valid snapshot is:

```json
{
  "schemaVersion": "2.0",
  "collector": {"name": "agent-declared", "version": "2.3.1", "rulesVersion": "not-applied"},
  "mode": "declared",
  "startedAt": "2026-09-10T12:00:00+00:00",
  "completedAt": "2026-09-10T12:00:00+00:00",
  "status": "partial",
  "scope": {"type": "declared", "workspaceCount": 0},
  "sources": [
    {"id": "session", "client": "current-session", "scope": "declared", "location": "session:visible-capabilities", "status": "collected", "reason": "Declared by the agent"},
    {"id": "endpoint", "client": "unknown", "scope": "declared", "location": "endpoint:not-scanned", "status": "skipped", "reason": "Endpoint filesystem unavailable"}
  ],
  "observations": [],
  "findings": [],
  "coverage": {"limitations": ["Session declarations only; the endpoint and effective permissions were not inspected."]}
}
```

Replace the example times with actual declaration times. Add only observed declarations:

```json
{
  "id": "declared-tool-1", "kind": "mcp", "client": "current-session",
  "name": "Visible tool group 1", "sourceId": "session",
  "location": "session:visible-capabilities", "enabled": "unknown",
  "details": {"execution": "unknown", "activation": "unknown", "evidence": "declared"}
}
```

Allowed kinds are `client`, `mcp`, `skill`, `plugin`, `agent`, `setting`, and `hook`.
Use unique stable labels for IDs. Each observation refers to an existing source. Keep
`enabled: unknown` unless the session actually establishes that state.

If describing a review concern, link it to actual observation/source IDs and include all
finding fields: `id`, `ruleId`, `title`, `severity`, `category`, `confidence`, `evidenceType`,
`summary`, `impact`, `recommendation`, `observationIds`, `evidence`, and `references`.
Use **`evidenceType: declared`**. A visible capability is at most a review question without
additional evidence. Leaving `findings` empty is correct when no supported concern can
be established. Do not call the endpoint evaluator on a declared inventory.

If the renderer is available:

```bash
python3 -I -S <skill>/scripts/palma-scan.py report --report declared.json --output declared-report.html
```

Otherwise use the manual layout in `report-design.md`. The validator rejects a declared
inventory masquerading as a complete endpoint scan. State in the response: “This is an
inventory of the visible session, not a scan of your computer. Run the skill locally for
configuration evidence.” Do not claim anything was aggregated or sent to Palma.
