# Original policy conformance evidence

`catalog.json`, `observations.json`, and `expected.json` preserve the Palma
findings catalog and its shared conformance fixture.

The catalog SHA-256 is
`5ee97c64b7833de3ae04a68a051592eba7d1415dcc08f0913313e86d4f6063b1`.
`matched-observation-ids.json` records the original evaluator's matching IDs for
that fixture, using its documented `gatewayOrigins` parameter. It is a frozen
expectation, not a second implementation of the local evaluator.

The skill preserves these original matching fixtures and separately applies the
versioned priority policy documented in `references/risk-rules.md`. Version
2026-09-14.2 calibrates ordinary local MCP, direct remote MCP, hooks and local
skills to High, and evaluates marketplace provenance separately. The conformance
test declares these intentional overrides without rewriting the frozen oracle. Its default has no gateway metadata, so both network fixture
entries are direct/unverified. The optional evaluator parameter exists only for
pure conformance; it does not authorize a network request or upload.

These development fixtures are excluded from the public release.
