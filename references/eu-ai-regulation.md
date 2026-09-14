# EU AI Act overview

Research reviewed **14 September 2026**. The report addresses the **EU AI Act,
Regulation (EU) 2024/1689**, including the July 2026 AI Omnibus amendments. It is
an offline review aid for the owner of an AI use case, not a compliance score,
legal opinion, certification, or automated legal risk classification.

## What the report can establish

The scanner sees local declarations and selected runtime metadata. It does not
collect intended business purposes, EU market/deployment facts, affected persons,
provider/deployer roles, published outputs, training records, conformity assessments,
or organisation-wide controls. Those facts are needed for a regulatory review.

| Evidence | Indicator |
| --- | --- |
| Endpoint or copied-home snapshot with observations and no governance layer | **Not covered · no governance layer found** |
| Endpoint or copied-home snapshot with observations and a governed connector | **Use-case review needed** |
| Snapshot with no observations | **Not assessed · no AI evidence** |
| Declared snapshot, including an empty one | **Not assessed · session only** |

A governance layer means a connector routed through a Palma-operated gateway that applies
as written (not switched off, not in an unselected profile, not in a cached policy copy or
an uninstalled pack), the only governance evidence the collector records; other governance
systems are not detected.
All four states leave legal risk class and compliance **not assessed**. Findings,
severity, a clean scan, absent configuration, disabled declarations, device location,
tool names and profile names cannot establish applicability or compliance. A personal
device does not establish purely personal use. The overview is always shown, including
when rebuilding older schema 2.0 snapshots. It does not add findings or change their
severity, IDs, evidence, summary counts or the snapshot schema.

## Research and review questions

- **Scope and role:** identify who provides or deploys each system, EU market or
  deployment connections, and where outputs are used. Article 2 includes certain
  non-EU providers/deployers; its personal-use exclusion concerns natural persons'
  purely personal, non-professional use. [Article 2](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-2).
- **Purpose and classification:** review prohibited practices separately from
  high-risk criteria. Intended purpose is not the only test: some prohibitions also
  cover a practice's objective or effect, and reasonably foreseeable outcomes.
  Article 6 covers qualifying regulated products and Annex III uses, with conditions
  and exceptions. An MCP server or permission bypass does not itself establish a
  prohibited or high-risk use. [Commission risk framework](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai),
  [Article 5](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-5),
  [Article 6](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-6).
- **Transparency:** distinguish provider interaction/marking duties from deployer
  disclosures for specified uses, including deepfakes and public-interest text.
  Exceptions matter; installing a generative tool proves neither publication nor a
  missing disclosure. [Article 50](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50).
- **Operational review:** for applicable high-risk systems, assess human oversight,
  operating instructions, monitoring, logs and technical safeguards. Configurations
  are only possible inputs to this work. [Article 14](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-14),
  [Article 26](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-26),
  [Article 15](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15).

The Digital Omnibus on AI, **Regulation (EU) 2026/1744**, entered into force on
**27 July 2026**. Among other changes it replaced Article 4: providers and deployers
must still take measures to support the development of AI literacy, but the Act no
longer requires them to guarantee a specific level. Local configuration cannot show
whether such measures exist, so never treat missing local training records as a
breach. Some AI Act Service Desk article pages state that their text has not yet been
updated for the amendments; check amended provisions against the Official Journal.
[Regulation (EU) 2026/1744](https://eur-lex.europa.eu/eli/reg/2026/1744/oj),
[Commission amendment summary](https://digital-strategy.ec.europa.eu/en/news/ai-omnibus-enters-force).

Research background for maintainers (not displayed in the report): original prohibitions from
2 February 2025; GPAI model rules from 2 August 2025, subject to transitions; Article
50 from 2 August 2026; new prohibited practices and a specific Article 50(2) transition
on 2 December 2026; Annex III high-risk rules from 2 December 2027; and regulated-product
high-risk rules from 2 August 2028. These dates do not decide an individual system's
deadline. [Current Commission timeline](https://ai-act-service-desk.ec.europa.eu/en/ai-act/timeline/timeline-implementation-eu-ai-act).

## Public report layout

Use **EU AI Act** as the heading. Place the panel as a collapsed section after the
inventory and before coverage, with four compact tiles: Human oversight, Technical safeguards,
Transparency and Risk classification. The first two show counts of mapped findings
when available with **Review required**. For a local inventory with no governance
layer, the panel status reads **Not covered · no governance layer found**, a notice
says that all four areas are treated as not covered until an owner documents them,
every area without mapped findings says **Not covered** with **No governance layer
found**, and mapped-finding areas say **Not covered · review required**. This is the
review aid's stated assumption for an ungoverned machine: without a governance layer,
assume nobody can supervise, intervene, stop, record or classify the agent's use. It is
not an observation of an absent organizational control, and other governance systems
are not detected. With a governed connector, zero matches and the other areas say
**Coverage not evidenced**, with **Owner verification required**: a gateway alone
cannot establish coverage of these four review areas. Empty and declared inventories
retain **Not assessed**. Native
`details` reveal guidance and original finding links. The default view uses labels
and counts. The footer has a brief assessment boundary and one official EU AI Act
guidance link. Do not add a scope explainer, timeline or legislative background
section to the report.
Do not repeat another regulation section below the findings. The highlighted
navigation link returns to this panel.

## Local evidence crosswalk

`scripts/palma_scan/report_regulation.py` links only existing findings with these exact
rule IDs. It never evaluates raw settings, matches words in names, or infers missing
controls. These are Palma's selected review inputs, not official regulatory tests or
an exhaustive mapping of the findings catalog.

| Review topic | Existing rule IDs |
| --- | --- |
| Human oversight (Articles 14 and 26) | `permissions-bypassed`, `tools-auto-approved`, `approval-prompts-disabled`, `browser-actions-unconfirmed`, `unrestricted-folder-access` |
| Technical safeguards (Article 15) | `sandbox-disabled`, `mcp-inline-credential`, `mcp-static-secret-auth`, `mcp-network-direct`, `mcp-local-unaudited`, `hooks-declared`, `skills-local-unreviewed`, `plugins-sideloaded` |

Counts describe finding records, including grouped findings, not systems, violations
or failed legal controls. Preserve Low findings and inactive/profile-specific evidence;
the link opens the original finding with its context. Unmapped findings remain in the
normal findings section. No matching findings leaves the control unassessed and,
when local AI evidence exists, marks the area not covered (no governance layer) or
highlights the missing coverage evidence (governed connector present). Each area
asks the owner to verify and document the relevant controls or review.

## Offline and maintenance contract

The overview, review prompts and official guidance links are embedded; no extra CLI flag,
questionnaire, dependency, lookup, upload or network request is introduced. Official
links open only on explicit clicks, without scan data. Research dates remain in this reference, independent of the wall clock and
original scan timestamp. The
research review date is kept in this reference, not displayed in the report. Identical
snapshots and options render identical HTML. Rebuilding with a newer renderer uses its
bundled guidance while preserving the saved evidence.

Before updating legal wording or dates, check the current amended law and Commission
guidance, distinguish enacted changes from proposals, update this reference's review date and
reference, and inspect a fictional demo. The original and amending legal texts are
available from the [Commission AI Act page](https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai).
This feature does not assess GDPR or other EU/national regimes. The
[Commission compliance checker](https://ai-act-service-desk.ec.europa.eu/en/eu-ai-act-compliance-checker)
provides a separate starting point for a fuller applicability review.
