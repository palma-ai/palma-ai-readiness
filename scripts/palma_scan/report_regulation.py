"""Offline EU AI Act review inputs, separate from Palma's severity policy.

Legal applicability and compliance cannot be inferred from local configuration.
See references/eu-ai-regulation.md for the sources and evidence crosswalk.
"""

from html import escape

from .governance import governance_layer

_DESK = "https://ai-act-service-desk.ec.europa.eu/en/"
_GUIDANCE = "https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai"

# Exact rule IDs only: review inputs, never tests of the cited articles.
_CONTROL_TOPICS = (
    ("oversight", "Human oversight", "Articles 14 & 26",
     (("Read Article 14", "ai-act/article-14"), ("Read Article 26", "ai-act/article-26")),
     "For high-risk uses, confirm who can supervise, intervene and stop the system. Review these local approval settings as a starting point.",
     frozenset({"permissions-bypassed", "tools-auto-approved", "approval-prompts-disabled",
                "browser-actions-unconfirmed", "unrestricted-folder-access"})),
    ("safeguards", "Technical safeguards", "Article 15", (("Read Article 15", "ai-act/article-15"),),
     "For high-risk uses, review isolation, credentials and connected tools alongside the system’s wider robustness and cybersecurity controls.",
     frozenset({"sandbox-disabled", "mcp-inline-credential", "mcp-static-secret-auth",
                "mcp-network-direct", "mcp-local-unaudited", "hooks-declared",
                "skills-local-unreviewed", "plugins-sideloaded"})),
)

# What each area lacks when the scan finds no governance layer. These are the stated
# assumption of the review aid, not an observation of an absent organizational control.
_NOT_COVERED = {
    "oversight": "Assume human oversight is not covered: nothing beyond this machine’s own approval prompts can supervise, intervene or stop an agent, and nothing records that anyone did.",
    "safeguards": "Assume technical safeguards are not covered: credentials, connected tools and agent actions are governed only by local configuration, with no central policy or audit trail.",
    "transparency": "Assume transparency duties are not covered: nothing records where AI output goes or whether people are told they are interacting with AI.",
    "classification": "Assume risk classification is not covered: no inventory of use cases, purposes and affected people exists outside this scan.",
}
_NEXT_STEPS = {
    "oversight": "Verify the responsible owner and the supervision, intervention and stop controls. Record how they cover this use case.",
    "safeguards": "Verify the responsible owner and evidence for isolation, credentials, connected tools and monitoring. Record how these controls cover this use case.",
}

# Decorative, bundled interface symbols; no external artwork or resources.
_ICONS = {
    "oversight": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
    "safeguards": '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="M9 12h6m-3-3v6"/>',
    "transparency": '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M8 9h8m-8 4h8m-8 4h4"/>',
    "classification": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 17.5h7m-3.5-3.5v7"/>',
}
_CHEVRON = '<svg class="regulation-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><path d="m9 5 7 7-7 7"/></svg>'


def _reference(label: str, url: str) -> str:
    # Destinations are fixed official sources, never snapshot URLs.
    return (f'<a class="regulation-source" href="{escape(url, quote=True)}" rel="noreferrer noopener" target="_blank">'
            f'{escape(label)}<span class="sr-only"> (opens in a new tab)</span></a>')


def _status(observations: list[dict], declared: bool, ungoverned: bool) -> tuple[str, str]:
    if declared:
        return "declared-only", "Not assessed · session only"
    if not observations:
        return "not-assessed", "Not assessed · no AI evidence"
    if ungoverned:
        return "not-covered", "Not covered · no governance layer found"
    return "review-needed", "Use-case review needed"


def _tile(slug: str, title: str, article: str, body: str, state: str, count: int, governance: str) -> str:
    """``governance`` is "none" (local evidence, no governed connector applies), "observed"
    (a governed connector applies) or "unknown" (no local evidence to judge)."""
    icon = f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{_ICONS[slug]}</svg>'
    if count:
        value = f'<span class="regulation-count" data-count="{count}">{count}<span>{"finding" if count == 1 else "findings"} to review</span></span>'
        label = ("Use-case controls not assessed" if state != "review-required"
                 else "Not covered · review required" if governance == "none" else "Review required")
        value += f'<span class="regulation-review-label">{label}</span>'
    elif state == "not-covered":
        value = '<span class="regulation-unknown">Not covered<span>No governance layer found</span></span>'
    elif state == "missing-evidence":
        value = '<span class="regulation-unknown">Coverage not evidenced<span>Owner verification required</span></span>'
    else:
        value = '<span class="regulation-unknown">Not assessed<span>Needs use-case context</span></span>'
    return f'''<details class="regulation-tile" id="regulation-{slug}" data-review-state="{state}" data-governance="{governance}"><summary>
<span class="regulation-tile-top"><span class="regulation-tile-icon">{icon}</span>{_CHEVRON}</span>
<span class="regulation-tile-title">{title}</span><span class="regulation-article">{article}</span>{value}
</summary><div class="regulation-tile-body">{body}</div></details>'''


def render_regulation_section(findings: list[tuple[str, dict]], observations: list[dict], declared: bool) -> str:
    local_evidence = bool(observations) and not declared
    # Local AI evidence without a governed connector that applies as written leaves every
    # area not covered; with one, an unmatched area still needs the owner's coverage evidence.
    ungoverned = local_evidence and not governance_layer(observations)
    governance = "none" if ungoverned else "observed" if local_evidence else "unknown"
    status, label = _status(observations, declared, ungoverned)
    unmatched_state = "not-covered" if ungoverned else "missing-evidence" if local_evidence else "not-assessed"

    def not_covered(slug):
        return f'<p class="regulation-not-covered"><strong>No governance layer found.</strong> {_NOT_COVERED[slug]}</p>' if ungoverned else ""

    tiles = []
    for slug, title, articles, sources, guidance, rule_ids in _CONTROL_TOPICS:
        matched = [(anchor, item) for anchor, item in findings
                   if isinstance(item.get("ruleId"), str) and item["ruleId"] in rule_ids]
        count = len(matched)
        links = ''.join(
            f'<li><a class="regulation-finding-link" href="#{escape(anchor, quote=True)}">'
            f'{escape(str(item.get("title", "Review finding")))}</a></li>'
            for anchor, item in matched)
        evidence = (f'<p class="regulation-evidence-label">{count} existing {"finding" if count == 1 else "findings"}</p><ul>{links}</ul>'
                    if links else '<p>No mapped findings. This scan does not establish coverage of these controls.</p>')
        evidence += not_covered(slug)
        if local_evidence:
            evidence += f'<p><strong>Next step:</strong> {_NEXT_STEPS[slug]}</p>'
        # Each label names exactly the article its link opens.
        articles_html = " · ".join(_reference(label, _DESK + path) for label, path in sources)
        body = f'<p>{guidance}</p>{evidence}<p>{articles_html}</p>'
        tiles.append(_tile(slug, title, articles, body, "review-required" if count and local_evidence else unmatched_state, count, governance))
    tiles.append(_tile("transparency", "Transparency", "Article 50",
        '<p>Check whether people interact with your AI or see its generated content. Notices, marking and disclosure duties depend on the use and your role.</p>'
        + not_covered("transparency") +
        '<p><strong>Next step:</strong> Review customer-facing AI, deepfakes and public-interest text, including relevant exceptions. Published outputs are not inspected by this scan.</p>'
        '<p>Confirm the owner and evidence for the relevant notices and disclosures. This scan does not establish their coverage.</p>'
        f'<p>{_reference("Read Article 50", _DESK + "ai-act/article-50")}</p>', unmatched_state, 0, governance))
    tiles.append(_tile("classification", "Risk classification", "Articles 5 & 6",
        '<p>Prohibited-practice and high-risk rules depend on how a system is used and what it does. Some prohibitions also cover a practice’s effect or reasonably foreseeable outcomes. Tool names and local permissions cannot establish a legal risk class.</p>'
        + not_covered("classification") +
        '<p><strong>Next step:</strong> Document the purpose, affected people and your role. Check prohibited practices, qualifying regulated products and Annex III uses, including exceptions.</p>'
        '<p>Confirm the owner and evidence for the use-case classification. This scan does not establish that a classification review exists.</p>'
        f'<p>{_reference("Prohibited practices", _DESK + "ai-act/article-5")} · {_reference("High-risk criteria", _DESK + "ai-act/article-6")}</p>', unmatched_state, 0, governance))
    notice = ('<p class="regulation-governance"><strong>No governance layer found on this machine.</strong> No connector that applies as written is routed through a Palma-operated gateway, so all four areas are treated as not covered until an owner documents them. Other governance systems are not detected by this scan.</p>'
              if ungoverned else "")
    return f'''<section class="regulation-panel" id="eu-ai-regulation" aria-labelledby="regulation-title">
<div class="regulation-heading" id="regulation-indicator" data-status="{status}"><div class="regulation-identity"><span class="regulation-mark" aria-hidden="true"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/></svg></span><div><h2 id="regulation-title">EU AI Act</h2><p>Four areas for your AI review</p></div></div><span class="regulation-status">{label}</span></div>
{notice}<div class="regulation-tiles">{''.join(tiles)}</div>
<div class="regulation-footer"><p>Local review signals · Compliance not assessed</p>{_reference("Official EU AI Act guidance ↗", _GUIDANCE)}</div>
</section>'''
