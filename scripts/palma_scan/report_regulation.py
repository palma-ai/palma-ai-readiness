"""Offline EU AI Act review inputs, separate from Palma's severity policy.

Legal applicability and compliance cannot be inferred from local configuration.
See references/eu-ai-regulation.md for the sources and evidence crosswalk.
"""

from html import escape


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


def _status(observations: list[dict], declared: bool) -> tuple[str, str]:
    if declared:
        return "declared-only", "Not assessed · session only"
    if observations:
        return "review-needed", "Use-case review needed"
    return "not-assessed", "Not assessed · no AI evidence"


def _tile(slug: str, title: str, article: str, body: str, count: int = 0) -> str:
    icon = f'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{_ICONS[slug]}</svg>'
    value = (f'<span class="regulation-count" data-count="{count}">{count}<span>{"finding" if count == 1 else "findings"} to review</span></span>'
             if count else '<span class="regulation-unknown">Not assessed<span>Needs use-case context</span></span>')
    return f'''<details class="regulation-tile" id="regulation-{slug}"><summary>
<span class="regulation-tile-top"><span class="regulation-tile-icon">{icon}</span>{_CHEVRON}</span>
<span class="regulation-tile-title">{title}</span><span class="regulation-article">{article}</span>{value}
</summary><div class="regulation-tile-body">{body}</div></details>'''


def render_regulation_section(findings: list[tuple[str, dict]], observations: list[dict], declared: bool) -> str:
    status, label = _status(observations, declared)
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
                    if links else '<p>No mapped findings. The control remains unassessed.</p>')
        # Each label names exactly the article its link opens.
        articles_html = " · ".join(_reference(label, _DESK + path) for label, path in sources)
        body = f'<p>{guidance}</p>{evidence}<p>{articles_html}</p>'
        tiles.append(_tile(slug, title, articles, body, count))
    tiles.append(_tile("transparency", "Transparency", "Article 50",
        '<p>Check whether people interact with your AI or see its generated content. Notices, marking and disclosure duties depend on the use and your role.</p>'
        '<p><strong>Next step:</strong> Review customer-facing AI, deepfakes and public-interest text, including relevant exceptions. Published outputs are not inspected by this scan.</p>'
        f'<p>{_reference("Read Article 50", _DESK + "ai-act/article-50")}</p>'))
    tiles.append(_tile("classification", "Risk classification", "Articles 5 & 6",
        '<p>Prohibited-practice and high-risk rules depend on how a system is used and what it does. Some prohibitions also cover a practice’s effect or reasonably foreseeable outcomes. Tool names and local permissions cannot establish a legal risk class.</p>'
        '<p><strong>Next step:</strong> Document the purpose, affected people and your role. Check prohibited practices, qualifying regulated products and Annex III uses, including exceptions.</p>'
        f'<p>{_reference("Prohibited practices", _DESK + "ai-act/article-5")} · {_reference("High-risk criteria", _DESK + "ai-act/article-6")}</p>'))
    return f'''<section class="regulation-panel" id="eu-ai-regulation" aria-labelledby="regulation-title">
<div class="regulation-heading" id="regulation-indicator" data-status="{status}"><div class="regulation-identity"><span class="regulation-mark" aria-hidden="true">EU</span><div><h2 id="regulation-title">EU AI Act</h2><p>Four areas for your AI review</p></div></div><span class="regulation-status">{label}</span></div>
<div class="regulation-tiles">{''.join(tiles)}</div>
<div class="regulation-footer"><p>Local review signals · Compliance not assessed</p>{_reference("Official EU AI Act guidance ↗", _GUIDANCE)}</div>
</section>'''
