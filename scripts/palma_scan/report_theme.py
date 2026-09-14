"""Palma's light report theme. Every resource is embedded in the generated HTML."""

from .report_font import ONEST_BASE64


CSS = (
    '@font-face{font-family:Onest;font-style:normal;font-weight:100 900;'
    'font-display:swap;src:url(data:font/ttf;base64,' + ONEST_BASE64 + ') format("truetype")}\n'
) + r"""
/* Palma Brand Motion 1.0.1: light surfaces, Onest, teal accents, quiet motion. */
:root {
  color-scheme: light;
  --ink: #0f172a; --muted: #475569; --faint: #536477;
  --brand: #007a93; --teal: #00a9c7; --brand-light: #ecfeff;
  --line: #e2e8f0; --surface: #f6fafc; --white: #fff;
  --gradient: linear-gradient(to right, #43A1D0, #33C0D0);
  --critical: #a52732; --high: #b14720; --medium: #91610c;
  --low: #187480; --info: #64748b;
  --radius: 22px; --card-radius: 16px;
  --shadow: 0 10px 15px -3px rgba(15,23,42,.06), 0 4px 6px -2px rgba(15,23,42,.03);
  --ease: cubic-bezier(.16,1,.3,1);
  font-family: Onest, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  font-synthesis: none;
}
* { box-sizing: border-box }
html { scroll-behavior: smooth; scroll-padding-top: 104px }
body {
  margin: 0; color: var(--ink); font-size: 15px; line-height: 1.65;
  background: radial-gradient(90% 120% at 8% 0%,rgba(51,192,208,.16),rgba(51,192,208,0) 60%),
    linear-gradient(135deg,#eef7fa 0%,#f6fbfc 52%,#e9f4f8 100%);
  background-size: 100% 720px, 100% 100%; background-repeat: no-repeat;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--brand); text-decoration: none }
a:hover { text-decoration: underline }
button,input { font: inherit }
button,summary { cursor: pointer }
button:disabled { cursor: default; opacity: .6 }
a,button,input,summary { touch-action: manipulation }
a,button,summary { transition: background-color .22s var(--ease),border-color .22s var(--ease),box-shadow .22s var(--ease),color .22s var(--ease) }
:is(button,a,summary,input):focus-visible { outline: 3px solid var(--brand); outline-offset: 4px; border-radius: 6px }
h1,h2,h3,h4,p { margin: 0 }
h1,h2,h3 { letter-spacing: -.035em; text-wrap: balance; font-weight: 700 }
h1 { font-size: clamp(32px,4vw,48px); line-height: 1.13 }
h2 { font-size: 28px; line-height: 1.25 }
h3 { line-height: 1.4 }
strong { font-weight: 600 }
code,pre { font-family: ui-monospace,SFMono-Regular,Consolas,monospace }
code { font-size: .85em; overflow-wrap: anywhere }
pre { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; line-height: 1.7 }
.icon { flex: none; vertical-align: middle }
.muted { color: var(--muted) }
[hidden] { display: none!important }
.sr-only { position: absolute; width: 1px; height: 1px; padding: 0; margin: -1px; overflow: hidden; clip: rect(0,0,0,0); white-space: nowrap; border: 0 }
.js-only { display: none }
.js .js-only { display: flex }
.skip-link { position: absolute; top: -80px; left: 20px; z-index: 99; background: var(--white); padding: 12px }
.skip-link:focus { top: 12px }
.shell { width: min(1180px,calc(100% - 80px)); margin: auto }
.eyebrow { display: flex; gap: 9px; align-items: center; color: var(--brand); font-size: 11px; font-weight: 600; letter-spacing: .13em; text-transform: uppercase; margin-bottom: 12px }
.eyebrow:before { content: ""; width: 18px; height: 3px; border-radius: 3px; background: var(--gradient) }

/* A compact EU AI Act overview follows the priorities; each area expands in place. */
.regulation-panel { --eu-blue: #2357af; --eu-pale: #f4f7fd; margin: 24px 0 0; padding: 24px 26px 0; border: 1px solid #cbd9ed; border-top: 3px solid var(--eu-blue); border-radius: var(--radius); background: var(--white); box-shadow: var(--shadow); overflow-wrap: anywhere }
.regulation-heading { display: flex; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 22px }
.regulation-identity { display: flex; align-items: center; gap: 14px; min-width: 0 }.regulation-mark { display: grid; place-items: center; width: 48px; height: 48px; flex: none; border-radius: 13px; background: var(--eu-blue); color: #fff; font-size: 23px; font-weight: 700; letter-spacing: -.06em }.regulation-identity h2 { font-size: 26px; line-height: 1.15 }.regulation-identity p { margin-top: 5px; color: var(--muted); font-size: 13px }
.regulation-status { display: inline-flex; align-items: center; gap: 7px; padding: 6px 10px; border: 1px solid #dbe3ee; border-radius: 7px; color: var(--muted); background: var(--surface); font-size: 12px; font-weight: 500 }.regulation-status:before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: currentColor; flex: none }.regulation-heading[data-status="review-needed"] .regulation-status { color: #795514; background: #fff8e8; border-color: #eddfb8 }
.regulation-tiles { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 12px; align-items: start }
.regulation-tile { min-width: 0; background: var(--eu-pale); border: 1px solid #dce5f3; border-radius: 13px; overflow: hidden }
.regulation-tile>summary { display: flex; flex-direction: column; padding: 16px 17px; min-height: 174px; list-style: none; color: var(--ink) }.regulation-tile>summary:hover { background: #eaf0fc }.regulation-tile[open]>summary { background: #eaf0fc }.regulation-tile>summary:focus-visible { outline-offset: -4px }
.regulation-tile-top { display: flex; justify-content: space-between; align-items: center; width: 100%; margin-bottom: 12px }.regulation-tile-icon { display: flex; color: var(--eu-blue) }.regulation-tile-icon svg { width: 23px; height: 23px }.regulation-chevron { flex: none; width: 15px; height: 15px; color: var(--eu-blue); transition: transform .2s var(--ease) }.regulation-tile[open]>summary .regulation-chevron { transform: rotate(90deg) }
.regulation-tile-title { font-size: 15px; font-weight: 600; letter-spacing: -.02em; line-height: 1.3 }.regulation-article { display: block; color: var(--muted); font-size: 12px; margin-top: 3px }
.regulation-count { display: flex; align-items: baseline; gap: 8px; margin-top: 12px; color: var(--eu-blue); font-size: 32px; font-weight: 600; line-height: 1.15; font-variant-numeric: tabular-nums; letter-spacing: -.04em }.regulation-count>span { font-size: 12px; font-weight: 400; color: var(--muted); letter-spacing: 0; line-height: 1.4 }
.regulation-unknown { display: block; color: var(--muted); font-size: 16px; font-weight: 600; margin-top: 14px; line-height: 1.3 }.regulation-unknown>span { display: block; margin-top: 3px; font-size: 12px; font-weight: 400 }
.regulation-tile-body { padding: 16px; background: var(--white); border-top: 1px solid #dce5f3; color: var(--muted); font-size: 13px }.regulation-tile-body p+p { margin-top: 12px }.regulation-tile-body ul { margin: 8px 0 14px; padding-left: 18px }.regulation-tile-body li { margin: 7px 0 }.regulation-evidence-label { color: var(--ink); font-weight: 600 }.regulation-panel a { color: var(--eu-blue) }
.regulation-footer { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-top: 18px; padding: 8px 0; border-top: 1px solid var(--line); font-size: 12px; color: var(--muted) }.regulation-footer>a { display: inline-flex; align-items: center; min-height: 44px; font-weight: 500 }
.main-nav a.regulation-nav { color: #2357af; background: #edf3ff; font-weight: 600 }
@media(max-width:960px) {
  .regulation-tiles { grid-template-columns: repeat(2,minmax(0,1fr)) }.regulation-tile>summary { min-height: 167px }
}
@media(max-width:560px) {
  .regulation-panel { padding: 18px 14px 0; margin-top: 22px }.regulation-heading { align-items: flex-start; flex-direction: column; gap: 12px; margin-bottom: 16px }.regulation-identity h2 { font-size: 24px }.regulation-mark { width: 43px; height: 43px; font-size: 21px }.regulation-identity p { font-size: 12px }.regulation-status { font-size: 12px }
  .regulation-tiles { gap: 9px }.regulation-tile>summary { padding: 13px 11px; min-height: 180px }.regulation-tile-title { font-size: 14px; min-height: 36px }.regulation-tile-top { margin-bottom: 9px }.regulation-tile-icon svg { width: 21px; height: 21px }.regulation-count { font-size: 29px; gap: 6px }.regulation-count>span { font-size: 12px; max-width: 60px }.regulation-unknown { font-size: 15px }.regulation-tile-body { padding: 12px; font-size: 13px }
  .regulation-footer { align-items: flex-start; flex-direction: column; gap: 2px; padding-top: 12px }
}
@media print {
  .regulation-panel { box-shadow: none; margin-bottom: 20px; padding: 16px 16px 0 }.regulation-tiles { grid-template-columns: repeat(2,minmax(0,1fr)) }.regulation-tile { break-inside: avoid; overflow: visible }.regulation-tile>summary { min-height: 0 }.regulation-tile-body { font-size: 10px }.regulation-count { font-size: 24px }.regulation-footer { font-size: 10px }
}

/* A compact masthead leaves the evidence in focus. */
.site-header { position: sticky; top: 0; z-index: 10; background: rgba(255,255,255,.97); border-bottom: 1px solid var(--line) }
.header-inner { min-height: 80px; display: flex; align-items: center; justify-content: space-between; gap: 24px }
.brand { display: flex; align-items: center; gap: 22px; color: var(--ink) }
.brand:hover { text-decoration: none }
.brand img { width: 122px; height: auto; display: block }
.brand-label { border-left: 1px solid var(--line); padding-left: 22px; color: var(--muted); font-size: 12px; line-height: 1.45 }
.main-nav { display: flex; gap: 8px; align-items: center }
.main-nav a { display: inline-flex; align-items: center; min-height: 44px; padding: 8px 12px; border-radius: 10px; color: var(--muted); font-size: 13px; font-weight: 500 }
.main-nav a:hover { background: var(--brand-light); color: var(--brand); text-decoration: none }
.print-button { align-items: center; gap: 8px; min-height: 44px; margin-left: 8px; padding: 9px 13px; border: 1px solid var(--line); border-radius: 10px; background: var(--white); color: var(--ink); font-size: 12px }
.print-button:hover { border-color: var(--brand) }
.print-button .icon { width: 16px; height: 16px }
.report-title { display: flex; justify-content: space-between; align-items: center; gap: 40px; padding: 44px 0 32px }
.title-accent { color: var(--brand) }
.report-subtitle { color: var(--muted); font-size: 16px; margin-top: 14px; max-width: 650px }
.report-meta { flex: 0 1 285px; min-width: 0; display: grid; gap: 10px; border-left: 1px solid #cbdde3; padding-left: 24px; font-size: 12px; color: var(--muted) }
.report-meta>span { display: block; overflow-wrap: anywhere }
.report-meta .meta-label { font-size: 11px; font-weight: 600; color: var(--brand); text-transform: uppercase; letter-spacing: .1em }
.scope-banner,.mode-banner { display: flex; align-items: flex-start; gap: 12px; padding: 14px 20px; margin: 0 0 20px; border: 1px solid #c1e0e6; border-radius: var(--card-radius); background: #effbfc; color: #235c6b; font-size: 13px }
.scope-banner strong { overflow-wrap: anywhere }
.scope-banner .icon,.mode-banner .icon { margin-top: 3px; width: 18px; height: 18px }
.mode-banner { background: #fffbeb; border-color: #ead5a6; color: #735019 }
.mode-banner strong { display: block; margin-bottom: 4px }

/* Review first: actionable cards and a count-based priority graphic. */
.overview { position: relative; background: var(--white); border: 1px solid var(--line); border-radius: var(--radius); box-shadow: var(--shadow); overflow: hidden }
.overview:before { content: ""; display: block; height: 4px; background: var(--gradient) }
.overview-intro { padding: 28px 30px 0 }
.overview-intro h2 { font-size: clamp(25px,2.5vw,32px) }
.overview-intro>p:last-child { color: var(--muted); font-size: 14px; margin-top: 10px; max-width: 740px }
.overview-grid { display: grid; grid-template-columns: minmax(0,1.85fr) minmax(280px,1fr); gap: 24px; padding: 24px 30px 30px }
.priority-list { display: flex; flex-direction: column; gap: 10px }
.priority-item { display: flex; gap: 14px; align-items: flex-start; padding: 17px 18px; border: 1px solid var(--line); border-radius: var(--card-radius); color: var(--ink); background: var(--white) }
.priority-item:hover { text-decoration: none; border-color: #a6d5df; background: #f7fcfd; box-shadow: 0 3px 10px rgba(15,23,42,.04) }
.priority-item:hover strong { color: var(--brand) }
.priority-index { display: flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 9px; background: var(--surface); color: var(--faint); font-size: 11px; font-weight: 600; flex: none; font-variant-numeric: tabular-nums }
.priority-copy { flex: 1; min-width: 0 }
.priority-meta { overflow-wrap: anywhere; display: flex; gap: 8px 12px; flex-wrap: wrap; align-items: center; margin-bottom: 7px; color: var(--faint); font-size: 11px }
.priority-copy strong { display: block; font-size: 15px; line-height: 1.45; letter-spacing: -.02em; overflow-wrap: anywhere }
.priority-action { display: block; color: var(--muted); margin-top: 7px; font-size: 12px; line-height: 1.6; overflow-wrap: anywhere }
.priority-item>.icon { margin-top: 5px; width: 17px; height: 17px; color: var(--brand) }
.priority-chart { background: var(--surface); border: 1px solid var(--line); border-radius: var(--card-radius); padding: 20px 22px }
.chart-heading { display: flex; justify-content: space-between; align-items: center; gap: 12px }
.chart-heading h3 { font-size: 14px; letter-spacing: -.02em }
.chart-heading>span { color: var(--faint); font-size: 12px }
.priority-ring { position: relative; width: 134px; height: 134px; margin: 17px auto }
.priority-ring svg { display: block; width: 100%; height: 100%; transform: rotate(-90deg) }
.ring-track { fill: none; stroke: var(--line); stroke-width: 10 }
.ring-segment { fill: none; stroke-width: 10 }
.ring-critical { stroke: var(--critical) }.ring-high { stroke: var(--high) }.ring-medium { stroke: var(--medium) }.ring-low { stroke: var(--low) }.ring-info { stroke: var(--info) }
.ring-center { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; font-size: 11px; color: var(--faint) }
.ring-center strong { font-size: 34px; line-height: 1.1; color: var(--ink); letter-spacing: -.05em; font-variant-numeric: tabular-nums }
.chart-row { display: grid; grid-template-columns: 55px minmax(0,1fr) 25px; gap: 12px; align-items: center; margin: 9px 0 }
.chart-label,.chart-number { font-size: 12px; color: var(--muted) }
.chart-number { text-align: right; color: var(--ink); font-weight: 600; font-variant-numeric: tabular-nums }
.bar-chart { width: 100%; height: 7px }
.bar-track { fill: var(--line) }
.bar-critical { fill: var(--critical) }.bar-high { fill: var(--high) }.bar-medium { fill: var(--medium) }.bar-low { fill: var(--low) }.bar-info { fill: var(--info) }
.chart-footnote { color: var(--faint); font-size: 12px; line-height: 1.6; padding-top: 12px; margin-top: 14px; border-top: 1px solid var(--line) }
.empty-priorities { display: flex; align-items: flex-start; gap: 14px; padding: 24px 0; color: var(--muted); font-size: 14px }
.severity { display: inline-flex; align-items: center; gap: 6px; font-size: 11px; line-height: 1.5; font-weight: 600; white-space: nowrap; color: var(--info); padding: 3px 8px; border-radius: 6px; background: #f1f5f9 }
.severity-dot { width: 5px; height: 5px; border-radius: 50%; background: currentColor }
.severity-critical { color: var(--critical); background: #fdf0f1 }.severity-high { color: var(--high); background: #fff3ec }.severity-medium { color: var(--medium); background: #fffae9 }.severity-low { color: var(--low); background: #eaf7f8 }

/* Inventory metrics use the same white surfaces as the public Palma vignettes. */
.metric-strip { display: grid; grid-template-columns: repeat(4,minmax(0,1fr)); gap: 16px; margin-top: 22px }
.metric { position: relative; display: flex; flex-direction: column; align-items: flex-start; padding: 22px; border: 1px solid var(--line); border-radius: var(--card-radius); background: var(--white); box-shadow: var(--shadow); color: var(--ink) }
.metric:hover { text-decoration: none; border-color: #a6d5df; background: #fbfeff }
.metric-icon { display: flex; align-items: center; justify-content: center; width: 36px; height: 36px; margin-bottom: 15px; border: 1px solid #dceff3; background: #effafc; border-radius: 11px; color: var(--brand) }
.metric-icon .icon { width: 19px; height: 19px }
.metric-number { display: block; font-size: 36px; font-weight: 600; letter-spacing: -.05em; line-height: 1.15; font-variant-numeric: tabular-nums }
.metric-label { display: flex; align-items: center; justify-content: space-between; gap: 12px; width: 100%; margin-top: 7px; font-size: 13px; color: var(--muted) }
.metric-label .icon { width: 15px; height: 15px; color: var(--brand) }
.metric-context { font-size: 12px; color: var(--faint); margin: 12px 0 0 }
.client-overview { display: flex; align-items: center; gap: 20px; margin-top: 22px }
.client-overview>span { font-size: 12px; color: var(--faint); flex: none }
.client-overview ul { display: flex; gap: 8px; flex-wrap: wrap; list-style: none; margin: 0; padding: 0 }
.client-overview a { display: flex; align-items: center; gap: 8px; min-height: 44px; padding: 8px 11px; border: 1px solid var(--line); border-radius: 10px; background: var(--white); color: var(--muted); font-size: 12px }
.client-overview a:hover { background: #f1fcfd; border-color: #a6d5df; text-decoration: none }
.client-overview .brand-icon { width: 20px; height: 20px }
.access-overview { display: grid; grid-template-columns: minmax(0,1.5fr) minmax(0,1fr); gap: 30px; margin-top: 28px; padding: 28px 30px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--white); box-shadow: var(--shadow) }
.access-heading { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 18px }
.access-heading h2 { font-size: 20px }
.access-heading a { display: inline-flex; align-items: center; gap: 6px; min-height: 44px; font-size: 12px }
.access-heading .icon { width: 15px; height: 15px }
.access-chart-row { display: grid; grid-template-columns: 164px minmax(0,1fr) 26px; gap: 12px; align-items: center; margin: 14px 0; font-size: 12px; color: var(--muted) }
.access-chart-row strong { text-align: right; color: var(--ink); font-size: 13px; font-variant-numeric: tabular-nums }
.access-bar { width: 100%; height: 6px }
.reach-local { fill: #007a93 }.reach-loopback { fill: #43A1D0 }.reach-remote { fill: #33C0D0 }.reach-unknown { fill: #94a3b8 }
.access-note { background: var(--surface); border: 1px solid var(--line); border-radius: var(--card-radius); padding: 22px }
.access-note-icon { display: inline-flex; color: var(--brand); margin-bottom: 12px }
.access-note h3 { font-size: 14px; letter-spacing: -.02em; margin-bottom: 8px }
.access-note p { color: var(--muted); font-size: 13px; line-height: 1.7 }
.access-note .access-state-note { margin-top: 12px; font-size: 12px; color: var(--faint) }

/* Findings and their evidence are one continuous reading surface. */
.report-section { padding-top: 48px; scroll-margin-top: 18px }
.section-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 24px; margin-bottom: 24px }
.section-heading p:not(.eyebrow) { margin-top: 9px; font-size: 14px; color: var(--muted) }
.section-count { display: inline-flex; min-width: 44px; min-height: 44px; align-items: center; justify-content: center; padding: 6px 11px; border: 1px solid #d2e5eb; border-radius: 12px; background: #f0fafc; color: var(--brand); font-size: 16px; font-weight: 600; font-variant-numeric: tabular-nums }
.findings-toolbar { justify-content: space-between; align-items: center; gap: 16px; padding: 12px; border: 1px solid var(--line); border-radius: var(--card-radius); background: var(--white) }
.filters { display: flex; gap: 5px; flex-wrap: wrap }
.filter-button { display: inline-flex; align-items: center; gap: 8px; padding: 9px 11px; min-height: 44px; border: 1px solid transparent; border-radius: 10px; background: transparent; color: var(--muted); font-size: 12px; font-weight: 500 }
.filter-button span { font-size: 11px; font-variant-numeric: tabular-nums }
.filter-button:hover { background: var(--surface) }
.filter-button[aria-pressed=true] { background: #e9f8fb; border-color: #b9dfe7; color: #006a80 }
.search-field { display: flex; align-items: center; gap: 9px; min-width: 240px; min-height: 44px; padding: 10px 12px; border: 1px solid var(--line); border-radius: 10px; background: var(--white) }
.search-field .icon { width: 17px; height: 17px; color: var(--faint) }
.search-field input { width: 100%; min-width: 0; border: 0; color: var(--ink); background: transparent; font-size: 13px }
.search-field input::placeholder { color: var(--faint) }
.results-toolbar { align-items: center; justify-content: space-between; gap: 18px; margin: 10px 2px 14px; color: var(--faint); font-size: 12px }
.text-button { display: inline-flex; align-items: center; min-height: 44px; border: 0; padding: 6px 0; color: var(--brand); background: transparent; font-size: 12px; font-weight: 600 }
.text-button:hover { text-decoration: underline }
.finding { --priority-line: #cbd5e1; position: relative; border: 1px solid var(--line); border-radius: var(--card-radius); margin-bottom: 18px; padding: 26px 28px 0; background: var(--white); box-shadow: 0 3px 10px rgba(15,23,42,.025); scroll-margin-top: 20px; overflow: hidden }
.finding:before { content: ""; position: absolute; left: 0; top: 24px; width: 3px; height: 32px; border-radius: 0 3px 3px 0; background: var(--priority-line) }
.finding[data-severity=critical] { --priority-line: var(--critical) }.finding[data-severity=high] { --priority-line: var(--high) }.finding[data-severity=medium] { --priority-line: var(--medium) }.finding[data-severity=low] { --priority-line: var(--low) }
.finding:target { border-color: #84c7d4; box-shadow: 0 0 0 3px #dff3f7 }
.finding-topline { display: flex; align-items: center; gap: 10px 14px; flex-wrap: wrap; margin-bottom: 13px; font-size: 12px; color: var(--faint) }
.finding-clients { display: flex; gap: 12px; flex-wrap: wrap; margin-left: auto }
.finding h3 { font-size: 21px; overflow-wrap: anywhere }
.finding-summary { font-size: 15px; color: var(--muted); margin-top: 10px; max-width: 940px; overflow-wrap: anywhere }
.next-step { display: flex; gap: 12px; padding: 17px 18px; margin: 19px 0 22px; border: 1px solid #e2eff2; border-radius: 12px; background: #f3fafb }
.next-step>.icon { color: var(--brand); width: 17px; height: 17px; margin-top: 3px }
.next-step h4 { color: var(--brand); font-size: 12px; font-weight: 600; margin-bottom: 5px }
.next-step p { font-size: 14px; line-height: 1.7; overflow-wrap: anywhere }
.finding-evidence { margin: 0 -28px; border-top: 1px solid var(--line); background: #fbfdfe }
summary::-webkit-details-marker { display: none }
.finding-evidence>summary { display: flex; gap: 12px; align-items: center; min-height: 52px; padding: 13px 28px; list-style: none; font-size: 12px; font-weight: 500 }
.finding-evidence>summary:hover { background: #f0f8fa; color: var(--brand) }
.evidence-count { margin-left: auto; font-size: 12px; color: var(--faint); font-weight: 400 }
.disclosure-icon { width: 15px; height: 15px; transition: transform .22s var(--ease) }
details[open]>summary>.disclosure-icon { transform: rotate(180deg) }
.evidence-content { border-top: 1px solid var(--line); padding: 24px 28px }
.impact h4,.finding-impact h4 { font-size: 13px; margin-bottom: 8px }
.impact p,.finding-impact p { font-size: 14px; color: var(--muted); overflow-wrap: anywhere }
.finding-impact { margin-top: 16px; max-width: 940px }
.rating-reason { margin-top: 18px }
.evidence-meta { display: flex; gap: 8px 20px; flex-wrap: wrap; margin: 20px 0 15px; font-size: 12px; color: var(--faint) }
.evidence-meta code { font-size: 12px }
.evidence-list { list-style: none; margin: 0; padding: 0 }
.evidence-row { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1.3fr); gap: 6px 22px; padding: 14px 0; border-bottom: 1px solid var(--line) }
.evidence-row:last-child { border-bottom: 0 }
.evidence-identity { display: flex; flex-direction: column; align-items: flex-start; gap: 4px; min-width: 0; font-size: 13px }
.evidence-where { grid-column: 1/-1; min-width: 0 }
.fact-list { display: flex; flex-wrap: wrap; align-items: center; align-content: flex-start; gap: 6px; min-width: 0 }
.fact { display: inline-flex; align-items: center; min-height: 24px; padding: 2px 8px; border: 1px solid var(--line); border-radius: 6px; background: var(--surface); color: var(--muted); font-size: 12px; line-height: 1.4; overflow-wrap: anywhere }
.fact-risk { color: #8a2f1b; background: #fff4ef; border-color: #f3d5c7 }.fact-good { color: #006577; background: #eaf8fb; border-color: #bfe3ea }
code.fact-setting { color: var(--ink); background: var(--white); font-size: 12px }
.fact-finding { font-weight: 600 }.fact-finding:hover { text-decoration: underline }
.fact-critical { color: var(--critical); background: #fdf0f1; border-color: #f2cdd1 }.fact-high { color: var(--high); background: #fff3ec; border-color: #f3d3c2 }.fact-medium { color: var(--medium); background: #fffae9; border-color: #efdfb0 }.fact-low,.fact-info { color: var(--low); background: #eaf7f8; border-color: #c7e6ea }
.evidence-more { margin-top: 6px }.evidence-more>summary,.locations>summary { display: inline-flex; align-items: center; gap: 6px; min-height: 36px; list-style: none; color: var(--brand); font-size: 12px; font-weight: 600 }
.evidence-omitted { font-size: 12px; margin-top: 8px }
.inventory-path { display: block; font-size: 12px; color: var(--muted); overflow-wrap: anywhere }
.locations ul { list-style: none; margin: 4px 0 0; padding: 8px 12px; background: var(--surface); border: 1px solid var(--line); border-radius: 10px }.locations li { padding: 4px 0; font-size: 12px }
.location-count { display: block; margin-top: 4px; font-size: 12px; color: var(--faint) }
.reference-links { display: flex; flex-wrap: wrap; align-items: center; gap: 8px 18px; margin-top: 18px; font-size: 12px }
.reference-links>span { color: var(--faint) }.reference-links a { display: inline-flex; gap: 6px; align-items: center; min-height: 44px }.reference-links .icon { width: 13px; height: 13px }
.section-note { font-size: 12px; color: var(--faint); margin-top: 16px; max-width: 900px }
.empty-state { display: flex; align-items: flex-start; gap: 16px; padding: 28px; border: 1px solid var(--line); border-radius: var(--card-radius); background: var(--white) }
.empty-state>.icon { color: var(--brand); margin-top: 3px }.empty-state h3 { font-size: 18px; margin-bottom: 8px }.empty-state p { color: var(--muted); font-size: 14px }
.inline-link { display: inline-flex; align-items: center; gap: 8px; min-height: 44px; font-size: 13px; margin-top: 12px }

/* Named inventory stays compact, with technical metadata behind disclosures. */
.inventory-toolbar { gap: 16px; align-items: center; margin-bottom: 18px }
.inventory-toolbar .search-field { flex: 1; max-width: 550px }.inventory-toolbar>p { margin: 0; color: var(--faint); font-size: 12px }
.inventory-list { display: grid; gap: 10px }
.inventory-group { min-width: 0; border: 1px solid var(--line); border-radius: var(--card-radius); background: var(--white); overflow: hidden }
.inventory-group>summary { display: flex; align-items: center; gap: 16px; min-height: 82px; padding: 18px 22px; list-style: none }
.inventory-group>summary:hover { background: #f7fcfd }.inventory-group>summary:hover strong { color: var(--brand) }
.inventory-group-icon { display: flex; align-items: center; justify-content: center; flex: none; width: 38px; height: 38px; border: 1px solid #dceaf0; border-radius: 11px; background: var(--surface); color: var(--brand) }
.inventory-kind { display: flex; align-items: baseline; gap: 28px; flex: 1; min-width: 0 }.inventory-kind strong { min-width: 215px; font-size: 15px; line-height: 1.5 }.inventory-kind>span { color: var(--faint); font-size: 12px }
.inventory-count { padding: 3px 9px; min-width: 33px; border-radius: 8px; background: var(--surface); text-align: center; font-size: 14px; font-variant-numeric: tabular-nums }
.inventory-group[open]>summary { border-bottom: 1px solid var(--line) }
.inventory-client-facts { justify-content: flex-end; max-width: 45% }.inventory-findings { display: inline-flex; align-items: center; min-height: 24px; padding: 2px 8px; border-radius: 6px; background: #fff3ec; color: var(--high); font-size: 12px; font-weight: 600 }
.inventory-rows { list-style: none; margin: 0; padding: 4px 22px 10px }
.inventory-row { display: grid; grid-template-columns: minmax(0,1fr) minmax(0,1.4fr); gap: 6px 22px; padding: 12px 0; border-bottom: 1px solid var(--line) }.inventory-row:last-child { border-bottom: 0 }
.inventory-item-name { display: flex; flex-direction: column; align-items: flex-start; gap: 3px; min-width: 0; line-height: 1.5; overflow-wrap: anywhere }.inventory-item-name strong,.inventory-item-name .observation-identity strong { font-size: 13px; font-weight: 600 }.inventory-kind-label { font-size: 11px; color: var(--faint) }
.inventory-where { grid-column: 1/-1; min-width: 0 }.inventory-context { display: block; font-size: 11px; color: var(--muted); margin-bottom: 2px; line-height: 1.6 }.inventory-empty { padding: 14px 22px; color: var(--muted); font-size: 13px }
.state { display: inline-flex; align-items: center; min-height: 24px; font-size: 12px; color: var(--muted) }.state-enabled { color: #006577 }.state-disabled { padding: 2px 6px; background: #f0f2f5; border-radius: 5px }

/* Coverage colors describe collection states, never an invented score. */
.discovery-summary { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 18px; margin: 0 0 20px }
.discovery-summary>div { display: flex; flex-direction: column-reverse; gap: 5px; padding: 18px; background: var(--white); border: 1px solid var(--line); border-radius: var(--card-radius) }.discovery-summary dt { font-size: 12px; color: var(--muted) }.discovery-summary dd { margin: 0; font-size: 27px; font-weight: 600; letter-spacing: -.04em }
.coverage-panel { padding: 28px 30px; border: 1px solid var(--line); border-radius: var(--radius); background: var(--white); box-shadow: var(--shadow); overflow: hidden }
.coverage-title { display: flex; align-items: center; gap: 20px; margin-bottom: 24px }.coverage-title>strong { font-size: 42px; letter-spacing: -.05em; line-height: 1.15; font-variant-numeric: tabular-nums }.coverage-title>strong span { font-size: 28px; color: var(--faint); font-weight: 400 }.coverage-title p { font-size: 14px; font-weight: 600 }.coverage-title p span { display: block; color: var(--faint); font-size: 12px; font-weight: 400; margin-top: 4px }
.coverage-summary { color: var(--muted); font-size: 14px; margin: 0 0 16px }
.coverage-causes { display: grid; gap: 10px }
.coverage-cause { border: 1px solid var(--line); border-radius: 12px; background: #fbfdfe; overflow: hidden }
.coverage-cause>summary { display: flex; align-items: center; gap: 12px; min-height: 52px; padding: 10px 16px; list-style: none; font-size: 13px }.coverage-cause>summary strong { min-width: 34px; font-size: 18px; font-variant-numeric: tabular-nums }.coverage-cause>summary .disclosure-icon { margin-left: auto }
.coverage-cause-body { padding: 0 16px 14px; font-size: 13px; color: var(--muted) }.coverage-cause-body ul { list-style: none; margin: 10px 0 0; padding: 0 }.coverage-cause-body li { padding: 8px 0; border-top: 1px solid var(--line) }.coverage-client { display: block; font-size: 12px; color: var(--ink); font-weight: 600 }
.source-reason { display: block; font-size: 12px; color: var(--muted); margin-top: 5px }

/* A light, explicitly illustrative Palma invitation follows all report data. */
.team-teaser { position: relative; margin-top: 48px; padding: 36px; border: 1px solid #bedfe7; border-radius: var(--radius); background: radial-gradient(ellipse at 100% 0%,#d6f6f8,transparent 65%),linear-gradient(135deg,#edf9fc,#f8fcfe); box-shadow: var(--shadow); overflow: hidden }
.team-teaser:before { content: ""; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: var(--gradient) }
.team-main { display: grid; grid-template-columns: minmax(0,1.25fr) minmax(0,1fr); align-items: center; gap: 46px }.team-copy h2 { font-size: clamp(28px,3vw,37px); margin-bottom: 16px }.team-copy>p:not(.eyebrow) { font-size: 15px; color: var(--muted); max-width: 530px }
.team-diagram { min-width: 0; margin: 0; padding: 18px; border: 1px solid #d5e9ee; border-radius: 18px; background: rgba(255,255,255,.75) }.team-diagram svg { display: block; width: 100%; height: auto }.team-diagram figcaption { margin-top: 8px; text-align: center; font-size: 11px; color: var(--muted) }
.diagram-endpoint rect { fill: #fff; stroke: #cbdfe6 }.diagram-source-label { fill: #334155; font-size: 14px }.diagram-team-card { fill: #fff; stroke: #c2dfe6 }.diagram-team-title { fill: #0f172a; font-size: 16px; font-weight: 600 }.diagram-result-label { fill: #334155; font-size: 14px }
.team-benefits { display: grid; grid-template-columns: repeat(3,minmax(0,1fr)); gap: 16px; margin-top: 28px }.team-benefits>div { border: 1px solid #dbeaf0; border-radius: var(--card-radius); padding: 20px; background: rgba(255,255,255,.85) }.team-benefits .icon { width: 21px; height: 21px; color: var(--brand); margin-bottom: 12px }.team-benefits h3 { font-size: 14px; letter-spacing: -.02em; margin-bottom: 7px }.team-benefits p { font-size: 13px; color: var(--muted) }
.team-conversation { display: flex; align-items: center; justify-content: space-between; gap: 30px; margin-top: 26px }.team-invitation { color: var(--muted); font-size: 14px }.team-invitation strong { display: block; color: var(--brand); margin-top: 3px }.offering-note { font-size: 12px; color: var(--muted); max-width: 410px }
.booking-link { display: inline-flex; align-items: center; justify-content: center; gap: 10px; min-height: 46px; padding: 12px 18px; background: #007a93; color: #fff; border: 1px solid #007a93; border-radius: 11px; font-size: 14px; font-weight: 600; white-space: nowrap }.booking-link:hover { background: #006577; text-decoration: none }.booking-link .icon { width: 16px; height: 16px }
.report-footer { display: flex; align-items: flex-start; justify-content: space-between; gap: 30px; padding: 30px 0 24px; color: var(--faint); font-size: 11px; line-height: 1.8 }.footer-brand { font-size: 17px; font-weight: 700; letter-spacing: -.04em; color: var(--ink) }.footer-brand span { color: var(--brand) }.footer-right { text-align: right }.footer-privacy { margin-top: 4px }
.artwork-credits { border-top: 1px solid var(--line); margin-bottom: 14px }.artwork-credits>summary { display: flex; align-items: center; gap: 10px; min-height: 44px; list-style: none; font-size: 12px; color: var(--faint) }.artwork-content { padding: 4px 0 18px; max-width: 960px }.artwork-content>p { font-size: 12px; color: var(--muted) }.artwork-sources { display: flex; gap: 10px 24px; flex-wrap: wrap; margin-top: 8px }.artwork-reference { display: inline-flex; align-items: center; min-height: 44px }.artwork-license>summary { display: flex; align-items: center; gap: 10px; min-height: 44px; list-style: none; font-size: 12px; color: var(--brand) }.artwork-license>pre { font-size: 12px; padding: 20px; background: var(--white); border: 1px solid var(--line); border-radius: 10px; max-height: 400px; overflow: auto }
.local-note-end { display: flex; gap: 10px; align-items: flex-start; color: var(--brand); padding: 0 0 32px; font-size: 12px }.local-note-end .icon { width: 17px; height: 17px; margin-top: 2px }.local-note-end span { color: var(--muted) }
.brand-sprite { position: absolute; width: 0; height: 0; overflow: hidden; pointer-events: none }.brand-icon { display: inline-block; width: 20px; height: 20px; flex: none; vertical-align: middle; overflow: visible }.brand-icon-generic { color: var(--brand) }.client-identity { display: inline-flex; align-items: center; gap: 7px; font-size: 12px; line-height: 1.5; min-width: 0; overflow-wrap: anywhere }.client-identity .brand-icon { width: 17px; height: 17px }.observation-identity { display: inline-flex; gap: 10px; align-items: center; max-width: 100%; line-height: 1.5 }.observation-identity>span { min-width: 0 }.observation-identity strong { display: block; color: var(--ink); font-size: 14px }.observation-instance { display: block; color: var(--faint); font-size: 11px; font-weight: 400; margin-top: 2px; overflow-wrap: anywhere }

@media(max-width:1000px) {
  .shell { width: calc(100% - 48px) }.brand-label { display: none }.main-nav { gap: 3px }.main-nav a { padding: 8px 10px }
  .report-title { gap: 28px }.report-meta { flex-basis: 235px }
  .overview-grid { grid-template-columns: minmax(0,1.6fr) minmax(245px,1fr); gap: 18px }.priority-item { padding: 15px; gap: 10px }.priority-chart { padding: 18px }
  .metric { padding: 18px }.metric-strip { gap: 12px }
  .findings-toolbar { flex-wrap: wrap }.findings-toolbar .search-field { flex: 1 }
  .access-overview { gap: 20px; padding: 24px }.access-chart-row { grid-template-columns: 151px minmax(0,1fr) 24px; gap: 9px }
  .inventory-kind { display: block }.inventory-kind strong { min-width: 0; display: block }.inventory-kind>span { display: block; margin-top: 3px }
  .team-teaser { padding: 28px }.team-main { gap: 24px }.team-benefits>div { padding: 17px }
}
@media(max-width:760px) {
  html { scroll-padding-top: 136px }
  .header-inner { flex-wrap: wrap; gap: 5px; padding: 12px 0 7px }.brand { flex: 1 }.brand img { width: 106px }.brand-label { display: block; padding-left: 14px; font-size: 11px }.main-nav { width: 100%; justify-content: space-between; gap: 0 }.main-nav a { min-height: 40px; padding: 6px 7px; font-size: 12px }.print-button { margin-left: 3px; padding: 8px; min-height: 40px }.print-button span { display: none }
  .overview-grid { grid-template-columns: 1fr }.priority-chart { display: grid; grid-template-columns: 1fr 1.25fr; gap: 0 24px; align-items: center }.chart-heading,.chart-footnote { grid-column: 1/-1 }.priority-ring { grid-column: 1; grid-row: 2/7; margin: 16px auto }.chart-row { grid-column: 2 }.chart-footnote { margin-top: 6px }
  .access-overview { grid-template-columns: 1fr }.access-chart-row { grid-template-columns: 170px minmax(0,1fr) 26px }.access-note { padding: 20px }.access-note-icon { float: left; margin: 1px 12px 0 0 }
  .report-title { display: block }.report-meta { display: flex; flex-wrap: wrap; gap: 7px 18px; border: 0; padding: 0; margin-top: 20px }.report-meta .meta-label { display: none }
  .metric-strip { grid-template-columns: repeat(2,minmax(0,1fr)) }.metric { padding: 20px }.metric-icon { position: absolute; top: 20px; right: 20px; width: 32px; height: 32px }.metric-number { padding-right: 35px }
  .client-overview { display: block }.client-overview ul { margin-top: 10px }
  .team-main { grid-template-columns: 1fr }.team-diagram { max-width: 440px; margin: 0 auto; width: 100% }
}
@media(max-width:560px) {
  .shell { width: calc(100% - 32px) }
  .header-inner { position: relative }.brand { padding-right: 44px }.main-nav a { padding-inline: 4px; font-size: 11px }.print-button { position: absolute; top: 12px; right: 0; margin: 0 }
  .report-title { padding: 30px 0 26px }.report-subtitle { font-size: 15px }.report-subtitle br { display: none }.report-meta { font-size: 11px }
  .overview-intro { padding: 23px 18px 0 }.overview-intro>p:last-child { font-size: 13px }.overview-grid { padding: 20px 14px 16px; gap: 14px }.priority-item { padding: 15px 12px; gap: 9px }.priority-index { width: 24px; height: 24px; font-size: 10px }.priority-item>.icon { width: 14px }.priority-meta { font-size: 11px }.priority-copy strong { font-size: 14px }.priority-action { font-size: 12px }.priority-chart { padding: 18px 14px; gap: 0 15px }.priority-ring { width: 108px; height: 108px }.ring-center strong { font-size: 28px }.chart-row { grid-template-columns: 46px minmax(0,1fr) 20px; gap: 7px; margin: 8px 0 }.chart-label,.chart-number { font-size: 11px }.chart-footnote { font-size: 11px }
  .metric { padding: 17px 14px }.metric-number { font-size: 31px }.metric-icon { top: 16px; right: 13px; width: 28px; height: 28px; border-radius: 8px }.metric-icon .icon { width: 16px; height: 16px }.metric-label { font-size: 12px; gap: 5px }.metric-label .icon { width: 12px }.metric-context { font-size: 11px }
  .access-overview { padding: 23px 18px; gap: 18px }.access-heading { margin-bottom: 10px }.access-heading h2 { font-size: 19px }.access-chart-row { grid-template-columns: 144px minmax(0,1fr) 20px; gap: 8px; font-size: 11px }.access-note { padding: 17px }
  .report-section { padding-top: 36px }.section-heading { gap: 14px; margin-bottom: 19px }.section-heading h2 { font-size: 25px }.section-heading p:not(.eyebrow) { font-size: 13px }.section-count { min-width: 38px; min-height: 38px; font-size: 14px }.eyebrow { font-size: 10px }
  .findings-toolbar { padding: 8px; gap: 10px }.filters { gap: 3px }.filter-button { padding: 9px 10px; font-size: 11px }.search-field { min-width: 0; width: 100%; min-height: 46px }.search-field input { font-size: 16px }.results-toolbar { gap: 10px; font-size: 11px }.text-button { font-size: 11px }
  .finding { padding: 22px 18px 0 }.finding-topline { gap: 9px; font-size: 11px }.finding-clients { width: 100%; margin-left: 0 }.finding h3 { font-size: 20px }.finding-summary { font-size: 14px }.next-step { padding: 14px 12px; gap: 9px }.next-step p { font-size: 13px }.finding-evidence { margin: 0 -18px }.finding-evidence>summary { padding: 13px 18px; font-size: 11px; gap: 9px }.evidence-count { font-size: 11px; white-space: nowrap }.evidence-content { padding: 20px 18px }.evidence-meta { font-size: 11px; gap: 7px 12px }
  .evidence-row,.inventory-row { grid-template-columns: 1fr }.inventory-rows { padding: 4px 14px 10px }.inventory-client-facts { display: none }
  .inventory-toolbar { flex-wrap: wrap; gap: 5px 16px }.inventory-toolbar .search-field { flex-basis: 100%; max-width: none }.inventory-group>summary { padding: 16px 14px; gap: 10px }.inventory-group-icon { width: 32px; height: 32px; border-radius: 9px }.inventory-group-icon .icon { width: 17px; height: 17px }.inventory-kind strong { font-size: 13px }.inventory-kind>span { font-size: 11px }.inventory-count { font-size: 12px; padding: 2px 7px }
  .discovery-summary { grid-template-columns: repeat(2,minmax(0,1fr)); gap: 12px }.discovery-summary>div { padding: 15px }.discovery-summary dd { font-size: 24px }.coverage-panel { padding: 24px 20px }.coverage-title { align-items: flex-start; flex-direction: column; gap: 10px }.coverage-title>strong { font-size: 38px }.coverage-title p span { font-size: 11px }
  .team-teaser { padding: 26px 20px; margin-top: 36px }.team-main { gap: 22px }.team-copy>p:not(.eyebrow) { font-size: 14px }.team-diagram { padding: 12px }.team-diagram figcaption { font-size: 10px }.team-benefits { grid-template-columns: 1fr; gap: 10px; margin-top: 20px }.team-benefits>div { padding: 16px 18px }.team-benefits .icon { float: left; margin: 2px 13px 30px 0 }.team-benefits p { font-size: 12px }.team-conversation { display: block; margin-top: 22px }.offering-note { margin-top: 16px; font-size: 11px }
  .report-footer { flex-direction: column; gap: 16px; padding: 24px 0 20px }.footer-right { text-align: left }.local-note-end { font-size: 11px }.local-note-end strong { display: block }
}
@media(prefers-reduced-motion:reduce) {
  html { scroll-behavior: auto } *,*:before,*:after { transition: none!important; animation: none!important }
}
@media print {
  @page { margin: 15mm }
  html { scroll-behavior: auto; scroll-padding-top: 0 }
  body { background: #fff; font-size: 10px; -webkit-print-color-adjust: exact; print-color-adjust: exact }
  .finding,.inventory-group,.coverage-panel { overflow: visible }
  .shell { width: 100%; max-width: none }.site-header { position: static; background: #fff }.header-inner { min-height: 48px; padding: 0 0 12px }.main-nav,.js-only,.js .js-only,.skip-link,.metric-context,#no-results,#inventory-no-results { display: none!important }
  .brand-label { display: block }.report-title { padding: 24px 0 20px; display: block }h1 { font-size: 32px }.report-subtitle { font-size: 11px }.report-meta { display: flex; flex-wrap: wrap; margin-top: 12px; padding: 0; border: 0; gap: 12px; font-size: 9px }.meta-label { display: none!important }.eyebrow { font-size: 8px; margin-bottom: 8px }
  .overview,.metric,.access-overview,.finding,.coverage-panel,.team-teaser { box-shadow: none; break-inside: avoid }.overview-intro { padding: 18px 20px 0 }.overview-intro h2 { font-size: 24px }.overview-intro>p:last-child { font-size: 10px }.overview-grid { grid-template-columns: minmax(0,1.8fr) minmax(190px,1fr); padding: 16px 20px 20px; gap: 16px }.priority-list { gap: 8px }.priority-item { padding: 10px; gap: 9px }.priority-copy strong { font-size: 11px }.priority-meta,.priority-action,.severity { font-size: 9px }.priority-chart { display: block; padding: 14px }.chart-heading h3 { font-size: 11px }.chart-heading>span { font-size: 9px }.priority-ring { width: 90px; height: 90px; margin: 12px auto }.ring-center strong { font-size: 24px }.ring-center,.chart-label,.chart-number,.chart-footnote { font-size: 9px }.chart-row { margin: 6px 0; grid-template-columns: 43px minmax(0,1fr) 20px }.chart-footnote { padding-top: 8px; margin-top: 10px }
  .metric-strip { grid-template-columns: repeat(4,minmax(0,1fr)); gap: 12px; margin-top: 16px }.metric { padding: 14px }.metric-icon { position: static; width: 27px; height: 27px; margin-bottom: 9px }.metric-number { padding: 0; font-size: 27px }.metric-label { font-size: 9px }.client-overview { margin-top: 16px }.client-overview>span,.client-overview a { font-size: 9px }.client-overview a { min-height: 28px; padding: 4px 7px }.client-overview .brand-icon { width: 16px; height: 16px }
  .access-overview { grid-template-columns: 1.5fr 1fr; padding: 20px; gap: 20px; margin-top: 20px }.access-heading h2 { font-size: 15px }.access-heading a { min-height: 24px; font-size: 9px }.access-chart-row { grid-template-columns: 125px minmax(0,1fr) 20px; font-size: 9px; margin: 10px 0 }.access-note { padding: 15px }.access-note h3 { font-size: 11px }.access-note p,.access-note .access-state-note { font-size: 9px }.access-note-icon { float: none }
  .report-section { padding-top: 28px }.section-heading { margin-bottom: 17px; break-after: avoid }.section-heading h2 { font-size: 23px }.section-heading p:not(.eyebrow) { font-size: 10px }.section-count { min-width: 30px; min-height: 30px; font-size: 11px }
  .finding { padding: 18px 20px 0; margin-bottom: 14px }.finding[hidden] { display: block!important }.finding h3 { font-size: 17px }.finding-topline { font-size: 9px; margin-bottom: 9px }.finding-clients { width: auto }.finding-summary,.next-step p,.impact p,.finding-impact p { font-size: 10px }.next-step { padding: 12px; margin: 12px 0 16px }.next-step h4,.impact h4,.finding-impact h4 { font-size: 10px }.finding-evidence { margin: 0 -20px }.finding-evidence>summary { padding: 10px 20px; min-height: 30px; font-size: 10px }.evidence-count,.evidence-meta,.evidence-meta code,.reference-links,.section-note { font-size: 9px }.evidence-content { padding: 16px 20px }.reference-links a { min-height: 20px }
  details:not([open])>:not(summary) { display: block!important }details::details-content { content-visibility: visible!important; display: block!important }.disclosure-icon { display: none }
  .fact,.inventory-path,.location-count,.source-reason { font-size: 9px }.fact { min-height: 18px; padding: 1px 5px }
  .inventory-group[hidden] { display: block!important }.inventory-group>summary { min-height: 48px; padding: 12px 15px; break-after: avoid }.inventory-group-icon { width: 28px; height: 28px }.inventory-kind { display: flex }.inventory-kind strong { font-size: 11px; min-width: 180px }.inventory-kind>span,.inventory-count { font-size: 9px }.inventory-row[hidden] { display: grid!important }.inventory-row { padding: 6px 0 }.inventory-item-name strong,.inventory-item-name .observation-identity strong,.state { font-size: 9px }.inventory-context { font-size: 8px }
  .discovery-summary { grid-template-columns: repeat(3,minmax(0,1fr)); gap: 12px }.discovery-summary>div { padding: 12px }.discovery-summary dd { font-size: 20px }.discovery-summary dt { font-size: 9px }.coverage-panel { padding: 20px }.coverage-title { flex-direction: row; align-items: center }.coverage-title>strong { font-size: 32px }.coverage-title p { font-size: 11px }.coverage-title p span,.coverage-summary { font-size: 9px }
  .team-teaser { margin-top: 28px; padding: 24px }.team-main { grid-template-columns: 1.15fr 1fr; gap: 22px }.team-copy h2 { font-size: 26px }.team-copy>p:not(.eyebrow) { font-size: 10px }.team-diagram { padding: 12px }.team-diagram figcaption { font-size: 8px }.team-benefits { grid-template-columns: repeat(3,minmax(0,1fr)); gap: 12px; margin-top: 18px }.team-benefits>div { padding: 14px }.team-benefits .icon { float: none; width: 17px; height: 17px; margin: 0 0 8px }.team-benefits h3 { font-size: 11px }.team-benefits p { font-size: 9px }.team-conversation { display: flex; gap: 22px; margin-top: 18px }.team-invitation { font-size: 10px }.offering-note { font-size: 9px; margin-top: 0; max-width: 300px }.booking-link { font-size: 10px; min-height: 34px; padding: 9px 12px }
  .report-footer { flex-direction: row; font-size: 8px; padding: 20px 0 15px }.footer-right { text-align: right }.footer-brand { font-size: 13px }.artwork-credits>summary,.artwork-content>p,.artwork-reference { font-size: 8px; min-height: 20px }.artwork-license { display: none!important }.local-note-end { font-size: 9px; padding-bottom: 0 }.local-note-end strong { display: inline }.brand-icon { width: 15px; height: 15px }.client-identity,.finding-clients .client-identity { font-size: 9px }.client-identity .brand-icon { width: 13px; height: 13px }.observation-identity strong { font-size: 10px }.observation-instance { font-size: 9px }
}
"""
