"""Deterministic, dependency-free, offline HTML for a sanitized Palma snapshot.

All report content is derived from the snapshot. ``summary`` is accepted as part of
the public renderer contract, but never used as a second source for visual counts.
Configuration is evidence of capability, not evidence of execution or compromise.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import html
import json
import re
from collections import Counter
from urllib.parse import urlsplit

from .brands_extra import EXTRA_ARTWORK_NOTICE, EXTRA_BRAND_ASSETS, EXTRA_CLIENTS
from .engine.redaction import visible
from .governance import PUBLIC_REFERENCES
from .model import booking_link as _booking_link
from .report_font import FONT_NOTICE
from .report_regulation import render_regulation_section
from .report_brand import LOGO_DATA_URI
from .report_overview import inventory_graph
from .report_theme import CSS as _CSS

# The embedded Palma logo is a fixed asset, never fetched at runtime.


_SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_NAMES = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
_KINDS = (("client", "AI clients"), ("mcp", "MCP servers & connectors"),
          ("skill", "Skills"), ("plugin", "Plugins"), ("agent", "Agents"),
          ("setting", "Settings & capabilities"), ("hook", "Hooks"))
_STATES = {"enabled": "Enabled in configuration", "disabled": "Disabled in configuration", "unknown": ""}
_SOURCE_STATES = ("collected", "missing", "skipped", "error", "unknown")
_SOURCE_NAMES = {"collected": "Collected", "missing": "Not present", "skipped": "Skipped", "error": "Read error", "unknown": "Unknown"}

# Fixed brand artwork, included only for recognized enum values. No asset URL or
# arbitrary SVG from a snapshot is accepted. Client geometry comes from Palma's
# application asset library (images/mcp-hosts); connector geometry comes from its
# brand-icons catalog, pinned to homarr-labs/dashboard-icons commit
# 03e8f8e22da16ccddf5e14afa90711391357231e (Apache-2.0; upstream LICENSE:
# https://github.com/homarr-labs/dashboard-icons/blob/03e8f8e22da16ccddf5e14afa90711391357231e/LICENSE).
# Playwright artwork: https://playwright.dev/img/playwright-logo.svg (Microsoft,
# documentation CC-BY-4.0). Full notices and license text: THIRD_PARTY_NOTICES.md.
# Development-time changes: CSS fills become SVG presentation attributes, IDs are
# namespaced, and metadata is removed. Geometry and brand colors are preserved.
# Brand names and marks belong to their owners; their presence is identification,
# not an endorsement or a claim that a configured endpoint is authentic.
_BRAND_ASSETS = {
    'atlassian': ('0 0 48 48', '<symbol viewBox="0 0 48 48" id="brand-atlassian"><path fill="url(#brand-atlassian-a)" d="M11.129 15.081c-.364-.4-.91-.364-1.165.11L4.07 26.98c-.218.473.11 1.02.619 1.02h8.188a.67.67 0 0 0 .618-.401c1.784-3.64.728-9.207-2.365-12.52z" transform="matrix(2 0 0 2 -7.989 -8)" /><path fill="#2684ff" d="M22.857.764c-6.55 10.408-6.114 21.98-1.82 30.642 4.367 8.661 7.643 15.357 7.934 15.794.218.51.728.8 1.237.8h16.376c1.02 0 1.747-1.091 1.237-2.037 0 0-22.051-44.106-22.635-45.198-.437-1.02-1.674-1.02-2.33 0z" /><defs><linearGradient id="brand-atlassian-a" x1="14.346" x2="8.133" y1="16.905" y2="27.666" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#0052CC" /><stop offset=".923" stop-color="#2684FF" /></linearGradient></defs></symbol>'),
    'chrome': ('0 0 512 512', '<symbol viewBox="0 0 512 512" id="brand-chrome"><circle cx="256" cy="255.9" r="128" fill="#fff" /><path d="M34.3 384C105 506.4 261.6 548.3 384 477.7S548.3 250.4 477.7 128 250.4-36.3 128 34.3C5.6 105-36.3 261.6 34.3 384m332.5-192c35.3 61.2 14.4 139.5-46.8 174.8S180.5 381.2 145.2 320 130.8 180.5 192 145.2c61.2-35.4 139.5-14.4 174.8 46.8" fill="none" /><linearGradient id="brand-chrome-a" x1="34.355" x2="477.629" y1="354.005" y2="354.005" gradientTransform="matrix(1 0 0 -1 0 514)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#d93025" /><stop offset="1" stop-color="#ea4335" /></linearGradient><path d="M256 128h221.6C407 5.6 250.5-36.3 128.1 34.3 89.2 56.8 56.8 89.1 34.4 128l110.8 192h.1c-35.4-61.1-14.6-139.3 46.5-174.7 19.4-11.4 41.6-17.3 64.2-17.3" fill="url(#brand-chrome-a)" /><circle cx="256" cy="256" r="101.3" fill="#1a73e8" /><linearGradient id="brand-chrome-b" x1="221.057" x2="442.694" y1="5.455" y2="389.341" gradientTransform="matrix(1 0 0 -1 0 514)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#fcc934" /><stop offset="1" stop-color="#fbbc04" /></linearGradient><path d="M366.8 320 256 512c141.3 0 255.9-114.5 255.9-255.9 0-45-11.8-89.1-34.3-128H256v.1c70.6-.1 127.9 57 128.1 127.6 0 22.5-6 44.7-17.3 64.2" fill="url(#brand-chrome-b)" /><linearGradient id="brand-chrome-c" x1="283.689" x2="62.052" y1="18.014" y2="401.901" gradientTransform="matrix(1 0 0 -1 0 514)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#1e8e3e" /><stop offset="1" stop-color="#34a853" /></linearGradient><path d="M145.2 320 34.4 128.1C-36.3 250.5 5.6 407 128 477.7c38.9 22.4 83.1 34.3 128 34.3l110.8-192-.1-.1c-35.2 61.2-113.3 82.3-174.5 47.1-19.5-11.2-35.8-27.4-47-47" fill="url(#brand-chrome-c)" /></symbol>'),
    'claude': ('0 0 24 24', '<symbol viewBox="0 0 24 24" id="brand-claude"><path fill="#D97757" d="m4.7144 15.9555 4.7174-2.6471.079-.2307-.079-.1275h-.2307l-.7893-.0486-2.6956-.0729-2.3375-.0971-2.2646-.1214-.5707-.1215-.5343-.7042.0546-.3522.4797-.3218.686.0608 1.5179.1032 2.2767.1578 1.6514.0972 2.4468.255h.3886l.0546-.1579-.1336-.0971-.1032-.0972L6.973 9.8356l-2.55-1.6879-1.3356-.9714-.7225-.4918-.3643-.4614-.1578-1.0078.6557-.7225.8803.0607.2246.0607.8925.686 1.9064 1.4754 2.4893 1.8336.3643.3035.1457-.1032.0182-.0728-.164-.2733-1.3539-2.4467-1.445-2.4893-.6435-1.032-.17-.6194c-.0607-.255-.1032-.4674-.1032-.7285L6.287.1335 6.6997 0l.9957.1336.419.3642.6192 1.4147 1.0018 2.2282 1.5543 3.0296.4553.8985.2429.8318.091.255h.1579v-.1457l.1275-1.706.2368-2.0947.2307-2.6957.0789-.7589.3764-.9107.7468-.4918.5828.2793.4797.686-.0668.4433-.2853 1.8517-.5586 2.9021-.3643 1.9429h.2125l.2429-.2429.9835-1.3053 1.6514-2.0643.7286-.8196.85-.9046.5464-.4311h1.0321l.759 1.1293-.34 1.1657-1.0625 1.3478-.8804 1.1414-1.2628 1.7-.7893 1.36.0729.1093.1882-.0183 2.8535-.607 1.5421-.2794 1.8396-.3157.8318.3886.091.3946-.3278.8075-1.967.4857-2.3072.4614-3.4364.8136-.0425.0304.0486.0607 1.5482.1457.6618.0364h1.621l3.0175.2247.7892.522.4736.6376-.079.4857-1.2142.6193-1.6393-.3886-3.825-.9107-1.3113-.3279h-.1822v.1093l1.0929 1.0686 2.0035 1.8092 2.5075 2.3314.1275.5768-.3218.4554-.34-.0486-2.2039-1.6575-.85-.7468-1.9246-1.621h-.1275v.17l.4432.6496 2.3436 3.5214.1214 1.0807-.17.3521-.6071.2125-.6679-.1214-1.3721-1.9246L14.38 17.959l-1.1414-1.9428-.1397.079-.674 7.2552-.3156.3703-.7286.2793-.6071-.4614-.3218-.7468.3218-1.4753.3886-1.9246.3157-1.53.2853-1.9004.17-.6314-.0121-.0425-.1397.0182-1.4328 1.9672-2.1796 2.9446-1.7243 1.8456-.4128.164-.7164-.3704.0667-.6618.4008-.5889 2.386-3.0357 1.4389-1.882.929-1.0868-.0062-.1579h-.0546l-6.3385 4.1164-1.1293.1457-.4857-.4554.0608-.7467.2307-.2429 1.9064-1.3114Z" /></symbol>'),
    'codex': ('0 0 320 320', '<symbol viewBox="0 0 320 320" id="brand-codex"><path fill="#000" d="m297.06 130.97c7.26-21.79 4.76-45.66-6.85-65.48-17.46-30.4-52.56-46.04-86.84-38.68-15.25-17.18-37.16-26.95-60.13-26.81-35.04-.08-66.13 22.48-76.91 55.82-22.51 4.61-41.94 18.7-53.31 38.67-17.59 30.32-13.58 68.54 9.92 94.54-7.26 21.79-4.76 45.66 6.85 65.48 17.46 30.4 52.56 46.04 86.84 38.68 15.24 17.18 37.16 26.95 60.13 26.8 35.06.09 66.16-22.49 76.94-55.86 22.51-4.61 41.94-18.7 53.31-38.67 17.57-30.32 13.55-68.51-9.94-94.51zm-120.28 168.11c-14.03.02-27.62-4.89-38.39-13.88.49-.26 1.34-.73 1.89-1.07l63.72-36.8c3.26-1.85 5.26-5.32 5.24-9.07v-89.83l26.93 15.55c.29.14.48.42.52.74v74.39c-.04 33.08-26.83 59.9-59.91 59.97zm-128.84-55.03c-7.03-12.14-9.56-26.37-7.15-40.18.47.28 1.3.79 1.89 1.13l63.72 36.8c3.23 1.89 7.23 1.89 10.47 0l77.79-44.92v31.1c.02.32-.13.63-.38.83l-64.41 37.19c-28.69 16.52-65.33 6.7-81.92-21.95zm-16.77-139.09c7-12.16 18.05-21.46 31.21-26.29 0 .55-.03 1.52-.03 2.2v73.61c-.02 3.74 1.98 7.21 5.23 9.06l77.79 44.91-26.93 15.55c-.27.18-.61.21-.91.08l-64.42-37.22c-28.63-16.58-38.45-53.21-21.95-81.89zm221.26 51.49-77.79-44.92 26.93-15.54c.27-.18.61-.21.91-.08l64.42 37.19c28.68 16.57 38.51 53.26 21.94 81.94-7.01 12.14-18.05 21.44-31.2 26.28v-75.81c.03-3.74-1.96-7.2-5.2-9.06zm26.8-40.34c-.47-.29-1.3-.79-1.89-1.13l-63.72-36.8c-3.23-1.89-7.23-1.89-10.47 0l-77.79 44.92v-31.1c-.02-.32.13-.63.38-.83l64.41-37.16c28.69-16.55 65.37-6.7 81.91 22 6.99 12.12 9.52 26.31 7.15 40.1zm-168.51 55.43-26.94-15.55c-.29-.14-.48-.42-.52-.74v-74.39c.02-33.12 26.89-59.96 60.01-59.94 14.01 0 27.57 4.92 38.34 13.88-.49.26-1.33.73-1.89 1.07l-63.72 36.8c-3.26 1.85-5.26 5.31-5.24 9.06l-.04 89.79zm14.63-31.54 34.65-20.01 34.65 20v40.01l-34.65 20-34.65-20z" /></symbol>'),
    'cursor': ('0 0 24 24', '<symbol viewBox="0 0 24 24" id="brand-cursor"><path d="M11.503.131 1.891 5.678a.84.84 0 0 0-.42.726v11.188c0 .3.162.575.42.724l9.609 5.55a1 1 0 0 0 .998 0l9.61-5.55a.84.84 0 0 0 .42-.724V6.404a.84.84 0 0 0-.42-.726L12.497.131a1.01 1.01 0 0 0-.996 0M2.657 6.338h18.55c.263 0 .43.287.297.515L12.23 22.918c-.062.107-.229.064-.229-.06V12.335a.59.59 0 0 0-.295-.51l-9.11-5.257c-.109-.063-.064-.23.061-.23" /></symbol>'),
    'figma': ('0 0 200 300', '<symbol viewBox="0 0 200 300" id="brand-figma"><path id="brand-figma-path0_fill" d="M50 300c27.6 0 50-22.4 50-50v-50H50c-27.6 0-50 22.4-50 50s22.4 50 50 50z" fill="#0acf83" /><path id="brand-figma-path1_fill" d="M0 150c0-27.6 22.4-50 50-50h50v100H50c-27.6 0-50-22.4-50-50z" fill="#a259ff" /><path id="brand-figma-path1_fill_1_" d="M0 50C0 22.4 22.4 0 50 0h50v100H50C22.4 100 0 77.6 0 50z" fill="#f24e1e" /><path id="brand-figma-path2_fill" d="M100 0h50c27.6 0 50 22.4 50 50s-22.4 50-50 50h-50V0z" fill="#ff7262" /><path id="brand-figma-path3_fill" d="M200 150c0 27.6-22.4 50-50 50s-50-22.4-50-50 22.4-50 50-50 50 22.4 50 50z" fill="#1abcfe" /></symbol>'),
    'gemini': ('0 0 24 24', '<symbol viewBox="0 0 24 24" id="brand-gemini"><path fill="#8E75B2" d="M11.04 19.32Q12 21.51 12 24q0-2.49.93-4.68.96-2.19 2.58-3.81t3.81-2.55Q21.51 12 24 12q-2.49 0-4.68-.93a12.3 12.3 0 0 1-3.81-2.58 12.3 12.3 0 0 1-2.58-3.81Q12 2.49 12 0q0 2.49-.96 4.68-.93 2.19-2.55 3.81a12.3 12.3 0 0 1-3.81 2.58Q2.49 12 0 12q2.49 0 4.68.96 2.19.93 3.81 2.55t2.55 3.81" /></symbol>'),
    'github': ('0 0 512 512', '<symbol viewBox="0 0 512 512" id="brand-github"><path d="M256 6.3C114.6 6.3 0 120.9 0 262.3c0 113.3 73.3 209 175 242.9 12.8 2.2 17.6-5.4 17.6-12.2 0-6.1-.3-26.2-.3-47.7-64.3 11.8-81-15.7-86.1-30.1-2.9-7.4-15.4-30.1-26.2-36.2-9-4.8-21.8-16.6-.3-17 20.2-.3 34.6 18.6 39.4 26.2 23 38.7 59.8 27.8 74.6 21.1 2.2-16.6 9-27.8 16.3-34.2-57-6.4-116.5-28.5-116.5-126.4 0-27.8 9.9-50.9 26.2-68.8-2.6-6.4-11.5-32.6 2.6-67.8 0 0 21.4-6.7 70.4 26.2 20.5-5.8 42.2-8.6 64-8.6s43.5 2.9 64 8.6c49-33.3 70.4-26.2 70.4-26.2 14.1 35.2 5.1 61.4 2.6 67.8 16.3 17.9 26.2 40.6 26.2 68.8 0 98.2-59.8 120-116.8 126.4 9.3 8 17.3 23.4 17.3 47.4 0 34.2-.3 61.8-.3 70.4 0 6.7 4.8 14.7 17.6 12.2C438.7 471.3 512 375.3 512 262.3c0-141.4-114.6-256-256-256" fill-rule="evenodd" clip-rule="evenodd" fill="#1b1f23" /></symbol>'),
    'google-drive': ('0 0 512 512', '<symbol viewBox="0 0 512 512" id="brand-google-drive"><path d="m38.7 419.3 22.6 39c4.7 8.2 11.4 14.7 19.4 19.4l80.6-139.6H0c0 9.1 2.3 18.2 7 26.4z" fill="#0066da" /><path d="M256 173.9 175.4 34.3c-7.9 4.7-14.7 11.1-19.4 19.4L7 311.7c-4.6 8-7 17.1-7 26.4h161.3z" fill="#00ac47" /><path d="M431.4 477.7c7.9-4.7 14.7-11.1 19.4-19.4l9.4-16.1 44.9-77.7c4.7-8.2 7-17.3 7-26.4H350.7l34.3 67.4z" fill="#ea4335" /><path d="m256 173.9 80.6-139.6c-7.9-4.7-17-7-26.4-7H201.8c-9.4 0-18.5 2.6-26.4 7z" fill="#00832d" /><path d="M350.7 338.1H161.3L80.6 477.7c7.9 4.7 17 7 26.4 7h298c9.4 0 18.5-2.6 26.4-7z" fill="#2684fc" /><path d="M430.5 182.7 356 53.7c-4.7-8.2-11.4-14.7-19.4-19.4L256 173.9l94.7 164.2h161c0-9.1-2.3-18.2-7-26.4z" fill="#ffba00" /></symbol>'),
    'linear': ('0 0 100 100', '<symbol fill="none" viewBox="0 0 100 100" id="brand-linear"><path fill="#222326" d="M1.22541 61.5228c-.2225-.9485.90748-1.5459 1.59638-.857L39.3342 97.1782c.6889.6889.0915 1.8189-.857 1.5964C20.0515 94.4522 5.54779 79.9485 1.22541 61.5228ZM.00189135 46.8891c-.01764375.2833.08887215.5599.28957165.7606L52.3503 99.7085c.2007.2007.4773.3075.7606.2896 2.3692-.1476 4.6938-.46 6.9624-.9259.7645-.157 1.0301-1.0963.4782-1.6481L2.57595 39.4485c-.55186-.5519-1.49117-.2863-1.648174.4782-.465915 2.2686-.77832 4.5932-.92588465 6.9624ZM4.21093 29.7054c-.16649.3738-.08169.8106.20765 1.1l64.77602 64.776c.2894.2894.7262.3742 1.1.2077 1.7861-.7956 3.5171-1.6927 5.1855-2.684.5521-.328.6373-1.0867.1832-1.5407L8.43566 24.3367c-.45409-.4541-1.21271-.3689-1.54074.1832-.99132 1.6684-1.88843 3.3994-2.68399 5.1855ZM12.6587 18.074c-.3701-.3701-.393-.9637-.0443-1.3541C21.7795 6.45931 35.1114 0 49.9519 0 77.5927 0 100 22.4073 100 50.0481c0 14.8405-6.4593 28.1724-16.7199 37.3375-.3903.3487-.984.3258-1.3542-.0443L12.6587 18.074Z" /></symbol>'),
    'notion': ('0 0 512 512', '<symbol viewBox="0 0 512 512" id="brand-notion"><path d="M41.8 22.1 325.1 1.2c34.8-3 43.7-1 65.6 14.9l90.4 63.7c14.9 11 19.9 13.9 19.9 25.9v349.4c0 21.9-8 34.9-35.8 36.8l-329 19.9c-20.9 1-30.8-2-41.8-15.9l-66.6-86.6C15.9 393.4 11 381.4 11 367.5V56.9c0-17.9 7.9-32.8 30.8-34.8" fill="#fff" /><path d="M325.1 1.2 41.8 22.1C18.9 24.1 11 39 11 56.9v310.6c0 13.9 5 25.9 16.9 41.8l66.6 86.6c10.9 13.9 20.9 16.9 41.8 15.9l329-19.9c27.8-2 35.8-14.9 35.8-36.8V105.7c0-11.3-4.5-14.6-17.6-24.2l-92.7-65.4C368.8.2 359.9-1.8 325.1 1.2M143.7 100c-26.9 1.8-33 2.2-48.2-10.2L56.7 58.9c-3.9-4-2-9 8-10L337 29.1c22.9-2 34.8 6 43.7 12.9l46.7 33.8c2 1 7 7 1 7L147.2 99.7zm-31.3 352.1V155.5c0-13 4-18.9 15.9-19.9l323-18.9c11-1 15.9 6 15.9 18.9v294.6c0 13-2 23.9-19.9 24.9L138.2 473c-17.9 1-25.8-5-25.8-20.9m305.1-280.7c2 9 0 17.9-9 18.9l-14.9 3v219c-12.9 7-24.8 10.9-34.8 10.9-15.9 0-19.9-5-31.8-19.9L229.6 250v148.3l30.8 7s0 17.9-24.9 17.9l-68.6 4c-2-4 0-13.9 6.9-15.9l17.9-5V210.2l-24.8-2c-2-9 3-21.9 16.9-22.9l73.6-5 101.4 155.3V198.3l-25.8-3c-2-11 6-18.9 15.9-19.9z" fill-rule="evenodd" clip-rule="evenodd" /></symbol>'),
    'playwright': ('0 0 400 400', '<symbol viewBox="0 0 400 400" fill="none" id="brand-playwright">\n<path d="M136.444 221.556C123.558 225.213 115.104 231.625 109.535 238.032C114.869 233.364 122.014 229.08 131.652 226.348C141.51 223.554 149.92 223.574 156.869 224.915V219.481C150.941 218.939 144.145 219.371 136.444 221.556ZM108.946 175.876L61.0895 188.484C61.0895 188.484 61.9617 189.716 63.5767 191.36L104.153 180.668C104.153 180.668 103.578 188.077 98.5847 194.705C108.03 187.559 108.946 175.876 108.946 175.876ZM149.005 288.347C81.6582 306.486 46.0272 228.438 35.2396 187.928C30.2556 169.229 28.0799 155.067 27.5 145.928C27.4377 144.979 27.4665 144.179 27.5336 143.446C24.04 143.657 22.3674 145.473 22.7077 150.721C23.2876 159.855 25.4633 174.016 30.4473 192.721C41.2301 233.225 76.8659 311.273 144.213 293.134C158.872 289.185 169.885 281.992 178.152 272.81C170.532 279.692 160.995 285.112 149.005 288.347ZM161.661 128.11V132.903H188.077C187.535 131.206 186.989 129.677 186.447 128.11H161.661Z" fill="#2D4552" />\n<path d="M193.981 167.584C205.861 170.958 212.144 179.287 215.465 186.658L228.711 190.42C228.711 190.42 226.904 164.623 203.57 157.995C181.741 151.793 168.308 170.124 166.674 172.496C173.024 167.972 182.297 164.268 193.981 167.584ZM299.422 186.777C277.573 180.547 264.145 198.916 262.535 201.255C268.89 196.736 278.158 193.031 289.837 196.362C301.698 199.741 307.976 208.06 311.307 215.436L324.572 219.212C324.572 219.212 322.736 193.41 299.422 186.777ZM286.262 254.795L176.072 223.99C176.072 223.99 177.265 230.038 181.842 237.869L274.617 263.805C282.255 259.386 286.262 254.795 286.262 254.795ZM209.867 321.102C122.618 297.71 133.166 186.543 147.284 133.865C153.097 112.156 159.073 96.0203 164.029 85.204C161.072 84.5953 158.623 86.1529 156.203 91.0746C150.941 101.747 144.212 119.124 137.7 143.45C123.586 196.127 113.038 307.29 200.283 330.682C241.406 341.699 273.442 324.955 297.323 298.659C274.655 319.19 245.714 330.701 209.867 321.102Z" fill="#2D4552" />\n<path d="M161.661 262.296V239.863L99.3324 257.537C99.3324 257.537 103.938 230.777 136.444 221.556C146.302 218.762 154.713 218.781 161.661 220.123V128.11H192.869C189.471 117.61 186.184 109.526 183.423 103.909C178.856 94.612 174.174 100.775 163.545 109.665C156.059 115.919 137.139 129.261 108.668 136.933C80.1966 144.61 57.179 142.574 47.5752 140.911C33.9601 138.562 26.8387 135.572 27.5049 145.928C28.0847 155.062 30.2605 169.224 35.2445 187.928C46.0272 228.433 81.663 306.481 149.01 288.342C166.602 283.602 179.019 274.233 187.626 262.291H161.661V262.296ZM61.0848 188.484L108.946 175.876C108.946 175.876 107.551 194.288 89.6087 199.018C71.6614 203.743 61.0848 188.484 61.0848 188.484Z" fill="#E2574C" />\n<path d="M341.786 129.174C329.345 131.355 299.498 134.072 262.612 124.185C225.716 114.304 201.236 97.0224 191.537 88.8994C177.788 77.3834 171.74 69.3802 165.788 81.4857C160.526 92.163 153.797 109.54 147.284 133.866C133.171 186.543 122.623 297.706 209.867 321.098C297.093 344.47 343.53 242.92 357.644 190.238C364.157 165.917 367.013 147.5 367.799 135.625C368.695 122.173 359.455 126.078 341.786 129.174ZM166.497 172.756C166.497 172.756 180.246 151.372 203.565 158C226.899 164.628 228.706 190.425 228.706 190.425L166.497 172.756ZM223.42 268.713C182.403 256.698 176.077 223.99 176.077 223.99L286.262 254.796C286.262 254.791 264.021 280.578 223.42 268.713ZM262.377 201.495C262.377 201.495 276.107 180.126 299.422 186.773C322.736 193.411 324.572 219.208 324.572 219.208L262.377 201.495Z" fill="#2EAD33" />\n<path d="M139.88 246.04L99.3324 257.532C99.3324 257.532 103.737 232.44 133.607 222.496L110.647 136.33L108.663 136.933C80.1918 144.611 57.1742 142.574 47.5704 140.911C33.9554 138.563 26.834 135.572 27.5001 145.929C28.08 155.063 30.2557 169.224 35.2397 187.929C46.0225 228.433 81.6583 306.481 149.005 288.342L150.989 287.719L139.88 246.04ZM61.0848 188.485L108.946 175.876C108.946 175.876 107.551 194.288 89.6087 199.018C71.6615 203.743 61.0848 188.485 61.0848 188.485Z" fill="#D65348" />\n<path d="M225.27 269.163L223.415 268.712C182.398 256.698 176.072 223.99 176.072 223.99L232.89 239.872L262.971 124.281L262.607 124.185C225.711 114.304 201.232 97.0224 191.532 88.8994C177.783 77.3834 171.735 69.3802 165.783 81.4857C160.526 92.163 153.797 109.54 147.284 133.866C133.171 186.543 122.623 297.706 209.867 321.097L211.655 321.5L225.27 269.163ZM166.497 172.756C166.497 172.756 180.246 151.372 203.565 158C226.899 164.628 228.706 190.425 228.706 190.425L166.497 172.756Z" fill="#1D8D22" />\n<path d="M141.946 245.451L131.072 248.537C133.641 263.019 138.169 276.917 145.276 289.195C146.513 288.922 147.74 288.687 149 288.342C152.302 287.451 155.364 286.348 158.312 285.145C150.371 273.361 145.118 259.789 141.946 245.451ZM137.7 143.451C132.112 164.307 127.113 194.326 128.489 224.436C130.952 223.367 133.554 222.371 136.444 221.551L138.457 221.101C136.003 188.939 141.308 156.165 147.284 133.866C148.799 128.225 150.318 122.978 151.832 118.085C149.393 119.637 146.767 121.228 143.776 122.867C141.759 129.093 139.722 135.898 137.7 143.451Z" fill="#C04B41" />\n</symbol>'),
    'slack': ('0 0 512 512', '<symbol viewBox="0 0 512 512" id="brand-slack"><path d="M107.9 323.6c0 29.7-24 53.8-53.8 53.8S.3 353.4.3 323.6c0-29.7 24-53.8 53.8-53.8h53.8zm26.9 0c0-29.7 24-53.8 53.8-53.8s53.8 24 53.8 53.8V458c0 29.7-24 53.8-53.8 53.8s-53.8-24-53.8-53.8z" fill="#e01e5a" /><path d="M188.6 107.7c-29.7 0-53.8-24-53.8-53.8S158.8.1 188.6.1s53.8 24 53.8 53.8v53.8zm0 27.3c29.7 0 53.8 24 53.8 53.8s-24 53.8-53.8 53.8H53.8C24 242.6 0 218.5 0 188.8S24 135 53.8 135z" fill="#36c5f0" /><path d="M404.1 188.8c0-29.7 24-53.8 53.8-53.8s53.8 24 53.8 53.8-24 53.8-53.8 53.8h-53.8zm-26.9 0c0 29.7-24 53.8-53.8 53.8-29.7 0-53.8-24-53.8-53.8V54c0-29.7 24-53.8 53.8-53.8s53.8 24 53.8 53.8z" fill="#2eb67d" /><path d="M323.4 404.3c29.7 0 53.8 24 53.8 53.8 0 29.7-24 53.8-53.8 53.8-29.7 0-53.8-24-53.8-53.8v-53.8zm0-26.9c-29.7 0-53.8-24-53.8-53.8s24-53.8 53.8-53.8h134.8c29.7 0 53.8 24 53.8 53.8 0 29.7-24 53.8-53.8 53.8z" fill="#ecb22e" /></symbol>'),
    'vscode': ('0 0 24 24', '<symbol viewBox="0 0 24 24" id="brand-vscode"><path fill="#007ACC" d="M17.583 0L9.23 7.637 3.986 3.864 0 5.5v12.956l3.986 1.636 5.244-3.773L17.583 24 24 21.044V2.912L17.583 0zM3.986 15.106V8.894L7.6 12l-3.614 3.106zM17.583 18.4L10.58 12l7.003-6.4V18.4z" /></symbol>'),
    'windsurf': ('0 0 1024 1024', '<symbol viewBox="0 0 1024 1024" fill="none" id="brand-windsurf"><path d="M897.246 286.869H889.819C850.735 286.808 819.017 318.46 819.017 357.539V515.589C819.017 547.15 792.93 572.716 761.882 572.716C743.436 572.716 725.02 563.433 714.093 547.85L552.673 317.304C539.28 298.16 517.486 286.747 493.895 286.747C457.094 286.747 423.976 318.034 423.976 356.657V515.619C423.976 547.181 398.103 572.746 366.842 572.746C348.335 572.746 329.949 563.463 319.021 547.881L138.395 289.882C134.316 284.038 125.154 286.93 125.154 294.052V431.892C125.154 438.862 127.285 445.619 131.272 451.34L309.037 705.2C319.539 720.204 335.033 731.344 352.9 735.392C397.616 745.557 438.77 711.135 438.77 667.278V508.406C438.77 476.845 464.339 451.279 495.904 451.279H495.995C515.02 451.279 532.857 460.562 543.785 476.145L705.235 706.661C718.659 725.835 739.327 737.218 763.983 737.218C801.606 737.218 833.841 705.9 833.841 667.308V508.376C833.841 476.815 859.41 451.249 890.975 451.249H897.276C901.233 451.249 904.43 448.053 904.43 444.097V294.021C904.43 290.065 901.233 286.869 897.276 286.869H897.246Z" fill="#0B100F" /></symbol>'),
}
_CLIENTS = {
    "codex": ("Codex", "codex"),
    "claude-code": ("Claude Code", "claude"),
    "claude-desktop": ("Claude Desktop", "claude"),
    "cursor": ("Cursor", "cursor"),
    "gemini-cli": ("Gemini CLI", "gemini"),
    "vscode": ("VS Code", "vscode"),
    "windsurf": ("Windsurf", "windsurf"),
    "shared": ("Shared skills", "shared"),
}
_PROVIDERS = {
    "github": ("GitHub", "github"), "slack": ("Slack", "slack"),
    "notion": ("Notion", "notion"), "linear": ("Linear", "linear"),
    "atlassian": ("Atlassian", "atlassian"), "figma": ("Figma", "figma"),
    "google-drive": ("Google Drive", "google-drive"),
    "playwright": ("Playwright", "playwright"),
    "chrome": ("Chrome DevTools", "chrome"),
    "chrome-devtools": ("Chrome DevTools", "chrome"),
    "context7": ("Context7", "book"), "browserbase": ("Browserbase", "browser"),
    "filesystem": ("Filesystem", "folder"), "browser": ("Browser", "browser"),
}
_ARTWORK_NOTICE = '# Third-party artwork notices\n\nThe report includes a fixed, offline catalog of product marks to help identify declared AI clients and connectors. Marks remain the property of their respective owners. Use of a mark does not imply endorsement, a verified service identity, a live connection, or a security assessment of the provider.\n\nNo artwork is fetched when collecting data, generating a report, or opening it. Only icons selected by the renderer\'s fixed client/provider enum catalog are included. Unknown connectors and providers without a bundled mark use a generic interface icon and an adjacent text label.\n\n## Artwork sources and transformations\n\n- **Palma**: the report uses Palma’s official [teal wordmark](https://palma.ai/brand/wordmark-teal.svg) and [teal brand mark](https://palma.ai/brand/brandmark-teal.svg), bundled as `assets/palma-logo.svg` and `assets/palma-mark.svg`. Palma retains the rights to its marks.\n- **Client artwork supplied by Palma**: Codex/OpenAI, Claude (Code and Desktop), Cursor, Gemini CLI, VS Code, and Windsurf artwork was supplied by Palma for this report. These are existing product-identification assets; their original brand and trademark rights remain with their owners. This notice does not assert a new open-source license for the marks.\n- **Dashboard Icons**: GitHub, Slack, Notion, Linear, Atlassian, Figma, Google Drive, and Google Chrome use [Homarr Labs Dashboard Icons](https://github.com/homarr-labs/dashboard-icons/tree/03e8f8e22da16ccddf5e14afa90711391357231e), pinned to commit `03e8f8e22da16ccddf5e14afa90711391357231e`. Palma supplied the connector artwork from that pinned catalog; the Chrome asset uses the same upstream revision. The upstream Apache License 2.0 is reproduced below, including its attribution notice.\n- **Playwright**: the Playwright mark is from [Microsoft\'s Playwright documentation artwork](https://playwright.dev/img/playwright-logo.svg). The [documentation repository license](https://github.com/microsoft/playwright.dev/blob/main/LICENSE) is Creative Commons Attribution 4.0 International, reproduced below. Retrieved 10 September 2026; the source digest is recorded below.\n- **Generic interface icons**: the shared-client, custom connector, filesystem, browser, and documentation glyphs are code-native interface symbols authored for this report. Browserbase and Context7 use these generic symbols with their names; the glyphs are not presented as their brand marks.\n\nDevelopment-time SVG normalization removes titles and metadata, converts CSS fills to SVG presentation attributes, and namespaces internal IDs for safe embedding. Original path geometry and colors are preserved. The renderer stores the normalized symbols directly; it does not parse or accept SVG content from a snapshot.\n\n## Original source checksums\n\nSource labels identify Palma-supplied artwork or the public upstream catalog described above. Checksums identify the original bytes before SVG normalization.\n\n| Catalog asset | Source | SHA-256 |\n| --- | --- | --- |\n| atlassian | Homarr Labs Dashboard Icons (pinned above) | `a8237d9afe82feb64291bdaad6d52174d1f693ea6d6900eaf78dad9c3a529a65` |\n| chrome | `https://raw.githubusercontent.com/homarr-labs/dashboard-icons/03e8f8e22da16ccddf5e14afa90711391357231e/svg/google-chrome.svg` | `4748547bb1d1cca359b67d3b164e57efb11eaeb41d2ac9cc3f97fccabfa05b0b` |\n| claude | Palma-supplied Claude artwork | `0010d8bd023d70c89bced1b9c26601ffeed0e5dbb312cd3d7d1a099b072317bd` |\n| codex | Palma-supplied Codex/OpenAI artwork | `4008e147d4715ea31a4281e746b65130edd886e5fd05b12021814cbc87e447d9` |\n| cursor | Palma-supplied Cursor artwork | `8235ce4a9d50961ebf8ed238841e0795a2a15ea65b7256c40a7d061742eb3d46` |\n| figma | Homarr Labs Dashboard Icons (pinned above) | `59f327ef3ae14b09c1c96ed5696f890c92efde2a5e6e52779e0515166385b6b9` |\n| gemini | Palma-supplied Gemini artwork | `cc4cfb30bd7ac48dc7ea4df873cfbc97c5f26ff97cac8920064b1b4f31afdaa1` |\n| github | Homarr Labs Dashboard Icons (pinned above) | `cdfb82ff14c8c2484eacba9d211d86cd0c993c933855cad2b03633414fa10ddb` |\n| google-drive | Homarr Labs Dashboard Icons (pinned above) | `963477d7e4a0b0d8865dd7aec8e27d8fd9c3a4b4f2e5b81f9df8581f9f2eca11` |\n| linear | Homarr Labs Dashboard Icons (pinned above) | `586a989c79bcf2284193e3240f1d12cc5a2ad42fa00bd09c622dfbb95438bcd6` |\n| notion | Homarr Labs Dashboard Icons (pinned above) | `b98fea4bc3f3259c6907a40dae994c959c3240d7ee4b4afea144a555c638f6c2` |\n| playwright | `https://playwright.dev/img/playwright-logo.svg` | `6b0a4367bdeab10995bc239278f04c68c10e48adbec15e799e01909a0d66dcb9` |\n| slack | Homarr Labs Dashboard Icons (pinned above) | `62e556a75b94516fd8dcfa9c8ee4eae76268b4087ee927d91a5f2d3115d54118` |\n| vscode | Palma-supplied VS Code artwork | `27f78c66393a925b8702100d788a08427a971ac048c98843c448bf74a5f93b44` |\n| windsurf | Palma-supplied Windsurf artwork | `5870805d8313e7540b517bc9df7fc8a96bc16b8b7c07eeccb12920cddf818964` |\n\n## Dashboard Icons: Apache License 2.0\n\n```text\nApache License\n                           Version 2.0, January 2004\n                        http://www.apache.org/licenses/\n\n   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION\n\n   1. Definitions.\n\n      "License" shall mean the terms and conditions for use, reproduction,\n      and distribution as defined by Sections 1 through 9 of this document.\n\n      "Licensor" shall mean the copyright owner or entity authorized by\n      the copyright owner that is granting the License.\n\n      "Legal Entity" shall mean the union of the acting entity and all\n      other entities that control, are controlled by, or are under common\n      control with that entity. For the purposes of this definition,\n      "control" means (i) the power, direct or indirect, to cause the\n      direction or management of such entity, whether by contract or\n      otherwise, or (ii) ownership of fifty percent (50%) or more of the\n      outstanding shares, or (iii) beneficial ownership of such entity.\n\n      "You" (or "Your") shall mean an individual or Legal Entity\n      exercising permissions granted by this License.\n\n      "Source" form shall mean the preferred form for making modifications,\n      including but not limited to software source code, documentation\n      source, and configuration files.\n\n      "Object" form shall mean any form resulting from mechanical\n      transformation or translation of a Source form, including but\n      not limited to compiled object code, generated documentation,\n      and conversions to other media types.\n\n      "Work" shall mean the work of authorship, whether in Source or\n      Object form, made available under the License, as indicated by a\n      copyright notice that is included in or attached to the work\n      (an example is provided in the Appendix below).\n\n      "Derivative Works" shall mean any work, whether in Source or Object\n      form, that is based on (or derived from) the Work and for which the\n      editorial revisions, annotations, elaborations, or other modifications\n      represent, as a whole, an original work of authorship. For the purposes\n      of this License, Derivative Works shall not include works that remain\n      separable from, or merely link (or bind by name) to the interfaces of,\n      the Work and Derivative Works thereof.\n\n      "Contribution" shall mean any work of authorship, including\n      the original version of the Work and any modifications or additions\n      to that Work or Derivative Works thereof, that is intentionally\n      submitted to Licensor for inclusion in the Work by the copyright owner\n      or by an individual or Legal Entity authorized to submit on behalf of\n      the copyright owner. For the purposes of this definition, "submitted"\n      means any form of electronic, verbal, or written communication sent\n      to the Licensor or its representatives, including but not limited to\n      communication on electronic mailing lists, source code control systems,\n      and issue tracking systems that are managed by, or on behalf of, the\n      Licensor for the purpose of discussing and improving the Work, but\n      excluding communication that is conspicuously marked or otherwise\n      designated in writing by the copyright owner as "Not a Contribution."\n\n      "Contributor" shall mean Licensor and any individual or Legal Entity\n      on behalf of whom a Contribution has been received by Licensor and\n      subsequently incorporated within the Work.\n\n   2. Grant of Copyright License. Subject to the terms and conditions of\n      this License, each Contributor hereby grants to You a perpetual,\n      worldwide, non-exclusive, no-charge, royalty-free, irrevocable\n      copyright license to reproduce, prepare Derivative Works of,\n      publicly display, publicly perform, sublicense, and distribute the\n      Work and such Derivative Works in Source or Object form.\n\n   3. Grant of Patent License. Subject to the terms and conditions of\n      this License, each Contributor hereby grants to You a perpetual,\n      worldwide, non-exclusive, no-charge, royalty-free, irrevocable\n      (except as stated in this section) patent license to make, have made,\n      use, offer to sell, sell, import, and otherwise transfer the Work,\n      where such license applies only to those patent claims licensable\n      by such Contributor that are necessarily infringed by their\n      Contribution(s) alone or by combination of their Contribution(s)\n      with the Work to which such Contribution(s) was submitted. If You\n      institute patent litigation against any entity (including a\n      cross-claim or counterclaim in a lawsuit) alleging that the Work\n      or a Contribution incorporated within the Work constitutes direct\n      or contributory patent infringement, then any patent licenses\n      granted to You under this License for that Work shall terminate\n      as of the date such litigation is filed.\n\n   4. Redistribution. You may reproduce and distribute copies of the\n      Work or Derivative Works thereof in any medium, with or without\n      modifications, and in Source or Object form, provided that You\n      meet the following conditions:\n\n      (a) You must give any other recipients of the Work or\n          Derivative Works a copy of this License; and\n\n      (b) You must cause any modified files to carry prominent notices\n          stating that You changed the files; and\n\n      (c) You must retain, in the Source form of any Derivative Works\n          that You distribute, all copyright, patent, trademark, and\n          attribution notices from the Source form of the Work,\n          excluding those notices that do not pertain to any part of\n          the Derivative Works; and\n\n      (d) If the Work includes a "NOTICE" text file as part of its\n          distribution, then any Derivative Works that You distribute must\n          include a readable copy of the attribution notices contained\n          within such NOTICE file, excluding those notices that do not\n          pertain to any part of the Derivative Works, in at least one\n          of the following places: within a NOTICE text file distributed\n          as part of the Derivative Works; within the Source form or\n          documentation, if provided along with the Derivative Works; or,\n          within a display generated by the Derivative Works, if and\n          wherever such third-party notices normally appear. The contents\n          of the NOTICE file are for informational purposes only and\n          do not modify the License. You may add Your own attribution\n          notices within Derivative Works that You distribute, alongside\n          or as an addendum to the NOTICE text from the Work, provided\n          that such additional attribution notices cannot be construed\n          as modifying the License.\n\n      You may add Your own copyright statement to Your modifications and\n      may provide additional or different license terms and conditions\n      for use, reproduction, or distribution of Your modifications, or\n      for any such Derivative Works as a whole, provided Your use,\n      reproduction, and distribution of the Work otherwise complies with\n      the conditions stated in this License.\n\n   5. Submission of Contributions. Unless You explicitly state otherwise,\n      any Contribution intentionally submitted for inclusion in the Work\n      by You to the Licensor shall be under the terms and conditions of\n      this License, without any additional terms or conditions.\n      Notwithstanding the above, nothing herein shall supersede or modify\n      the terms of any separate license agreement you may have executed\n      with Licensor regarding such Contributions.\n\n   6. Trademarks. This License does not grant permission to use the trade\n      names, trademarks, service marks, or product names of the Licensor,\n      except as required for reasonable and customary use in describing the\n      origin of the Work and reproducing the content of the NOTICE file.\n\n   7. Disclaimer of Warranty. Unless required by applicable law or\n      agreed to in writing, Licensor provides the Work (and each\n      Contributor provides its Contributions) on an "AS IS" BASIS,\n      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or\n      implied, including, without limitation, any warranties or conditions\n      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A\n      PARTICULAR PURPOSE. You are solely responsible for determining the\n      appropriateness of using or redistributing the Work and assume any\n      risks associated with Your exercise of permissions under this License.\n\n   8. Limitation of Liability. In no event and under no legal theory,\n      whether in tort (including negligence), contract, or otherwise,\n      unless required by applicable law (such as deliberate and grossly\n      negligent acts) or agreed to in writing, shall any Contributor be\n      liable to You for damages, including any direct, indirect, special,\n      incidental, or consequential damages of any character arising as a\n      result of this License or out of the use or inability to use the\n      Work (including but not limited to damages for loss of goodwill,\n      work stoppage, computer failure or malfunction, or any and all\n      other commercial damages or losses), even if such Contributor\n      has been advised of the possibility of such damages.\n\n   9. Accepting Warranty or Additional Liability. While redistributing\n      the Work or Derivative Works thereof, You may choose to offer,\n      and charge a fee for, acceptance of support, warranty, indemnity,\n      or other liability obligations and/or rights consistent with this\n      License. However, in accepting such obligations, You may act only\n      on Your own behalf and on Your sole responsibility, not on behalf\n      of any other Contributor, and only if You agree to indemnify,\n      defend, and hold each Contributor harmless for any liability\n      incurred by, or claims asserted against, such Contributor by reason\n      of your accepting any such warranty or additional liability.\n\n   END OF TERMS AND CONDITIONS\n\n   APPENDIX: How to apply the Apache License to your work.\n\n      To apply the Apache License to your work, attach the following\n      boilerplate notice, with the fields enclosed by brackets "[]"\n      replaced with your own identifying information. (Don\'t include\n      the brackets!)  The text should be enclosed in the appropriate\n      comment syntax for the file format. We also recommend that a\n      file or class name and description of purpose be included on the\n      same "printed page" as the copyright notice for easier\n      identification within third-party archives.\n\n   Copyright (c) 2024 Bjorn Lammers, Meier Lukas, Thomas Camlong and Homarr Labs\n\n   Licensed under the Apache License, Version 2.0 (the "License");\n   you may not use this file except in compliance with the License.\n   You may obtain a copy of the License at\n\n       http://www.apache.org/licenses/LICENSE-2.0\n\n   Unless required by applicable law or agreed to in writing, software\n   distributed under the License is distributed on an "AS IS" BASIS,\n   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n   See the License for the specific language governing permissions and\n   limitations under the License.\n```\n\n## Playwright documentation: Creative Commons Attribution 4.0 International\n\n```text\nAttribution 4.0 International\n\n=======================================================================\n\nCreative Commons Corporation ("Creative Commons") is not a law firm and\ndoes not provide legal services or legal advice. Distribution of\nCreative Commons public licenses does not create a lawyer-client or\nother relationship. Creative Commons makes its licenses and related\ninformation available on an "as-is" basis. Creative Commons gives no\nwarranties regarding its licenses, any material licensed under their\nterms and conditions, or any related information. Creative Commons\ndisclaims all liability for damages resulting from their use to the\nfullest extent possible.\n\nUsing Creative Commons Public Licenses\n\nCreative Commons public licenses provide a standard set of terms and\nconditions that creators and other rights holders may use to share\noriginal works of authorship and other material subject to copyright\nand certain other rights specified in the public license below. The\nfollowing considerations are for informational purposes only, are not\nexhaustive, and do not form part of our licenses.\n\n     Considerations for licensors: Our public licenses are\n     intended for use by those authorized to give the public\n     permission to use material in ways otherwise restricted by\n     copyright and certain other rights. Our licenses are\n     irrevocable. Licensors should read and understand the terms\n     and conditions of the license they choose before applying it.\n     Licensors should also secure all rights necessary before\n     applying our licenses so that the public can reuse the\n     material as expected. Licensors should clearly mark any\n     material not subject to the license. This includes other CC-\n     licensed material, or material used under an exception or\n     limitation to copyright. More considerations for licensors:\n\twiki.creativecommons.org/Considerations_for_licensors\n\n     Considerations for the public: By using one of our public\n     licenses, a licensor grants the public permission to use the\n     licensed material under specified terms and conditions. If\n     the licensor\'s permission is not necessary for any reason--for\n     example, because of any applicable exception or limitation to\n     copyright--then that use is not regulated by the license. Our\n     licenses grant only permissions under copyright and certain\n     other rights that a licensor has authority to grant. Use of\n     the licensed material may still be restricted for other\n     reasons, including because others have copyright or other\n     rights in the material. A licensor may make special requests,\n     such as asking that all changes be marked or described.\n     Although not required by our licenses, you are encouraged to\n     respect those requests where reasonable. More_considerations\n     for the public: \n\twiki.creativecommons.org/Considerations_for_licensees\n\n=======================================================================\n\nCreative Commons Attribution 4.0 International Public License\n\nBy exercising the Licensed Rights (defined below), You accept and agree\nto be bound by the terms and conditions of this Creative Commons\nAttribution 4.0 International Public License ("Public License"). To the\nextent this Public License may be interpreted as a contract, You are\ngranted the Licensed Rights in consideration of Your acceptance of\nthese terms and conditions, and the Licensor grants You such rights in\nconsideration of benefits the Licensor receives from making the\nLicensed Material available under these terms and conditions.\n\n\nSection 1 -- Definitions.\n\n  a. Adapted Material means material subject to Copyright and Similar\n     Rights that is derived from or based upon the Licensed Material\n     and in which the Licensed Material is translated, altered,\n     arranged, transformed, or otherwise modified in a manner requiring\n     permission under the Copyright and Similar Rights held by the\n     Licensor. For purposes of this Public License, where the Licensed\n     Material is a musical work, performance, or sound recording,\n     Adapted Material is always produced where the Licensed Material is\n     synched in timed relation with a moving image.\n\n  b. Adapter\'s License means the license You apply to Your Copyright\n     and Similar Rights in Your contributions to Adapted Material in\n     accordance with the terms and conditions of this Public License.\n\n  c. Copyright and Similar Rights means copyright and/or similar rights\n     closely related to copyright including, without limitation,\n     performance, broadcast, sound recording, and Sui Generis Database\n     Rights, without regard to how the rights are labeled or\n     categorized. For purposes of this Public License, the rights\n     specified in Section 2(b)(1)-(2) are not Copyright and Similar\n     Rights.\n\n  d. Effective Technological Measures means those measures that, in the\n     absence of proper authority, may not be circumvented under laws\n     fulfilling obligations under Article 11 of the WIPO Copyright\n     Treaty adopted on December 20, 1996, and/or similar international\n     agreements.\n\n  e. Exceptions and Limitations means fair use, fair dealing, and/or\n     any other exception or limitation to Copyright and Similar Rights\n     that applies to Your use of the Licensed Material.\n\n  f. Licensed Material means the artistic or literary work, database,\n     or other material to which the Licensor applied this Public\n     License.\n\n  g. Licensed Rights means the rights granted to You subject to the\n     terms and conditions of this Public License, which are limited to\n     all Copyright and Similar Rights that apply to Your use of the\n     Licensed Material and that the Licensor has authority to license.\n\n  h. Licensor means the individual(s) or entity(ies) granting rights\n     under this Public License.\n\n  i. Share means to provide material to the public by any means or\n     process that requires permission under the Licensed Rights, such\n     as reproduction, public display, public performance, distribution,\n     dissemination, communication, or importation, and to make material\n     available to the public including in ways that members of the\n     public may access the material from a place and at a time\n     individually chosen by them.\n\n  j. Sui Generis Database Rights means rights other than copyright\n     resulting from Directive 96/9/EC of the European Parliament and of\n     the Council of 11 March 1996 on the legal protection of databases,\n     as amended and/or succeeded, as well as other essentially\n     equivalent rights anywhere in the world.\n\n  k. You means the individual or entity exercising the Licensed Rights\n     under this Public License. Your has a corresponding meaning.\n\n\nSection 2 -- Scope.\n\n  a. License grant.\n\n       1. Subject to the terms and conditions of this Public License,\n          the Licensor hereby grants You a worldwide, royalty-free,\n          non-sublicensable, non-exclusive, irrevocable license to\n          exercise the Licensed Rights in the Licensed Material to:\n\n            a. reproduce and Share the Licensed Material, in whole or\n               in part; and\n\n            b. produce, reproduce, and Share Adapted Material.\n\n       2. Exceptions and Limitations. For the avoidance of doubt, where\n          Exceptions and Limitations apply to Your use, this Public\n          License does not apply, and You do not need to comply with\n          its terms and conditions.\n\n       3. Term. The term of this Public License is specified in Section\n          6(a).\n\n       4. Media and formats; technical modifications allowed. The\n          Licensor authorizes You to exercise the Licensed Rights in\n          all media and formats whether now known or hereafter created,\n          and to make technical modifications necessary to do so. The\n          Licensor waives and/or agrees not to assert any right or\n          authority to forbid You from making technical modifications\n          necessary to exercise the Licensed Rights, including\n          technical modifications necessary to circumvent Effective\n          Technological Measures. For purposes of this Public License,\n          simply making modifications authorized by this Section 2(a)\n          (4) never produces Adapted Material.\n\n       5. Downstream recipients.\n\n            a. Offer from the Licensor -- Licensed Material. Every\n               recipient of the Licensed Material automatically\n               receives an offer from the Licensor to exercise the\n               Licensed Rights under the terms and conditions of this\n               Public License.\n\n            b. No downstream restrictions. You may not offer or impose\n               any additional or different terms or conditions on, or\n               apply any Effective Technological Measures to, the\n               Licensed Material if doing so restricts exercise of the\n               Licensed Rights by any recipient of the Licensed\n               Material.\n\n       6. No endorsement. Nothing in this Public License constitutes or\n          may be construed as permission to assert or imply that You\n          are, or that Your use of the Licensed Material is, connected\n          with, or sponsored, endorsed, or granted official status by,\n          the Licensor or others designated to receive attribution as\n          provided in Section 3(a)(1)(A)(i).\n\n  b. Other rights.\n\n       1. Moral rights, such as the right of integrity, are not\n          licensed under this Public License, nor are publicity,\n          privacy, and/or other similar personality rights; however, to\n          the extent possible, the Licensor waives and/or agrees not to\n          assert any such rights held by the Licensor to the limited\n          extent necessary to allow You to exercise the Licensed\n          Rights, but not otherwise.\n\n       2. Patent and trademark rights are not licensed under this\n          Public License.\n\n       3. To the extent possible, the Licensor waives any right to\n          collect royalties from You for the exercise of the Licensed\n          Rights, whether directly or through a collecting society\n          under any voluntary or waivable statutory or compulsory\n          licensing scheme. In all other cases the Licensor expressly\n          reserves any right to collect such royalties.\n\n\nSection 3 -- License Conditions.\n\nYour exercise of the Licensed Rights is expressly made subject to the\nfollowing conditions.\n\n  a. Attribution.\n\n       1. If You Share the Licensed Material (including in modified\n          form), You must:\n\n            a. retain the following if it is supplied by the Licensor\n               with the Licensed Material:\n\n                 i. identification of the creator(s) of the Licensed\n                    Material and any others designated to receive\n                    attribution, in any reasonable manner requested by\n                    the Licensor (including by pseudonym if\n                    designated);\n\n                ii. a copyright notice;\n\n               iii. a notice that refers to this Public License;\n\n                iv. a notice that refers to the disclaimer of\n                    warranties;\n\n                 v. a URI or hyperlink to the Licensed Material to the\n                    extent reasonably practicable;\n\n            b. indicate if You modified the Licensed Material and\n               retain an indication of any previous modifications; and\n\n            c. indicate the Licensed Material is licensed under this\n               Public License, and include the text of, or the URI or\n               hyperlink to, this Public License.\n\n       2. You may satisfy the conditions in Section 3(a)(1) in any\n          reasonable manner based on the medium, means, and context in\n          which You Share the Licensed Material. For example, it may be\n          reasonable to satisfy the conditions by providing a URI or\n          hyperlink to a resource that includes the required\n          information.\n\n       3. If requested by the Licensor, You must remove any of the\n          information required by Section 3(a)(1)(A) to the extent\n          reasonably practicable.\n\n       4. If You Share Adapted Material You produce, the Adapter\'s\n          License You apply must not prevent recipients of the Adapted\n          Material from complying with this Public License.\n\n\nSection 4 -- Sui Generis Database Rights.\n\nWhere the Licensed Rights include Sui Generis Database Rights that\napply to Your use of the Licensed Material:\n\n  a. for the avoidance of doubt, Section 2(a)(1) grants You the right\n     to extract, reuse, reproduce, and Share all or a substantial\n     portion of the contents of the database;\n\n  b. if You include all or a substantial portion of the database\n     contents in a database in which You have Sui Generis Database\n     Rights, then the database in which You have Sui Generis Database\n     Rights (but not its individual contents) is Adapted Material; and\n\n  c. You must comply with the conditions in Section 3(a) if You Share\n     all or a substantial portion of the contents of the database.\n\nFor the avoidance of doubt, this Section 4 supplements and does not\nreplace Your obligations under this Public License where the Licensed\nRights include other Copyright and Similar Rights.\n\n\nSection 5 -- Disclaimer of Warranties and Limitation of Liability.\n\n  a. UNLESS OTHERWISE SEPARATELY UNDERTAKEN BY THE LICENSOR, TO THE\n     EXTENT POSSIBLE, THE LICENSOR OFFERS THE LICENSED MATERIAL AS-IS\n     AND AS-AVAILABLE, AND MAKES NO REPRESENTATIONS OR WARRANTIES OF\n     ANY KIND CONCERNING THE LICENSED MATERIAL, WHETHER EXPRESS,\n     IMPLIED, STATUTORY, OR OTHER. THIS INCLUDES, WITHOUT LIMITATION,\n     WARRANTIES OF TITLE, MERCHANTABILITY, FITNESS FOR A PARTICULAR\n     PURPOSE, NON-INFRINGEMENT, ABSENCE OF LATENT OR OTHER DEFECTS,\n     ACCURACY, OR THE PRESENCE OR ABSENCE OF ERRORS, WHETHER OR NOT\n     KNOWN OR DISCOVERABLE. WHERE DISCLAIMERS OF WARRANTIES ARE NOT\n     ALLOWED IN FULL OR IN PART, THIS DISCLAIMER MAY NOT APPLY TO YOU.\n\n  b. TO THE EXTENT POSSIBLE, IN NO EVENT WILL THE LICENSOR BE LIABLE\n     TO YOU ON ANY LEGAL THEORY (INCLUDING, WITHOUT LIMITATION,\n     NEGLIGENCE) OR OTHERWISE FOR ANY DIRECT, SPECIAL, INDIRECT,\n     INCIDENTAL, CONSEQUENTIAL, PUNITIVE, EXEMPLARY, OR OTHER LOSSES,\n     COSTS, EXPENSES, OR DAMAGES ARISING OUT OF THIS PUBLIC LICENSE OR\n     USE OF THE LICENSED MATERIAL, EVEN IF THE LICENSOR HAS BEEN\n     ADVISED OF THE POSSIBILITY OF SUCH LOSSES, COSTS, EXPENSES, OR\n     DAMAGES. WHERE A LIMITATION OF LIABILITY IS NOT ALLOWED IN FULL OR\n     IN PART, THIS LIMITATION MAY NOT APPLY TO YOU.\n\n  c. The disclaimer of warranties and limitation of liability provided\n     above shall be interpreted in a manner that, to the extent\n     possible, most closely approximates an absolute disclaimer and\n     waiver of all liability.\n\n\nSection 6 -- Term and Termination.\n\n  a. This Public License applies for the term of the Copyright and\n     Similar Rights licensed here. However, if You fail to comply with\n     this Public License, then Your rights under this Public License\n     terminate automatically.\n\n  b. Where Your right to use the Licensed Material has terminated under\n     Section 6(a), it reinstates:\n\n       1. automatically as of the date the violation is cured, provided\n          it is cured within 30 days of Your discovery of the\n          violation; or\n\n       2. upon express reinstatement by the Licensor.\n\n     For the avoidance of doubt, this Section 6(b) does not affect any\n     right the Licensor may have to seek remedies for Your violations\n     of this Public License.\n\n  c. For the avoidance of doubt, the Licensor may also offer the\n     Licensed Material under separate terms or conditions or stop\n     distributing the Licensed Material at any time; however, doing so\n     will not terminate this Public License.\n\n  d. Sections 1, 5, 6, 7, and 8 survive termination of this Public\n     License.\n\n\nSection 7 -- Other Terms and Conditions.\n\n  a. The Licensor shall not be bound by any additional or different\n     terms or conditions communicated by You unless expressly agreed.\n\n  b. Any arrangements, understandings, or agreements regarding the\n     Licensed Material not stated herein are separate from and\n     independent of the terms and conditions of this Public License.\n\n\nSection 8 -- Interpretation.\n\n  a. For the avoidance of doubt, this Public License does not, and\n     shall not be interpreted to, reduce, limit, restrict, or impose\n     conditions on any use of the Licensed Material that could lawfully\n     be made without permission under this Public License.\n\n  b. To the extent possible, if any provision of this Public License is\n     deemed unenforceable, it shall be automatically reformed to the\n     minimum extent necessary to make it enforceable. If the provision\n     cannot be reformed, it shall be severed from this Public License\n     without affecting the enforceability of the remaining terms and\n     conditions.\n\n  c. No term or condition of this Public License will be waived and no\n     failure to comply consented to unless expressly agreed to by the\n     Licensor.\n\n  d. Nothing in this Public License constitutes or may be interpreted\n     as a limitation upon, or waiver of, any privileges and immunities\n     that apply to the Licensor or You, including from the legal\n     processes of any jurisdiction or authority.\n\n\n=======================================================================\n\nCreative Commons is not a party to its public\nlicenses. Notwithstanding, Creative Commons may elect to apply one of\nits public licenses to material it publishes and in those instances\nwill be considered the “Licensor.” The text of the Creative Commons\npublic licenses is dedicated to the public domain under the CC0 Public\nDomain Dedication. Except for the limited purpose of indicating that\nmaterial is shared under a Creative Commons public license or as\notherwise permitted by the Creative Commons policies published at\ncreativecommons.org/policies, Creative Commons does not authorize the\nuse of the trademark "Creative Commons" or any other trademark or logo\nof Creative Commons without its prior written consent including,\nwithout limitation, in connection with any unauthorized modifications\nto any of its public licenses or any other arrangements,\nunderstandings, or agreements concerning use of licensed material. For\nthe avoidance of doubt, this paragraph does not form part of the\npublic licenses.\n\nCreative Commons may be contacted at creativecommons.org.\n```\n'


_BRAND_ASSETS.update(EXTRA_BRAND_ASSETS)
_CLIENTS.update(EXTRA_CLIENTS)
_ARTWORK_NOTICE += "\n\n" + EXTRA_ARTWORK_NOTICE + "\n\n" + FONT_NOTICE


def _text(value: object) -> str:
    if value is None:
        return "Not recorded"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2)
    return str(value)


# Documentation links come only from the bundled rules, never from snapshot text.
_KNOWN_REFERENCES = frozenset(url for urls in PUBLIC_REFERENCES.values() for url in urls)


def _e(value: object) -> str:
    # Hidden characters in scanned names could reorder text or carry unseen instructions.
    return html.escape(visible(_text(value)), quote=True)


def _records(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _enum(value: object, values: tuple, fallback: str) -> str:
    return value if isinstance(value, str) and value in values else fallback


def _label(value: object) -> str:
    return re.sub(r"(?<=[a-z])(?=[A-Z])", " ", _text(value)).replace("_", " ").replace("-", " ").strip().capitalize()


def _anchor(prefix: str, index: int, value: object) -> str:
    digest = hashlib.sha256(f"{index}:{_text(value)}".encode("utf-8")).hexdigest()[:14]
    return f"{prefix}-{digest}"


def _safe_https(value: object) -> str | None:
    """Accept an explicit HTTPS navigation destination, never an active payload."""
    if not isinstance(value, str) or not value or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        return None
    try:
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
            return None
        # Accessing .port also rejects malformed ports. Credentials never belong in links.
        if parts.port is not None and not 0 < parts.port < 65536:
            return None
        return value
    except (ValueError, UnicodeError):
        return None


def _date(value: object) -> str:
    if isinstance(value, str):
        match = re.match(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})", value)
        if match:
            year, month, day, hour, minute = match.groups()
            months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
            if 1 <= int(month) <= 12:
                zone = " UTC" if value.endswith("Z") or value.endswith("+00:00") else ""
                return f"{int(day)} {months[int(month) - 1]} {year} · {hour}:{minute}{zone}"
    return "Collection time not recorded"


def _icon(name: str, css: str = "") -> str:
    # Fixed, code-native UI icons. No user-controlled SVG or attributes.
    paths = {
        "arrow": '<path d="M5 12h14M13 6l6 6-6 6"/>',
        "chevron": '<path d="m6 9 6 6 6-6"/>',
        "lock": '<rect x="5" y="10" width="14" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
        "search": '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4.5 4.5"/>',
        "print": '<path d="M7 8V3h10v5M7 17H4V9h16v8h-3"/><path d="M7 14h10v7H7zM17 11h.01"/>',
        "external": '<path d="M14 3h7v7M21 3l-9 9M10 4H4v16h16v-6"/>',
        "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',
        "check": '<path d="m5 12 4 4L19 6"/>',
        "connector": '<path d="M9 3v4M15 3v4M7 7h10v4a5 5 0 0 1-10 0V7ZM12 16v5"/>',
        "app": '<rect x="4" y="4" width="16" height="16" rx="4"/><path d="M4 9h16M8 6.5h.01M11 6.5h.01"/>',
        "folder": '<path d="M3 7a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>',
        "browser": '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01M12 12v5M9.5 14.5h5"/>',
        "shared": '<circle cx="8" cy="8" r="3"/><path d="M2 20v-2a6 6 0 0 1 12 0v2M16 5a3 3 0 0 1 0 6M17 14a5 5 0 0 1 5 5v1"/>',
        "book": '<path d="M3 4h6a3 3 0 0 1 3 3v14a3 3 0 0 0-3-3H3V4ZM21 4h-6a3 3 0 0 0-3 3v14a3 3 0 0 1 3-3h6V4Z"/>',
    }
    return f'<svg class="icon {css}" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{paths[name]}</svg>'


def _client_details(value: object) -> tuple[str, str]:
    key = value.strip().lower() if isinstance(value, str) else ""
    return _CLIENTS.get(key, (_text(value), "app"))


def _provider_details(details: dict) -> tuple[str | None, str]:
    value = details.get("provider")
    return _PROVIDERS.get(value, (None, "connector")) if isinstance(value, str) else (None, "connector")


def _brand_icon(key: str) -> str:
    if key in _BRAND_ASSETS:
        viewbox = _BRAND_ASSETS[key][0]
        return f'<svg class="brand-icon" data-brand="{key}" width="20" height="20" viewBox="{viewbox}" aria-hidden="true" focusable="false"><use href="#brand-{key}"/></svg>'
    generic = key if key in {"app", "connector", "folder", "browser", "shared", "book"} else "connector"
    return _icon(generic, "brand-icon brand-icon-generic").replace('<svg ', f'<svg data-generic="{generic}" ', 1)


def _client_identity(value: object) -> str:
    name, icon = _client_details(value)
    return f'<span class="client-identity">{_brand_icon(icon)}<span>{_e(name)}</span></span>'


def _observation_identity(item: dict) -> str:
    name = _text(item.get("name", "Unnamed observation"))
    if item.get("kind") == "client":
        label, icon = _client_details(item.get("client", name))
    elif item.get("kind") == "mcp":
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        provider, icon = _provider_details(details)
        label = name
    else:
        return f'<strong>{_e(name)}</strong>'
    instance = f'<span class="observation-instance">{_e(provider)}</span>' if item.get("kind") == "mcp" and provider and provider.casefold() != name.casefold() else ""
    return f'<span class="observation-identity">{_brand_icon(icon)}<span><strong>{_e(label)}</strong>{instance}</span></span>'


def _brand_sprite(observations: list[dict]) -> str:
    used = set()
    for item in observations:
        used.add(_client_details(item.get("client", ""))[1])
        if item.get("kind") == "mcp":
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            used.add(_provider_details(details)[1])
    symbols = "".join(_BRAND_ASSETS[key][1] for key in sorted(used) if key in _BRAND_ASSETS)
    return f'<svg class="brand-sprite" width="0" height="0" aria-hidden="true" focusable="false"><defs>{symbols}</defs></svg>' if symbols else ""


_KIND_LABELS = {"client": "AI client", "mcp": "Connector", "skill": "Skill", "plugin": "Plugin",
                "agent": "Agent", "setting": "Setting", "hook": "Hook"}
_KIND_PLURALS = {"mcp": ("connector", "connectors"), "skill": ("skill", "skills"), "plugin": ("plugin", "plugins"),
                 "agent": ("agent", "agents"), "hook": ("hook", "hooks"), "setting": ("setting", "settings")}
_KIND_ORDER = ("mcp", "skill", "plugin", "agent", "hook", "setting")
_EVIDENCE_VISIBLE = 20
_EVIDENCE_LIMIT = 200
_LOCATIONS_LIMIT = 100
# Folders and files that name an AI configuration location. The shareable report keeps the
# last such segment and the file name, and drops every folder around them.
_SHARE_MARKERS = frozenset({".claude", ".claude.json", ".mcp.json", ".cursor", ".vscode", ".gemini", ".codex",
                            ".agents", ".github", ".opencode", "opencode.json", "opencode.jsonc", ".continue", ".kiro",
                            ".windsurf", ".roo", ".cline", ".codeium", ".aider.conf.yml", ".copilot", ".openclaw",
                            ".lmstudio", ".local", ".config", ".mozilla", "Library", "AppData", "Applications",
                            "etc", "Program Files", "ProgramData"})
# Scanner-generated labels rather than filesystem paths; they name no folder of the user's.
_PSEUDO_LOCATIONS = ("system:", "machine:", "installation:", "managed:", "managed-cache:", "session:", "user:",
                     "override:", "collection:", "scope:")
_PATH_LIKE = re.compile(r"[\\/]|://")
# Names that are network addresses or email addresses identify organisations and people.
_NETWORK_NAME = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}|[^\s@]+@[^\s@]+\.[^\s@]+")
# File names the shareable report keeps; any other file shows only its extension.
_SHARE_FILES = frozenset({"settings.json", "settings.local.json", "mcp.json", "mcp_config.json", "mcp-config.json", "mcp_settings.json",
                          "cline_mcp_settings.json", "claude_desktop_config.json", "config.toml", "config.json", "config.jsonc",
                          "config.yaml", "config.yml", "cli-config.json", "cli.json", "hooks.json", "plugin.json", "marketplace.json",
                          "installed_plugins.json", "known_marketplaces.json", "skill.md", "agents.md", "claude.md", "gemini.md",
                          "extensions.json", "manifest.json", "trustedfolders.json", ".codex-global-state.json", "managed-settings.json",
                          "managed-mcp.json", "remote-settings.json", "system-defaults.json", "state.vscdb", "info.plist",
                          "package.json", "openclaw.json", "exec-approvals.json", "codex-package.json", "gemini-extension.json",
                          "codex", "claude", "cursor", "cursor-agent", "gemini", "code", "code-insiders", "windsurf", "ollama",
                          "opencode", "copilot", "aider", "kiro", "goose", "antigravity", "chatgpt", "openclaw"})
_CLIENT_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,40}")
# A path or web address left in finding text after its known locations are reduced.
_ADDRESS = re.compile(r"(?<![\w.])(?:~|[A-Za-z]:)?[\\/][^\s,;]*|\b[A-Za-z][A-Za-z0-9+.-]*://\S*")


def _share_location(value: object) -> str:
    """A location for the shareable report: its AI configuration folder and file name only.

    ``~/.claude/settings.json`` stays as it is; ``~/code/app/.cursor/mcp.json`` becomes
    ``project/.cursor/mcp.json``; anything between the configuration folder and the file
    becomes an ellipsis. Applying it twice gives the same result.
    """
    text = _text(value).replace("\\", "/")
    if text.startswith(_PSEUDO_LOCATIONS):
        return text
    parts = [part for part in text.split("/") if part]
    markers = [index for index, part in enumerate(parts) if part in _SHARE_MARKERS]
    if not markers:
        return "location withheld"
    start = markers[-1]
    tail = parts[start:] if len(parts) - start <= 2 else [parts[start], "\u2026", parts[-1]]
    if len(tail) > 1:
        # A file name can itself name a project or client.
        base = tail[-1]
        suffix = "." + base.rsplit(".", 1)[1] if "." in base.strip(".") and re.fullmatch(r"[A-Za-z0-9]{1,8}", base.rsplit(".", 1)[1]) else ""
        if base.lower().removesuffix(".exe") not in _SHARE_FILES and base not in _SHARE_MARKERS:
            tail[-1] = "(name withheld)" + suffix
    if start == 1 and parts[0] == "~":
        prefix = "~/"
    elif start == 1 and re.fullmatch(r"[A-Za-z]:", parts[0]):
        prefix = parts[0] + "/"
    elif start == 0 and text.startswith("/"):
        prefix = "/"
    else:
        prefix = "project/"
    return prefix + "/".join(tail)


def _shareable(snapshot: dict) -> dict:
    """The snapshot as the shareable summary shows it: nothing names a folder or an address.

    Locations are reduced by ``_share_location``. Every other string an observation or
    evidence line carries is withheld when it is a path or web address, and a client id
    outside the scanner's vocabulary becomes "unknown". Finding text keeps its reduced
    locations and loses any other path or address. The scope label is dropped.
    """
    data = copy.deepcopy(snapshot)
    replacements = {}

    def location(value):
        if isinstance(value, str):
            replacements[value] = _share_location(value)
            return replacements[value]
        return value

    def withheld(value, label="value withheld"):
        if isinstance(value, str):
            if _PATH_LIKE.search(value):
                return replacements.setdefault(value, label)
            return value
        if isinstance(value, list):
            return [withheld(entry) for entry in value]
        if isinstance(value, dict):
            return {key: withheld(entry) for key, entry in value.items()}
        return value

    def client(value):
        return value if isinstance(value, str) and _CLIENT_ID.fullmatch(value) else "unknown"

    def name(value):
        if isinstance(value, str) and "@" in value and "." not in value.split("@", 1)[1]:
            replacements.setdefault(value, value.split("@", 1)[0])
            value = value.split("@", 1)[0]  # A plugin id without its marketplace.
        if isinstance(value, str) and _NETWORK_NAME.fullmatch(value):
            return replacements.setdefault(value, "Name withheld")
        return withheld(value, "Name withheld")

    def prose(text):
        if not isinstance(text, str):
            return text
        kept = []
        for original in sorted(replacements, key=len, reverse=True):
            if original in text:
                text = text.replace(original, f"\x00{len(kept)}\x00")
                kept.append(replacements[original])
        text = _ADDRESS.sub("location withheld", text)
        return re.sub("\x00(\\d+)\x00", lambda match: kept[int(match.group(1))], text)

    if isinstance(data.get("scope"), dict):
        data["scope"].pop("label", None)
    name_groups = {}
    for item in _records(data.get("observations")):
        # Group before redaction: unrelated private names can both become "Name withheld".
        group_key = (_text(item.get("kind")), _text(item.get("name")))
        item["_reportNameGroup"] = name_groups.setdefault(group_key, len(name_groups))
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        locations = details.pop("locations", None)
        value = details.get("value")
        if details.get("interpretation") == "inventory-only" and isinstance(value, (int, float)) and not isinstance(value, bool):
            details["value"] = "value withheld"  # An untyped number can be a code, id or account number.
        item["details"] = withheld(details)
        if isinstance(locations, list):
            item["details"]["locations"] = list(dict.fromkeys(location(entry) for entry in locations if isinstance(entry, str)))
        item["name"] = name(item.get("name"))
        item["location"], item["client"] = location(item.get("location")), client(item.get("client"))
    for finding in _records(data.get("findings")):
        finding["clients"] = [client(value) for value in finding["clients"]] if isinstance(finding.get("clients"), list) else []
        for entry in _records(finding.get("evidence")):
            entry["key"], entry["value"] = name(entry.get("key")), withheld(entry.get("value"))
            entry["location"] = location(entry.get("location"))
    for source in _records(data.get("sources")):
        source["location"], source["client"] = location(source.get("location")), client(source.get("client"))
    for finding in _records(data.get("findings")):
        for key in ("title", "summary", "impact", "recommendation", "ratingReason"):
            if key in finding:
                finding[key] = prose(finding[key])
    return data


def _client_anchor(value: object) -> str:
    return "inventory-" + hashlib.sha256(_text(value).casefold().encode("utf-8")).hexdigest()[:12]


def _plural(count: int, singular: str, plural: str) -> str:
    return f"{count:,} {singular if count == 1 else plural}"


def _fact(label: str, tone: str = "") -> str:
    return f'<span class="fact{" fact-" + tone if tone else ""}">{_e(label)}</span>'


def _value_text(value: object) -> str:
    """A typed setting value as plain text; summaries become short phrases, never JSON."""
    if isinstance(value, dict):
        phrases = []
        for key, item in sorted(value.items()):
            if item is True:
                phrases.append(_label(key).lower())
            elif isinstance(item, (int, float, str)) and not isinstance(item, bool):
                phrases.append(f"{_label(key).lower()} {item}")
        return ", ".join(phrases) or "summary recorded"
    if isinstance(value, list):
        return _plural(len(value), "entry", "entries")
    return _text(value)


def _setting_fact(key: object, value: object) -> str:
    return f'<code class="fact fact-setting">{_e(key)} = {_e(_value_text(value))}</code>'


def _count(value: object) -> int:
    return value if type(value) is int and value > 0 else 0


def _facts(item: dict) -> list[str]:
    """Typed facts worth reading at a glance; the complete record stays in snapshot.json."""
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    kind, facts = item.get("kind"), []
    add = lambda label, tone="": facts.append(_fact(label, tone))
    if kind == "client":
        versions = [value for value in details.get("versions", []) if isinstance(value, str)] if isinstance(details.get("versions"), list) else []
        version = details.get("version")
        if versions:
            add("Versions " + ", ".join(versions))
        elif isinstance(version, str) and version and version != "not-inspected":
            add("Version " + version)
        if details.get("installationState") == "installed" or details.get("activation") == "installed":
            add("Installed")
        if details.get("processObserved") is True or details.get("activation") == "running":
            add("Running")
        if _count(details.get("projectCount")):
            add("Used in " + _plural(details["projectCount"], "project", "projects"))
        modes = details.get("authModes") if isinstance(details.get("authModes"), list) else []
        for mode in modes:
            if isinstance(mode, str) and mode != "unknown":
                add({"api_key": "Signs in with an API key", "vendor_login": "Vendor account sign-in",
                     "cloud_provider": "Cloud provider sign-in", "enterprise_identity": "Enterprise identity"}.get(mode, _label(mode)))
    elif kind == "mcp":
        if details.get("governedBy") == "palma-gateway":
            add("Through Palma gateway", "good")
        if details.get("endpointScope") == "loopback":
            add("Loopback endpoint")
        elif details.get("execution") == "local" or details.get("transport") in ("stdio", "sdk"):
            add("Runs locally")
        elif details.get("execution") == "remote":
            add("Remote service")
        else:
            add("Transport not recognized")
        if details.get("cleartextTransport") is True:
            add("Unencrypted connection", "risk")
        capability = details.get("capability") or (details.get("toolFamily") if details.get("toolFamily") in ("computer", "browser") else None)
        approval = details.get("autoApproval")
        if capability in ("computer", "browser"):
            add("Controls screen, keyboard and mouse" if capability == "computer" else "Controls a web browser", "risk")
            # System policy configures the connector; it still acts as the signed-in user.
            alias = details.get("accountAlias", "~")
            if alias == "system":
                add("Set by system policy")
            add("Acts as that account" if isinstance(alias, str) and alias.startswith("user-") else "Acts as you")
            add({"all": "No approval before tool use", "none": "Asks before tool use"}.get(approval, "Approval setting not recorded"), "risk" if approval == "all" else "")
        elif approval == "all":
            add("No approval before tool use", "risk")
        if details.get("inlineCredentialPresent") is True or _count(details.get("literalCredentialCount")):
            add("Credential stored in the file", "risk")
        auth = {"bearer_header": "Fixed secret", "static_header": "Fixed secret", "oauth_declared": "OAuth sign-in",
                "environment_reference": "Secret from environment"}.get(details.get("auth"))
        if auth:
            add(auth)
        if details.get("unversionedPackage") is True:
            add("Unpinned package version")
        if details.get("configurationIssue"):
            add("Unsupported configuration", "risk")
    elif kind == "skill":
        if details.get("provenance") == "version-controlled":
            add("In version control")
        elif details.get("context") == "package" or details.get("parentId"):
            add("From a plugin")
        elif details.get("origin") == "project" or details.get("context") == "project":
            add("Project skill")
        elif details.get("origin") == "user":
            add("Your skills folder")
        if _count(details.get("filesHashed")):
            add(_plural(details["filesHashed"], "file", "files"))
        if "digest" in details and not details.get("digest"):
            add("Contents not fully read")
    elif kind == "agent":
        if _count(details.get("toolCount")):
            add(_plural(details["toolCount"], "tool", "tools"))
        if details.get("delegation") == "remote":
            add("Delegates to a remote agent", "risk")
    elif kind == "plugin":
        if isinstance(details.get("version"), str) and details["version"]:
            add("Version " + details["version"])
        if details.get("installationState") == "cached":
            add("Cached, not installed")
        if details.get("origin") == "local":
            add("Installed outside a marketplace", "risk")
        if details.get("broadHostAccess") is True:
            add("Access to all websites", "risk")
        if details.get("aiRelatedNameHint") is True:
            permissions = details.get("permissions")
            if isinstance(permissions, list):
                for permission in dict.fromkeys(value for value in permissions if isinstance(value, str)):
                    add("Permission: " + permission)
    elif kind == "hook":
        events = [str(event) for event in details.get("events", []) if isinstance(event, str)] if isinstance(details.get("events"), list) else []
        if events:
            add("Runs on " + ", ".join(events[:4]) + (f" and {len(events) - 4} more" if len(events) > 4 else ""))
        counts = details.get("typeCounts") if isinstance(details.get("typeCounts"), dict) else {}
        for handler, (singular, plural) in (("command", ("command handler", "command handlers")), ("http", ("web request handler", "web request handlers")),
                                            ("prompt", ("prompt handler", "prompt handlers")), ("agent", ("agent handler", "agent handlers")),
                                            ("configuredLocations", ("hook folder", "hook folders"))):
            if _count(counts.get(handler)):
                add(_plural(counts[handler], singular, plural))
    elif kind == "setting":
        key = details.get("key") or details.get("nativeKey")
        if isinstance(key, str) and key and "value" in details:
            facts.append(_setting_fact(key, details["value"]))
    if kind in {"skill", "plugin", "agent"}:
        source_trust = details.get("sourceTrust")
        if source_trust == "allowlisted":
            add("Allowlisted source")
        elif source_trust == "unapproved":
            add("Marketplace review required", "risk")
        elif source_trust == "unresolved":
            add("Source not verified")
    return facts


def _state_chip(item: dict) -> str:
    if item.get("kind") == "client":
        return ""
    state = _enum(item.get("enabled"), ("enabled", "disabled", "unknown"), "unknown")
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    label = _observed_state(details, state)
    return f'<span class="state state-{state}">{_e(label)}</span>' if label else ""


def _where(item: dict, share: bool, *, list_places: bool = True) -> str:
    """The location, and every other place the same declaration appears.

    The inventory lists the places; evidence rows only count them, so a declaration
    copied into many folders is listed once per report.
    """
    details = item.get("details") if isinstance(item.get("details"), dict) else {}
    location = item.get("location", "Location not recorded")
    html = f'<code class="inventory-path">{_e(_share_location(location) if share else location)}</code>'
    others = [entry for entry in details.get("locations", []) if isinstance(entry, str)] if isinstance(details.get("locations"), list) else []
    total = details.get("locationCount") if _count(details.get("locationCount")) else len(others)
    copies = _count(details.get("copyCount"))
    if total > 1 and (share or not list_places):
        html += f'<span class="location-count">Declared in {total:,} places</span>'
    elif total > 1:
        rows = "".join(f"<li><code>{_e(entry)}</code></li>" for entry in others[:_LOCATIONS_LIMIT])
        if total > min(len(others), _LOCATIONS_LIMIT):
            rows += f'<li class="muted">{total - min(len(others), _LOCATIONS_LIMIT):,} more not listed</li>'
        html += f'<details class="locations"><summary>Declared in {total:,} places{_icon("chevron", "disclosure-icon")}</summary><ul>{rows}</ul></details>'
    elif copies > 1:
        html += f'<span class="location-count">Declared {copies:,} times in this file</span>'
    return html


def _artwork_credits() -> str:
    return f'<details class="artwork-credits"><summary><span>Artwork credits</span>{_icon("chevron", "disclosure-icon")}</summary><div class="artwork-content"><p>Brand marks identify declared products and belong to their respective owners. Artwork comes from Palma’s existing asset library, Homarr Labs Dashboard Icons, and Microsoft’s Playwright documentation. Generic interface symbols are used where no brand artwork is bundled. Onest 2.001 is embedded under the SIL Open Font License 1.1.</p><p class="artwork-sources"><a class="artwork-reference" href="https://github.com/homarr-labs/dashboard-icons/tree/03e8f8e22da16ccddf5e14afa90711391357231e" rel="noreferrer noopener" target="_blank">Dashboard Icons · Apache 2.0<span class="sr-only"> (opens in a new tab)</span></a><a class="artwork-reference" href="https://github.com/microsoft/playwright.dev/blob/main/LICENSE" rel="noreferrer noopener" target="_blank">Playwright documentation · CC BY 4.0<span class="sr-only"> (opens in a new tab)</span></a></p><details class="artwork-license"><summary>Read full licenses and provenance{_icon("chevron", "disclosure-icon")}</summary><pre>{_e(_ARTWORK_NOTICE)}</pre></details></div></details>'


def _badge(severity: str) -> str:
    return f'<span class="severity severity-{severity}"><span class="severity-dot" aria-hidden="true"></span>{_SEVERITY_NAMES[severity]}</span>'


def _observation_context(details: dict) -> str:
    """Keep non-default, cached, and profile applicability visible before expanding."""
    context = details.get("context")
    notes = []
    version = details.get("version")
    if isinstance(version, str) and version:
        notes.append("Version " + version)
    account = details.get("accountAlias")
    if isinstance(account, str) and account not in {"", "~"}:
        notes.append("Profile: " + _label(account))
    if isinstance(context, str) and context and context != "base":
        notes.append("Context: " + _label(context))
    if details.get("profileSelected") is False:
        notes.append("Unselected profile")
    elif details.get("profileSelected") is True:
        notes.append("Selected profile")
    if details.get("shadowedBySelectedProfile") is True:
        notes.append("Overridden by selected profile")
    if details.get("effective") is False or details.get("effectiveConfiguration") is False:
        notes.append("Not effective configuration")
    if isinstance(details.get("applicability"), str):
        notes.append(details["applicability"])
    return '<span class="inventory-context">' + _e(" · ".join(notes)) + '</span>' if notes else ""


def _observed_state(details: dict, state: str) -> str:
    if state == "disabled":
        return _STATES[state]
    activation = _text(details.get("activation"))
    return {"running": "Process observed", "installed": "Installed", "cached": "Cached",
            "present": "", "configured": "Configured"}.get(activation, _STATES[state])


def _finding_chart(counts: Counter, total: int) -> str:
    highest = max(counts.values(), default=0) or 1
    rows = []
    for severity in _SEVERITIES:
        count = counts[severity]
        width = round(240 * count / highest, 2)
        rows.append(f'<a class="chart-row" href="#findings" data-priority="{severity}" aria-label="Show {count} {_SEVERITY_NAMES[severity]} findings"><span class="chart-label">{_SEVERITY_NAMES[severity]}</span><svg viewBox="0 0 240 16" class="bar-chart" aria-hidden="true"><rect width="240" height="16" rx="5" class="bar-track"/><rect width="{width}" height="16" rx="5" class="bar-{severity}"/></svg><span class="chart-number">{count}</span></a>')
    return f'<aside class="priority-chart" aria-label="Finding counts by priority"><div class="chart-heading"><h3>Review priorities</h3><span>{total} findings</span></div>{"".join(rows)}<p class="chart-footnote">Select a bar to inspect its findings.</p></aside>'


def _finding_clients(finding: dict, observations: dict[str, dict]) -> list[str]:
    refs = finding.get("observationIds", [])
    if not isinstance(refs, list):
        return []
    declared = finding.get("clients", [])
    clients = {item for item in declared if isinstance(item, str) and item} if isinstance(declared, list) else set()
    return sorted(clients | {_text(observations.get(_text(ref), {}).get("client")) for ref in refs
                   if observations.get(_text(ref), {}).get("client")}, key=str.casefold)


def _overview(findings: list[tuple[str, dict]], counts: Counter, observations: dict[str, dict], graph: dict, client_count: int, coverage_status: str) -> str:
    first_count = counts["critical"] + counts["high"]
    if first_count:
        headline = f'{first_count} {"item" if first_count == 1 else "items"} to review first.'
    elif counts["medium"]:
        headline = f'{counts["medium"]} {"item" if counts["medium"] == 1 else "items"} worth a closer look.'
    elif counts["low"]:
        headline = f'{counts["low"]} {"item" if counts["low"] == 1 else "items"} for routine review.'
    else:
        headline = "No priority review items."
    rows = []
    selected, seen = [], set()
    for anchor, finding in findings:
        if finding.get("severity") == "info":
            continue
        key = (_text(finding.get("ruleId")), _text(finding.get("title")))
        if key not in seen:
            seen.add(key)
            selected.append((anchor, finding))
        if len(selected) == 3:
            break
    for anchor, finding in selected:
        severity = _enum(finding.get("severity"), _SEVERITIES, "info")
        rows.append(f'<a class="priority-item priority-item-{severity}" href="#{anchor}"><span class="priority-copy"><span class="priority-meta">{_badge(severity)}</span><strong>{_e(finding.get("title", "Review this observation"))}</strong></span>{_icon("arrow")}</a>')
    nodes = "".join(f'<a class="environment-node" href="#{target}"><span class="environment-node-icon">{_icon(icon)}</span><strong>{count:,}</strong><span>{label}</span><small>{note}</small></a>' for count, label, note, icon, target in (
        (graph["mcpNames"], "MCP server names", f'{graph["mcpConfigurations"]:,} configurations', "connector", "inventory-mcp" if graph["mcpNames"] else "inventory"),
        (graph["skillNames"], "Skill names", f'{graph["skillConfigurations"]:,} configurations', "book", "inventory-skill" if graph["skillNames"] else "inventory"),
        (graph["plugins"], "Plugins", "configuration records", "app", "inventory")))
    root_label = "AI clients" if client_count else "Client groups"
    root_count = client_count or len(graph["clients"])
    environment = f'<div class="environment-overview" data-mcp-names="{graph["mcpNames"]}" data-skill-names="{graph["skillNames"]}"><div class="chart-heading"><h3>Your AI environment</h3><a href="#client-map">Explore clients{_icon("arrow")}</a></div><a class="environment-root" href="#client-map">{_icon("app")}<strong>{root_count}</strong><span>{root_label}</span></a><div class="environment-branches">{nodes}</div><p class="reach-title">MCP configurations</p>{_reach_strip(graph["reach"])}<p class="chart-footnote">Configured relationships; activity is not inferred.</p></div>'
    info = f'<a href="#findings" data-priority="info" class="overview-info">{counts["info"]} informational</a>' if counts["info"] else ""
    shortlist = '<div class="priority-shortlist">' + "".join(rows) + '</div>' if rows else ""
    return f'<section class="overview visual-overview" id="overview" aria-labelledby="overview-title"><div class="overview-intro"><div><p class="eyebrow">At a glance</p><h2 id="overview-title">{headline}</h2></div><div class="overview-status"><a class="coverage-status" href="#coverage">{_icon("info")}{_e(coverage_status)}</a>{info}</div></div>{shortlist}<div class="overview-grid">{_finding_chart(counts, len(findings))}{environment}</div></section>'


def _reach_strip(reach: dict) -> str:
    total = sum(reach.values())
    offset, pieces = 0, []
    for key in ("local", "remote", "unknown", "disabled"):
        width = 100 * reach[key] / total if total else 0
        pieces.append(f'<rect class="reach-fill-{key}" x="{offset:.6f}" y="0" width="{width:.6f}" height="10"/>')
        offset += width
    legend = "".join(f'<span><i class="reach-dot reach-fill-{key}"></i><strong>{reach[key]}</strong> {label}</span>' for key, label in (("local", "Local"), ("remote", "Remote"), ("unknown", "Unknown"), ("disabled", "Disabled")) if reach[key] or key in ("local", "remote"))
    return f'<div class="reach-strip"><svg viewBox="0 0 100 10" preserveAspectRatio="none" aria-hidden="true">{"".join(pieces)}</svg><div class="reach-legend">{legend}</div></div>'


def _client_map(graph: dict, observations: list[dict]) -> str:
    rows = []
    for group in sorted(graph["clients"], key=lambda row: _client_details(row["client"])[0].casefold()):
        client = group["client"]
        components = "".join(f'<a class="client-component" href="#{target}"><strong>{count}</strong><span>{label}</span></a>' for count, label, target in (
            (group["mcpNames"], "MCP servers", "inventory-mcp" if group["mcpNames"] else _client_anchor(client)),
            (group["skillNames"], "Skills", "inventory-skill" if group["skillNames"] else _client_anchor(client)),
            (group["plugins"], "Plugins", _client_anchor(client))))
        rows.append(f'<li class="client-map-row"><a class="client-map-identity" href="#{_client_anchor(client)}">{_client_identity(client)}</a><div class="client-components">{components}</div><div class="client-reach">{_reach_strip(group["reach"])}<small>{group["mcpConfigurations"]} MCP configurations</small></div></li>')
    return _disclosure("client-map", "Client connections", f'{len(rows)} client groups', '<p class="disclosure-intro">Each client’s configured components. A shared name can appear in several clients.</p><ul class="client-map">' + "".join(rows) + '</ul>' + _access_overview(observations), "app")


def _disclosure(identity: str, title: str, count: str, body: str, icon: str) -> str:
    return f'<details class="report-disclosure" id="{identity}"><summary><span class="disclosure-section-icon">{_icon(icon)}</span><h2>{title}</h2><span class="disclosure-section-count">{_e(count)}</span>{_icon("chevron", "disclosure-icon")}</summary><div class="report-disclosure-body">{body}</div></details>'


def _access_overview(observations: list[dict]) -> str:
    mcps = [item for item in observations if item.get("kind") == "mcp"]
    if not mcps:
        return ""
    reaches = (("local", "Local process"), ("loopback", "Loopback HTTP endpoint"), ("gateway", "Through Palma gateway"),
               ("remote", "Remote endpoint"), ("unknown", "Reach unknown"))
    counts = Counter()
    disabled = 0
    for item in mcps:
        state = _enum(item.get("enabled"), ("enabled", "disabled", "unknown"), "unknown")
        if state == "disabled":
            disabled += 1
            continue
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        if details.get("execution") == "local" or details.get("transport") == "stdio":
            reach = "local"
        elif details.get("endpointScope") == "loopback":
            reach = "loopback"
        elif details.get("governedBy") == "palma-gateway":
            reach = "gateway"
        elif details.get("execution") == "remote":
            reach = "remote"
        else:
            reach = "unknown"
        counts[reach] += 1
    maximum = max(counts.values(), default=0) or 1
    rows = []
    for reach, label in reaches:
        width = round(220 * counts[reach] / maximum, 2)
        rows.append(f'<div class="access-chart-row" data-reach="{reach}"><span>{label}</span><svg viewBox="0 0 220 6" class="access-bar" aria-hidden="true"><rect width="220" height="6" rx="3" class="bar-track"/><rect width="{width}" height="6" rx="3" class="reach-{reach}"/></svg><strong>{counts[reach]}</strong></div>')
    disabled_note = f'<p class="access-state-note">{disabled} {"disabled entry is" if disabled == 1 else "disabled entries are"} excluded from these bars.</p>' if disabled else ""
    return f'<section class="access-overview" aria-labelledby="access-title"><div><p class="eyebrow">Access footprint</p><div class="access-heading"><h2 id="access-title">Where MCP access can reach</h2><a href="#inventory">Inspect configurations{_icon("arrow")}</a></div><div class="access-chart" aria-label="MCP configurations by access reach, excluding disabled entries">{"".join(rows)}</div></div><div class="access-note"><span class="access-note-icon">{_icon("connector")}</span><h3>Configured access, in context</h3><p>These counts describe configuration, not running processes or live connections. Browser and computer-control capabilities appear in findings when the scan identifies a relevant pattern.</p>{disabled_note}</div></section>'


def _team_teaser(booking_link: str) -> str:
    # This is a labeled conceptual diagram, not an aggregation of report findings.
    diagram = '''<figure class="team-diagram"><svg viewBox="0 0 390 215" role="img" aria-labelledby="team-diagram-title team-diagram-description"><title id="team-diagram-title">Individual endpoints, one team view</title><desc id="team-diagram-description">Illustration of your endpoint and teammates’ endpoints contributing to a separate Palma team view of shared tools, repeated exposure, and priorities. This report does not aggregate or send results.</desc><g fill="none" stroke="#76b1bb" stroke-width="1.5"><path d="M123 41h30c16 0 23 11 23 27v15c0 16 8 24 24 24h15"/><path d="M123 107h92"/><path d="M123 173h30c16 0 23-11 23-27v-15c0-16 8-24 24-24h15"/><path d="m208 101 7 6-7 6"/></g><g class="diagram-endpoint"><rect x="4" y="18" width="119" height="46" rx="10"/><rect x="4" y="84" width="119" height="46" rx="10"/><rect x="4" y="150" width="119" height="46" rx="10"/></g><g fill="none" stroke="#548a94" stroke-width="1.5" stroke-linejoin="round"><path d="M17 31h17v12H17zM14 47h23M17 97h17v12H17zM14 113h23M17 163h17v12H17zM14 179h23"/></g><g class="diagram-source-label"><text x="45" y="45">Your scan</text><text x="45" y="111">Teammate</text><text x="45" y="177">Teammate</text></g><rect class="diagram-team-card" x="223" y="40" width="162" height="136" rx="14"/><text class="diagram-team-title" x="242" y="68">One team view</text><path d="M242 81h124" stroke="#d5e6e9"/><g fill="#398493"><circle cx="246" cy="102" r="3"/><circle cx="246" cy="125" r="3"/><circle cx="246" cy="148" r="3"/></g><g class="diagram-result-label"><text x="257" y="106">Common tools</text><text x="257" y="129">Exposure</text><text x="257" y="152">Priorities</text></g></svg><figcaption>Illustrative team view · separate Palma offering</figcaption></figure>'''
    invitation = booking_link or '<p class="team-invitation">Interested in the team view? <strong>Get in touch with Palma.</strong></p>'
    return f'''<aside class="team-teaser" id="team-view" aria-labelledby="team-title"><div class="team-main"><div class="team-copy"><p class="eyebrow">The next perspective</p><h2 id="team-title">See the bigger picture<br>across your team.</h2><p>Bring individual scans into an aggregated Palma view to understand shared AI tools, repeated exposure, and governance priorities across people and devices.</p></div>{diagram}</div><div class="team-benefits"><div>{_icon("shared")}<h3>Find the common ground</h3><p>See which AI clients, skills, and connectors appear across your team.</p></div><div>{_icon("connector")}<h3>Spot recurring exposure</h3><p>Connect permission and configuration patterns that repeat across endpoints.</p></div><div>{_icon("arrow")}<h3>Decide where to start</h3><p>Compare access patterns and focus your next governance steps together.</p></div></div><div class="team-conversation">{invitation}<p class="offering-note">A separate Palma offering. This report does not create an aggregated view or send any results.</p></div></aside>'''


def _entry_facts(entry: dict) -> list[str]:
    """Facts from a finding's evidence line when no observation describes it."""
    value = entry.get("value")
    facts = []
    if isinstance(value, dict):
        if _count(value.get("sizeBytes")):
            facts.append(_fact(f"{value['sizeBytes']:,} bytes", "risk"))
        for key, label in (("limitBytes", "read limit"), ("reviewThresholdBytes", "review threshold")):
            if _count(value.get(key)):
                facts.append(_fact(f"{label} {value[key]:,} bytes"))
        for key in ("issueKind", "reason"):
            if isinstance(value.get(key), str) and value[key]:
                facts.append(_fact(_label(value[key])))
        if "value" in value:
            facts.insert(0, _setting_fact(entry.get("key", "setting"), value["value"]))
    elif value is not None:
        facts.append(_setting_fact(entry.get("key", "setting"), value))
    return facts


def _evidence_row(observation: dict | None, entry: dict | None, share: bool) -> str:
    if observation:
        facts = _facts(observation)
        if entry and observation.get("kind") == "setting" and not any("fact-setting" in fact for fact in facts):
            facts = _entry_facts(entry)[:1] + facts
        identity = _observation_identity(observation)
        client = _client_identity(observation["client"]) if observation.get("client") else ""
        return f'<li class="evidence-row"><div class="evidence-identity">{identity}{client}</div><div class="fact-list">{_state_chip(observation)}{"".join(facts)}</div><div class="evidence-where">{_where(observation, share, list_places=False)}</div></li>'
    location = entry.get("location", "Location not recorded")
    return f'<li class="evidence-row"><div class="evidence-identity"><strong>{_e(_label(entry.get("key", "Evidence")))}</strong></div><div class="fact-list">{"".join(_entry_facts(entry))}</div><div class="evidence-where"><code class="inventory-path">{_e(_share_location(location) if share else location)}</code></div></li>'


def _evidence(finding: dict, observations: dict[str, dict], share: bool) -> str:
    evidence = _records(finding.get("evidence"))
    identities = [_text(value) for value in finding.get("observationIds", [])] if isinstance(finding.get("observationIds"), list) else []
    rows, used = [], set()
    unused_by_source = {}
    for position, item in enumerate(evidence):
        unused_by_source.setdefault(_text(item.get("sourceId")), []).append(position)
    for index, identity in enumerate(identities):
        observation = observations.get(identity)
        if observation is None:
            continue
        # The evidence line in the same position, else the next unused line for the same source.
        position = index if index < len(evidence) and index not in used and evidence[index].get("sourceId") == observation.get("sourceId") else None
        candidates = unused_by_source.get(_text(observation.get("sourceId")), [])
        while position is None and candidates:
            candidate = candidates.pop(0)
            position = None if candidate in used else candidate
        if position is not None:
            used.add(position)
        rows.append(_evidence_row(observation, evidence[position] if position is not None else None, share))
    rows.extend(_evidence_row(None, entry, share) for position, entry in enumerate(evidence) if position not in used)
    shown = "".join(rows[:_EVIDENCE_VISIBLE])
    rest = rows[_EVIDENCE_VISIBLE:_EVIDENCE_LIMIT]
    shown_all = f"Show all {len(rows):,}" if len(rows) <= _EVIDENCE_LIMIT else f"Show {_EVIDENCE_LIMIT:,} of {len(rows):,}"
    more = f'<details class="evidence-more"><summary>{shown_all}{_icon("chevron", "disclosure-icon")}</summary><ul class="evidence-list">{"".join(rest)}</ul></details>' if rest else ""
    if len(rows) > _EVIDENCE_LIMIT:
        more += f'<p class="muted evidence-omitted">{len(rows) - _EVIDENCE_LIMIT:,} more {"are not shown in this summary" if share else "are listed in snapshot.json"}.</p>'
    evidence_html = f'<ul class="evidence-list">{shown}</ul>{more}' if rows else '<p class="muted">No evidence lines were recorded for this finding.</p>'
    links = []
    for value in finding.get("references", []) if isinstance(finding.get("references"), list) else []:
        url = _safe_https(value) if isinstance(value, str) and value in _KNOWN_REFERENCES else None
        if url:
            host = urlsplit(url).hostname or "Reference"
            links.append(f'<a href="{_e(url)}" rel="noreferrer noopener" target="_blank">{_e(host)}{_icon("external")}<span class="sr-only"> (opens in a new tab)</span></a>')
    references = '<div class="reference-links"><span>Documentation</span>' + "".join(links) + '</div>' if links else ""
    confidence = _enum(finding.get("confidence"), ("high", "medium", "low"), "low")
    evidence_type = _enum(finding.get("evidenceType"), ("configuration", "inventory", "declared"), "inventory")
    declarations = finding.get("declarations")
    extent = f'<span>{declarations} {"declaration" if declarations == 1 else "declarations"}</span>' if type(declarations) is int and declarations > 0 else ""
    distinct = finding.get("distinct")
    if type(distinct) is int and distinct > 0:
        extent += f'<span>{distinct} distinct</span>'
    rating_reason = finding.get("ratingReason")
    rating = f'<div class="impact rating-reason"><h4>Priority rationale</h4><p>{_e(rating_reason)}</p></div>' if isinstance(rating_reason, str) and rating_reason else ""
    count = _plural(len(rows), "item", "items")
    return f'<details class="finding-evidence"><summary><span>Evidence</span><span class="evidence-count">{count}</span>{_icon("chevron", "disclosure-icon")}</summary><div class="evidence-content">{evidence_html}{rating}<div class="evidence-meta">{extent}<span>{confidence.capitalize()} confidence in the match</span><span>{evidence_type.capitalize()} evidence</span><span>Rule <code>{_e(finding.get("ruleId", "Not recorded"))}</code></span></div>{references}</div></details>'


def _findings_section(findings: list[tuple[str, dict]], counts: Counter, observations: dict[str, dict], share: bool) -> str:
    cards = []
    for anchor, finding in findings:
        severity = _enum(finding.get("severity"), _SEVERITIES, "info")
        client_labels = "".join(_client_identity(client) for client in _finding_clients(finding, observations))
        clients_html = f'<span class="finding-clients">{client_labels}</span>' if client_labels else ""
        impact = finding.get("impact")
        impact_html = f'<div class="finding-impact"><h4>Why it matters</h4><p>{_e(impact)}</p></div>' if isinstance(impact, str) and impact else ""
        cards.append(f'<article class="finding" id="{anchor}" data-severity="{severity}" aria-labelledby="{anchor}-title"><details class="finding-details"><summary><span class="finding-topline">{_badge(severity)}<span>{_e(_label(finding.get("category", "Configuration")))}</span>{clients_html}</span><h3 id="{anchor}-title">{_e(finding.get("title", "Review this observation"))}</h3>{_icon("chevron", "disclosure-icon")}</summary><div class="finding-body"><p class="finding-summary">{_e(finding.get("summary", "Review the available evidence for this configuration."))}</p>{impact_html}<div class="next-step">{_icon("arrow")}<div><h4>Next step</h4><p>{_e(finding.get("recommendation", "Review this configuration and confirm that its access is intentional."))}</p></div></div>{_evidence(finding, observations, share)}</div></details></article>')
    filters = '<button type="button" class="filter-button" data-filter="all" aria-pressed="true">All <span>' + str(len(findings)) + '</span></button>'
    for severity in _SEVERITIES:
        filters += f'<button type="button" class="filter-button" data-filter="{severity}" aria-pressed="false">{_SEVERITY_NAMES[severity]} <span>{counts[severity]}</span></button>'
    toolbar = f'<div class="findings-toolbar js-only"><div class="filters" role="group" aria-label="Filter findings by priority">{filters}</div><label class="search-field">{_icon("search")}<span class="sr-only">Search findings and evidence</span><input id="finding-search" type="search" placeholder="Search findings &amp; evidence" autocomplete="off" spellcheck="false"></label></div><div class="results-toolbar js-only"><p id="filter-status" role="status" aria-live="polite">Showing {len(findings)} of {len(findings)} findings</p><button type="button" class="text-button" id="expand-evidence">Expand visible evidence</button></div>' if findings else ""
    empty = '<div class="empty-state">' + _icon("info") + '<div><h3>No findings were recorded</h3><p>This is a result for the sources and rules available to this scan. Review coverage before drawing conclusions.</p><a class="inline-link" href="#coverage">See scan coverage ' + _icon("arrow") + '</a></div></div>'
    return f'<section class="report-section" id="findings" aria-labelledby="findings-title"><div class="section-heading"><div><p class="eyebrow">01 / Findings</p><h2 id="findings-title">Your findings</h2><p>The configuration, the potential impact, and what you can do next.</p></div><span class="section-count">{len(findings):02d}</span></div>{toolbar}<div id="findings-list">{"".join(cards) if cards else empty}</div><div id="no-results" class="empty-state" hidden><div><h3>No findings match this view</h3><p>Try another priority or a different search term.</p><button class="text-button" type="button" id="clear-filters">Clear filters</button></div></div><p class="section-note">Severity describes potential impact. Confidence describes the evidence match. Neither establishes that a capability was used or that a compromise occurred.</p></section>'


def _declaration_count(items: list[dict]) -> int:
    return sum(max(1, _count(item.get("details", {}).get("copyCount")))
               if isinstance(item.get("details"), dict) else 1 for item in items)


def _named_groups(observations: list[dict], kind: str, share: bool) -> list[list[dict]]:
    groups = {}
    for item in observations:
        if item.get("kind") == kind:
            key = item.get("_reportNameGroup") if share else _text(item.get("name"))
            groups.setdefault(key, []).append(item)
    return sorted(groups.values(), key=lambda items: _text(items[0].get("name")).casefold())


def _inventory_finding_link(items: list[dict], linked: dict) -> str:
    matches = dict(pair for item in items for pair in linked.get(_text(item.get("id", "")), []))
    if not matches:
        return ""
    anchor, severity = min(matches.items(), key=lambda pair: _SEVERITIES.index(pair[1]))
    return f'<a class="fact fact-finding fact-{severity}" href="#{anchor}">{_plural(len(matches), "finding", "findings")}</a>'


def _inventory_group_row(items: list[dict], linked: dict, share: bool, *, extensions: bool = False) -> str:
    """A name is an overview key, never evidence that configurations or trust match."""
    first = items[0]
    count = _declaration_count(items)
    header = first
    if first.get("kind") == "mcp":
        providers = {_provider_details(item.get("details") if isinstance(item.get("details"), dict) else {}) for item in items}
        if len(providers) > 1:
            header = {**first, "details": {}}  # One provider must not stand in for other variants.
    name = '<strong>AI-related browser extensions</strong>' if extensions else _observation_identity(header)
    label = "Browser extensions" if extensions else _KIND_LABELS.get(first.get("kind"), "Observation")
    clients = sorted({_text(item.get("client") or "unknown") for item in items}, key=lambda value: _client_details(value)[0].casefold())
    badges = "".join(f'<a class="inventory-client-tag" href="#{_client_anchor(client)}">{_client_identity(client)}</a>' for client in clients)
    entries = []
    for index, item in enumerate(items, 1):
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        identity = f'<strong>Extension record {index}</strong>' if extensions else _client_identity(item.get("client"))
        if item.get("kind") == "mcp":
            identity += _observation_identity(item)
        entries.append(f'<li class="declaration-row">{identity}<div class="fact-list">{_state_chip(item)}{"".join(_facts(item))}{_inventory_finding_link([item], linked)}</div><div class="inventory-where">{_observation_context(details)}{_where(item, share)}</div></li>')
    count_label = _plural(count, "extension record", "extension records") if extensions else _plural(count, "declaration", "declarations")
    return f'<li class="inventory-row"><div class="inventory-item-name">{name}<span class="inventory-kind-label">{label}</span></div><div class="fact-list inventory-client-tags">{badges}{_inventory_finding_link(items, linked)}</div><details class="inventory-declarations"><summary>{count_label}{_icon("chevron", "disclosure-icon")}</summary><ul>{"".join(entries)}</ul></details></li>'


def _inventory(observations: list[dict], findings: list[tuple[str, dict]], share: bool) -> str:
    """Server and skill names first, with configuration variants available underneath."""
    linked = {}
    for anchor, finding in findings:
        for identity in finding.get("observationIds", []) if isinstance(finding.get("observationIds"), list) else []:
            linked.setdefault(_text(identity), []).append((anchor, _enum(finding.get("severity"), _SEVERITIES, "info")))
    groups_by_client = {}
    for item in observations:
        groups_by_client.setdefault(_text(item.get("client") or "unknown"), []).append(item)
    groups, total = [], 0
    for kind, title, icon in (("mcp", "MCP servers", "connector"), ("skill", "Skills", "book")):
        named = _named_groups(observations, kind, share)
        if not named:
            continue
        rows = "".join(_inventory_group_row(items, linked, share) for items in named)
        total += len(named)
        count = _declaration_count([item for items in named for item in items])
        breakdown = _plural(len(named), "distinct name", "distinct names") + " · " + _plural(count, "declaration", "declarations")
        groups.append(f'<details class="inventory-group" id="inventory-{kind}"><summary><span class="inventory-group-icon">{_brand_icon(icon)}</span><span class="inventory-kind"><strong>{title}</strong><span>{breakdown}</span></span><span class="inventory-count" data-total="{len(named)}">{len(named)}</span>{_icon("chevron", "disclosure-icon")}</summary><ul class="inventory-rows">{rows}</ul></details>')
    for client in sorted(groups_by_client, key=lambda value: (_client_details(value)[0].casefold(), value)):
        items = groups_by_client[client]
        name, icon = _client_details(client)
        client_rows = [item for item in items if item.get("kind") == "client"]
        members = sorted((item for item in items if item.get("kind") != "client"), key=lambda record: (
            _KIND_ORDER.index(record.get("kind")) if record.get("kind") in _KIND_ORDER else len(_KIND_ORDER),
            _text(record.get("name", "")).casefold(), _text(record.get("location", "")), _text(record.get("id", ""))))
        breakdown = " · ".join(_plural(sum(item.get("kind") == kind for item in members), *_KIND_PLURALS[kind]) for kind in _KIND_ORDER if any(item.get("kind") == kind for item in members))
        # Older or partial snapshots can hold several rows for one client; show their facts once.
        client_facts = "".join(dict.fromkeys(fact for row in client_rows for fact in _facts(row)))
        related = {anchor for item in items for anchor, _ in linked.get(_text(item.get("id", "")), [])}
        findings_note = f'<span class="inventory-findings">{_plural(len(related), "finding", "findings")}</span>' if related else ""
        rows = []
        extension_items = [item for item in members if item.get("kind") == "plugin" and isinstance(item.get("details"), dict) and item["details"].get("aiRelatedNameHint") is True]
        extension_ids = {id(item) for item in extension_items}
        if extension_items:
            rows.append(_inventory_group_row(extension_items, linked, share, extensions=True))
        for item in members:
            if item.get("kind") in ("mcp", "skill") or id(item) in extension_ids:
                continue
            matches = linked.get(_text(item.get("id", "")), [])
            finding_link = ""
            if matches:
                worst = min(matches, key=lambda pair: _SEVERITIES.index(pair[1]))
                finding_link = f'<a class="fact fact-finding fact-{worst[1]}" href="#{worst[0]}">{_plural(len(matches), "finding", "findings")}</a>'
            details = item.get("details") if isinstance(item.get("details"), dict) else {}
            kind_label = _KIND_LABELS.get(_text(item.get("kind")), "Observation")
            rows.append(f'<li class="inventory-row"><div class="inventory-item-name">{_observation_identity(item)}<span class="inventory-kind-label">{_e(kind_label)}</span></div><div class="fact-list">{_state_chip(item)}{"".join(_facts(item))}{finding_link}</div><div class="inventory-where">{_observation_context(details)}{_where(item, share)}</div></li>')
        total += len(rows)
        named_links = " · ".join(f'<a href="#inventory-{kind}">{title}</a>' for kind, title in (("mcp", "MCP servers"), ("skill", "Skills")) if any(item.get("kind") == kind for item in members))
        body = f'<p class="inventory-empty">{named_links} are listed by name above, with this client tagged on each row.</p>' if named_links else ""
        body += f'<ul class="inventory-rows">{"".join(rows)}</ul>' if rows else '<p class="inventory-empty">No additional inventory recorded for this client.</p>'
        if not rows:
            body += '<div class="inventory-client-location">' + "".join(_where(row, share) for row in client_rows) + '</div>'
        groups.append(f'<details class="inventory-group" id="{_client_anchor(client)}"><summary><span class="inventory-group-icon">{_brand_icon(icon)}</span><span class="inventory-kind"><strong>{_e(name)}</strong><span>{breakdown or "Installation and configuration"}</span></span><span class="fact-list inventory-client-facts">{client_facts}{findings_note}</span><span class="inventory-count" data-total="{len(rows)}">{len(rows)}</span>{_icon("chevron", "disclosure-icon")}</summary>{body}</details>')
    toolbar = f'<div class="inventory-toolbar js-only"><label class="search-field">{_icon("search")}<span class="sr-only">Search inventory by name, client, or location</span><input id="inventory-search" type="search" placeholder="Find a skill, connector, client, or location" autocomplete="off" spellcheck="false"></label><p id="inventory-search-status" role="status" aria-live="polite">{total} items</p><button class="text-button" type="button" id="clear-inventory-search" hidden>Clear search</button></div>' if observations else ""
    empty = '<div class="empty-state"><p>No inventory observations were recorded.</p></div>'
    no_matches = '<div class="empty-state" id="inventory-no-results" hidden><p>No inventory matches this search. Try a tool name, client, or location.</p></div>'
    return f'<section class="report-section" id="inventory" aria-labelledby="inventory-title"><div class="section-heading"><div><p class="eyebrow">02 / Inventory</p><h2 id="inventory-title">What’s in your AI environment</h2><p>MCP servers and skills are grouped by their declared name and tagged with their clients. Open a name to compare its declarations; matching names can have different configurations or contents. Other inventory is grouped by client.</p></div><span class="section-count">{total:02d}</span></div>{toolbar}<div class="inventory-list">{"".join(groups) if groups else empty}</div>{no_matches}</section>'


def _discovery_summary(snapshot: dict) -> str:
    scope = snapshot.get("scope") if isinstance(snapshot.get("scope"), dict) else {}
    discovery = scope.get("discovery") if isinstance(scope.get("discovery"), dict) else {}
    if not discovery:
        return ""
    values = []
    for key, label in (("localVolumes", "local volumes"), ("projectsDiscovered", "AI projects"),
                       ("directoriesVisited", "directories searched")):
        number = discovery.get(key)
        if isinstance(number, int) and not isinstance(number, bool) and number >= 0:
            values.append(f'<div><dt>{label}</dt><dd>{number:,}</dd></div>')
    excluded = discovery.get("excludedDirectories")
    note = ('<p class="muted discovery-note">Folders that belong to other accounts, temporary folders and this scanner’s own folder were not searched for projects. To include a project there, scan it with <code>--workspace</code>.</p>'
            if type(excluded) is int and excluded > 0 else "")
    return '<dl class="discovery-summary" aria-label="Machine discovery coverage">' + "".join(values) + '</dl>' + note


# Causes of incomplete coverage, in reading order, with what the person can do about each.
_CAUSES = (
    ("denied", "Permission denied", "Grant read access to these locations, or run the scan from an account that can read them."),
    ("interpret", "Could not be interpreted", "These files are malformed or use an unsupported format. Fix or remove them, then scan again."),
    ("limit", "Over a size or scan limit", "Very large files and folders are skipped so the scan stays bounded."),
    ("links", "Links not followed", "Symbolic links and junctions are never followed, so their targets were not read."),
    ("scope", "Outside the scan scope", "These locations are outside the scanned account and folders."),
    ("failed", "Could not be processed", "An unexpected problem stopped these sources; everything else was still collected."),
    ("other", "Other problems", "Each source lists the recorded reason."),
)


def _reasons(source: dict) -> list[str]:
    reasons = source.get("reasons")
    reasons = [reason for reason in reasons if isinstance(reason, str) and reason] if isinstance(reasons, list) else []
    if isinstance(source.get("reason"), str) and source["reason"]:
        reasons.append(source["reason"])
    return list(dict.fromkeys(reasons))


def _cause(source: dict) -> str:
    text = " ".join(_reasons(source)).lower()
    if "permission" in text:
        return "denied"
    if any(word in text for word in ("adapter_error", "interpreted safely", "stopped unexpectedly")):
        return "failed"
    if any(word in text for word in ("size_limit", "manifest_limit", "count_limit", "time_limit", "budget")):
        return "limit"
    if any(word in text for word in ("symlink", "symbolic link", "reparse")):
        return "links"
    if any(word in text for word in ("outside_scope", "outside selected scope", "not in selected scope")):
        return "scope"
    if any(word in text for word in ("parse", "invalid", "unsupported", "unknown_schema", "shape", "malformed", "duplicate", "could not be interpreted")):
        return "interpret"
    return "other"


def _source_diagnostics(source: dict) -> str:
    """Display only fixed diagnostic enums and bounded native codes in local coverage."""
    metadata = source.get("metadata") if isinstance(source.get("metadata"), dict) else {}
    allowed = {
        "stage": {"boundary-check", "directory-listing", "directory-open", "directory-identity", "entry-metadata", "directory-metadata", "metadata-read", "profile-access", "process-command", "system-directory", "account-filter", "process-inventory", "process-output"},
        "kind": {"unsupported-value", "timeout", "permission-denied", "os-error", "read-gap", "command-exit", "output-limit"},
        "reason": {"outside_scope", "symlink", "permission_denied", "io_error", "not_found", "parse_error", "unknown_schema", "size_limit", "count_limit", "time_limit"},
    }
    rows = []
    for item in _records(metadata.get("errorDiagnostics"))[:16]:
        parts = []
        for key, choices in allowed.items():
            value = item.get(key)
            if isinstance(value, str) and value in choices:
                parts.append(key + ": " + value)
        for key in ("errno", "windowsError", "exitStatus"):
            value = item.get(key)
            if type(value) is int and -(2 ** 31) <= value < 2 ** 32:
                parts.append(key + ": " + str(value))
        if parts:
            rows.append('<span class="source-reason">' + _e(" · ".join(parts)) + '</span>')
    return "".join(rows)


def _coverage(sources: list[dict], snapshot: dict, share: bool) -> str:
    """How much was read, and every source that was not, grouped by cause."""
    coverage = snapshot.get("coverage") if isinstance(snapshot.get("coverage"), dict) else {}
    inspected = coverage.get("sourcesInspected")
    inspected = inspected if type(inspected) is int and inspected >= 0 else sum(item.get("status") == "collected" for item in sources)
    problems = [item for item in sources if item.get("status") in {"error", "skipped"}]
    if not sources and not inspected:
        panel = '<p class="muted">No source records were included.</p>'
    else:
        causes = []
        for key, label, advice in _CAUSES:
            group = [item for item in problems if _cause(item) == key]
            if not group:
                continue
            rows = ""
            if not share:
                for source in group[:500]:
                    reasons = "".join('<span class="source-reason">' + _e(_label(reason) if re.fullmatch(r"[a-z]+(?:_[a-z]+)+", reason) else reason) + '</span>' for reason in _reasons(source))
                    rows += f'<li><span class="coverage-client">{_e(_client_details(source.get("client", "unknown"))[0])}</span><code class="inventory-path">{_e(source.get("location", "Location not recorded"))}</code>{reasons}{_source_diagnostics(source)}</li>'
                if len(group) > 500:
                    rows += f'<li class="muted">{len(group) - 500:,} more are listed in snapshot.json.</li>'
            causes.append(f'<details class="coverage-cause"><summary><strong>{len(group):,}</strong><span>{label}</span>{_icon("chevron", "disclosure-icon")}</summary><div class="coverage-cause-body"><p>{advice}</p>{"<ul>" + rows + "</ul>" if rows else ""}</div></details>')
        status = (f'<p class="coverage-summary">{_plural(len(problems), "source", "sources")} could not be fully read. Each is listed below by cause; everything else was collected.</p>'
                  if problems else '<p class="coverage-summary">Every inspected source was read.</p>')
        panel = f'<div class="coverage-title"><strong>{inspected:,}</strong><p>sources inspected<span>Configuration files, AI folders, installations and system inventories that were read.</span></p></div>{status}<div class="coverage-causes">{"".join(causes)}</div>'
    return f'<section class="report-section" id="coverage" aria-labelledby="coverage-title"><div class="section-heading"><div><p class="eyebrow">03 / Coverage</p><h2 id="coverage-title">Collection coverage</h2><p>A record of what was inspected.</p></div></div>{_discovery_summary(snapshot)}<div class="coverage-panel">{panel}</div></section>'


_JS = r"""
(() => {
  'use strict';
  document.documentElement.classList.add('js');
  const cards = Array.from(document.querySelectorAll('.finding'));
  const filters = Array.from(document.querySelectorAll('[data-filter]'));
  const search = document.getElementById('finding-search');
  const status = document.getElementById('filter-status');
  const noResults = document.getElementById('no-results');
  const expand = document.getElementById('expand-evidence');
  let selected = 'all';
  const syncExpansion = () => {
    if (!expand) return;
    const visible = cards.filter(card => !card.hidden);
    const anyClosed = visible.some(card => !card.querySelector('.finding-evidence').open);
    expand.disabled = visible.length === 0;
    expand.textContent = visible.length > 0 && !anyClosed ? 'Collapse visible evidence' : 'Expand visible evidence';
  };
  const update = () => {
    const query = search ? search.value.trim().toLocaleLowerCase() : '';
    let visible = 0;
    cards.forEach(card => {
      const matches = (selected === 'all' || card.dataset.severity === selected) && (!query || card.textContent.toLocaleLowerCase().includes(query));
      card.hidden = !matches;
      if (matches) visible += 1;
    });
    filters.forEach(button => button.setAttribute('aria-pressed', String(button.dataset.filter === selected)));
    if (status) status.textContent = `Showing ${visible} of ${cards.length} findings`;
    if (noResults) noResults.hidden = visible > 0 || cards.length === 0;
    syncExpansion();
  };
  filters.forEach(button => button.addEventListener('click', () => {
    selected = button.dataset.filter;
    update();
  }));
  document.querySelectorAll('[data-priority]').forEach(link => link.addEventListener('click', () => {
    selected = link.dataset.priority;
    if (search) search.value = '';
    update();
    document.getElementById('findings').open = true;
  }));
  if (search) search.addEventListener('input', update);
  const clear = document.getElementById('clear-filters');
  if (clear) clear.addEventListener('click', () => {
    selected = 'all';
    if (search) search.value = '';
    update();
    if (search) search.focus();
  });
  if (expand) expand.addEventListener('click', () => {
    const visible = cards.filter(card => !card.hidden).map(card => card.querySelector('.finding-evidence'));
    const shouldOpen = visible.some(detail => !detail.open);
    visible.forEach(detail => {
      detail.open = shouldOpen;
      if (shouldOpen) detail.closest('.finding-details').open = true;
    });
    syncExpansion();
  });
  cards.forEach(card => card.querySelector('.finding-evidence').addEventListener('toggle', syncExpansion));
  const inventoryGroups = Array.from(document.querySelectorAll('.inventory-group'));
  const inventoryRows = Array.from(document.querySelectorAll('.inventory-row'));
  const inventoryGroupText = new Map(inventoryGroups.map(group => [group,
    Array.from(group.querySelectorAll('.inventory-kind strong, .inventory-client-facts, .inventory-client-location'))
      .map(item => item.textContent).join(' ').toLocaleLowerCase()
  ]));
  // A row matches its client's name too, so "claude code" finds that client's items.
  const inventoryText = new Map(inventoryRows.map(row => {
    const client = row.closest('.inventory-group').querySelector('.inventory-kind strong');
    return [row, `${client ? client.textContent : ''} ${row.textContent}`.toLocaleLowerCase()];
  }));
  const inventorySearch = document.getElementById('inventory-search');
  const inventoryStatus = document.getElementById('inventory-search-status');
  const inventoryEmpty = document.getElementById('inventory-no-results');
  const inventoryClear = document.getElementById('clear-inventory-search');
  let inventoryQuery = '';
  let inventoryOpenState = [];
  const updateInventory = () => {
    const query = inventorySearch ? inventorySearch.value.trim().toLocaleLowerCase() : '';
    if (query && !inventoryQuery) inventoryOpenState = inventoryGroups.map(group => [group, group.open]);
    let visible = 0;
    inventoryRows.forEach(row => {
      row.hidden = Boolean(query) && !inventoryText.get(row).includes(query);
      if (!row.hidden) visible += 1;
    });
    inventoryGroups.forEach(group => {
      const matching = Array.from(group.querySelectorAll('.inventory-row')).filter(row => !row.hidden).length;
      group.hidden = Boolean(query) && matching === 0 && !inventoryGroupText.get(group).includes(query);
      if (query && !group.hidden) group.open = true;
      const count = group.querySelector('.inventory-count');
      count.textContent = query ? `${matching} / ${count.dataset.total}` : count.dataset.total;
    });
    if (!query && inventoryQuery) inventoryOpenState.forEach(([group, open]) => { group.open = open; });
    inventoryQuery = query;
    if (inventoryStatus) inventoryStatus.textContent = query ? `${visible} of ${inventoryRows.length} items` : `${inventoryRows.length} items`;
    if (inventoryEmpty) inventoryEmpty.hidden = !query || inventoryGroups.some(group => !group.hidden);
    if (inventoryClear) inventoryClear.hidden = !query;
  };
  if (inventorySearch) inventorySearch.addEventListener('input', updateInventory);
  if (inventoryClear) inventoryClear.addEventListener('click', () => {
    inventorySearch.value = '';
    updateInventory();
    inventorySearch.focus();
  });
  const revealTarget = () => {
    const id = window.location.hash.slice(1);
    const target = id ? document.getElementById(id) : null;
    if (!target) return;
    if (target.closest('.inventory-group') && inventoryQuery) {
      inventorySearch.value = '';
      updateInventory();
    }
    if (target.tagName === 'DETAILS') target.open = true;
    const card = target.closest('.finding');
    if (card) card.querySelector('.finding-details').open = true;
    if (card && card.hidden) {
      selected = 'all';
      if (search) search.value = '';
      update();
    }
    let parent = target.parentElement;
    while (parent) {
      if (parent.tagName === 'DETAILS') parent.open = true;
      parent = parent.parentElement;
    }
    target.scrollIntoView({block: 'start'});
  };
  // Clicking an already selected anchor must also reopen a closed disclosure.
  document.querySelectorAll('a[href^="#"]').forEach(link => link.addEventListener('click', () => {
    if (link.hash === window.location.hash) revealTarget();
  }));
  window.addEventListener('hashchange', revealTarget);
  if (window.location.hash) revealTarget();
  const printButton = document.getElementById('print-report');
  if (printButton) printButton.addEventListener('click', () => window.print());
  let printState = [];
  let printCounts = [];
  window.addEventListener('beforeprint', () => {
    printState = Array.from(document.querySelectorAll('details')).map(detail => [detail, detail.open]);
    printState.forEach(([detail]) => { detail.open = true; });
    printCounts = Array.from(document.querySelectorAll('.inventory-count')).map(count => [count, count.textContent]);
    printCounts.forEach(([count]) => { count.textContent = count.dataset.total; });
  });
  window.addEventListener('afterprint', () => {
    printState.forEach(([detail, open]) => { detail.open = open; });
    printState = [];
    printCounts.forEach(([count, value]) => { count.textContent = value; });
    printCounts = [];
  });
})();
"""


def render_report(snapshot: dict, summary: dict, *, booking_url: str | None = None, share: bool = False) -> str:
    """Return a complete offline HTML report without reading files or using a network.

    ``snapshot`` must contain sanitized collection results. The renderer escapes all
    data again for its HTML context, rejects active/non-HTTPS destinations, and emits
    a hash-based Content Security Policy. It does not evaluate configuration values.
    The booking link is navigation initiated by the reader, never a request
    made by report generation or loading. Identical inputs produce identical bytes.
    ``share`` renders the shareable summary from ``_shareable``: locations keep only their AI
    configuration folder and file name, and coverage lists counts instead of source locations.
    """
    if share:
        snapshot = _shareable(snapshot)
    sources = _records(snapshot.get("sources"))
    observations = _records(snapshot.get("observations"))
    findings_data = _records(snapshot.get("findings"))
    findings_data = sorted(findings_data, key=lambda item: (_SEVERITIES.index(_enum(item.get("severity"), _SEVERITIES, "info")), _text(item.get("title", "")).casefold(), _text(item.get("id", ""))))
    # Finding ids derive from local paths, so the shareable summary numbers its anchors instead.
    findings = [(f"finding-{index + 1}" if share else _anchor("finding", index, item.get("id", "")), item) for index, item in enumerate(findings_data)]
    severity_counts = Counter(_enum(item.get("severity"), _SEVERITIES, "info") for item in findings_data)
    observation_map = {_text(item.get("id", "")): item for item in observations}
    coverage_record = snapshot.get("coverage") if isinstance(snapshot.get("coverage"), dict) else {}
    inspected = coverage_record.get("sourcesInspected")
    collected = inspected if type(inspected) is int and inspected >= 0 else sum(item.get("status") == "collected" for item in sources)
    scope = snapshot.get("scope") if isinstance(snapshot.get("scope"), dict) else {}
    scope_type = _text(scope.get("type", "Scope not recorded"))
    scope_name = {"machine": "Your account on this computer", "copied-home": "Copied home", "current-user": "Current user", "user": "Current user", "endpoint": "Current user", "declared": "Current session"}.get(scope_type, _label(scope_type))
    platform_name = {"macos": "macOS", "darwin": "macOS", "windows": "Windows", "linux": "Linux"}.get(_text(scope.get("platform")))
    if platform_name:
        scope_name += " · " + platform_name
    environment = scope.get("environment") if isinstance(scope.get("environment"), dict) else {}
    if environment.get("containerIndicators"):
        scope_name += " · Container context"
    if environment.get("subsystemIndicators"):
        scope_name += " · Subsystem context"
    if environment.get("sandboxIndicators"):
        scope_name += " · Restricted process context"
    workspace_count = scope.get("workspaceCount", 0)
    if isinstance(workspace_count, int) and not isinstance(workspace_count, bool) and workspace_count > 0:
        scope_name += f' · {workspace_count} {"project" if workspace_count == 1 else "projects"}'
    declared = snapshot.get("mode") == "declared"
    banner = ""
    if share:
        banner = '<div class="scope-banner" role="note">' + _icon("lock") + '<strong>Shareable summary: file locations keep only their AI configuration folder and file name, without project or folder names. Tool, connector and skill names are included; names that are paths or web addresses are withheld.</strong></div>'
    if isinstance(scope.get("label"), str) and scope["label"].strip():
        banner += '<div class="scope-banner" role="note">' + _icon("info") + '<strong>' + _e(scope["label"]) + '</strong></div>'
    if declared:
        banner += '<div class="mode-banner" role="note">' + _icon("info") + '<div><strong>Declared inventory — endpoint not scanned</strong>This report reflects what an AI agent declared about its session. Configuration and local files have not been independently verified.</div></div>'
    client_count = len({_client_details(item.get("client", ""))[0].casefold() for item in observations if item.get("kind") == "client" and item.get("client") not in {"shared", "machine", "browser-extensions", "unknown"}})
    mcp_count = len(_named_groups(observations, "mcp", share))
    skill_count = len(_named_groups(observations, "skill", share))
    graph = inventory_graph(observations, share=share)
    gaps = sum(item.get("status") in {"error", "skipped"} for item in sources)
    coverage_status = "Declared inventory" if declared else ("Partial coverage" if gaps or snapshot.get("status") == "partial" else "Coverage recorded" if sources or collected else "No source records")
    findings_panel = _disclosure("findings", "Findings", f"{len(findings)} findings", _findings_section(findings, severity_counts, observation_map, share).replace('id="findings"', 'id="findings-content"', 1), "search")
    inventory_panel = _disclosure("inventory", "Inventory", f"{mcp_count} MCP · {skill_count} skills", _inventory(observations, findings, share).replace('id="inventory"', 'id="inventory-content"', 1), "folder")
    coverage_panel = _disclosure("coverage", "Collection coverage", f"{collected:,} inspected · {_plural(gaps, 'gap', 'gaps')}", _coverage(sources, snapshot, share).replace('id="coverage"', 'id="coverage-content"', 1), "info")
    regulation_panel = _disclosure("eu-ai-regulation", "EU AI Act readiness", "4 review areas", render_regulation_section(findings, observations, declared).replace('id="eu-ai-regulation"', 'id="eu-ai-regulation-content"', 1), "lock")
    collector = snapshot.get("collector") if isinstance(snapshot.get("collector"), dict) else {}
    try:
        booking = _safe_https(_booking_link(booking_url))
    except ValueError:
        booking = None
    booking_link = f'<a class="booking-link" href="{_e(booking)}" rel="noreferrer noopener" target="_blank">Talk to Palma{_icon("external")}<span class="sr-only"> (opens in a new tab)</span></a>' if booking else ""
    script_hash = base64.b64encode(hashlib.sha256(_JS.encode("utf-8")).digest()).decode("ascii")
    style_hash = base64.b64encode(hashlib.sha256(_CSS.encode("utf-8")).digest()).decode("ascii")
    policy = f"default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'sha256-{style_hash}'; img-src data:; font-src data:; connect-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'; manifest-src 'none'"
    title = "Palma · Shareable AI access summary" if share else "Palma · Personal AI access scan"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="{_e(policy)}"><meta name="referrer" content="no-referrer"><meta name="color-scheme" content="light"><title>{title}</title><style>{_CSS}</style></head>
<body><a class="skip-link" href="#main">Skip to report</a>{_brand_sprite(observations)}<header class="site-header"><div class="shell header-inner"><a class="brand" href="#main" aria-label="Palma, back to report overview"><img src="{LOGO_DATA_URI}" width="152" height="38" alt="Palma AI"><span class="brand-label">Personal AI<br>access scan</span></a><nav class="main-nav" aria-label="Report sections"><a href="#main">Overview</a><a class="regulation-nav" href="#eu-ai-regulation">EU AI Act</a><a href="#findings">Findings</a><a href="#inventory">Inventory</a><a href="#coverage">Coverage</a><button class="print-button js-only" type="button" id="print-report" aria-label="Print report">{_icon("print")}<span>Print report</span></button></nav></div></header>
<main class="shell" id="main"><div class="report-title"><div><p class="eyebrow">Your personal AI access report</p><h1>Your AI environment, <span class="title-accent">at a glance.</span></h1><p class="report-subtitle">See what is configured. Explore the evidence when you need it.</p></div><div class="report-meta"><span class="meta-label">Scan details</span><span>{_e(_date(snapshot.get("completedAt")))}</span><span>{_e(scope_name)}</span></div></div>{banner}
{_overview(findings, severity_counts, observation_map, graph, client_count, coverage_status)}
{_client_map(graph, observations)}
{findings_panel}
{inventory_panel}
{regulation_panel}
{coverage_panel}
{_team_teaser(booking_link)}
<footer class="report-footer"><div><img src="{LOGO_DATA_URI}" width="112" height="28" alt="Palma AI"><p class="footer-privacy">Built for a clearer view of your AI access.</p></div><div class="footer-right"><p>{_e(collector.get("name", "Palma scan"))} · {_e(collector.get("version", "version not recorded"))}</p><p>Rules {_e(collector.get("rulesVersion", "not recorded"))} · Schema {_e(snapshot.get("schemaVersion", "not recorded"))}</p></div></footer>{_artwork_credits()}<div class="local-note local-note-end">{_icon("lock")}<div><strong>Local by design.</strong> <span>This report makes no network requests. You control any sharing.</span></div></div></main><script>{_JS}</script></body></html>"""
