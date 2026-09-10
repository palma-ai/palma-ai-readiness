"""Verified package identities, not a generic installed-software catalog."""
import re

CLAUDE_FAMILY = "Claude_pzs8sxrjxfjjc"
CODEX_FAMILY = "OpenAI.Codex_2p2nqsd0c76g0"
PRODUCTS = {
    CLAUDE_FAMILY: {"family": "claude-desktop", "name": "Claude", "app_id": "Claude",
                    "binaries": {"claude.exe"},
                    "publisher": ('CN="Anthropic, PBC", O="Anthropic, PBC", L=San Francisco, S=California, C=US, '
                                  'SERIALNUMBER=4860621, OID.2.5.4.15=Private Organization, '
                                  'OID.1.3.6.1.4.1.311.60.2.1.2=Delaware, OID.1.3.6.1.4.1.311.60.2.1.3=US')},
    CODEX_FAMILY: {"family": "codex", "name": "OpenAI.Codex", "app_id": "App",
                   "binaries": {"codex.exe", "chatgpt.exe"},
                   "publisher": "CN=50BDFD77-8903-4850-9FFE-6E8522F64D5B"},
}
FULL_NAMES = {family: re.compile(re.escape(rule["name"]) +
              r"_([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)_(?:x64|arm64)__" + re.escape(family.rsplit("_", 1)[1]) + r"\Z")
              for family, rule in PRODUCTS.items()}
