"""Numeric metadata must not turn a bounded document into unbounded work."""
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from palma_scan.engine.parsing import parse_document


class YamlNumericResourceTests(unittest.TestCase):
    def assert_numeric_document_rejected(self, scalar, format_name="yaml"):
        raw = ("value: " + scalar + "\n").encode()
        if format_name == "markdown":
            raw = b"---\n" + raw + b"---\nFictional skill body.\n"
        self.assertLess(len(raw), 2 * 1024 * 1024)
        # The unfixed sexagesimal constructor can hang. Keep it out of the
        # unittest process, and let subprocess.run kill and reap it on timeout.
        code = """
import sys
sys.path.insert(0, sys.argv[1])
from palma_scan.engine.parsing import ParseError, parse_document
try:
    parse_document(sys.stdin.buffer.read(), sys.argv[2])
except ParseError:
    print("parse_error")
else:
    print("accepted")
"""
        try:
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", code, str(SCRIPTS), format_name],
                input=raw, capture_output=True, timeout=10,
            )
        except subprocess.TimeoutExpired:
            self.fail("numeric document exceeded the subprocess timeout")
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertEqual(result.stdout, b"parse_error\n")

    def test_sexagesimal_integer_cannot_stall_yaml_or_frontmatter_parsing(self):
        for format_name in ("yaml", "markdown"):
            with self.subTest(format_name=format_name):
                self.assert_numeric_document_rejected("1" + ":0" * 500_000, format_name)

    def test_numeric_tags_reject_excessive_work_across_numeric_spellings(self):
        scalars = {
            "decimal": "1" + "0" * 2_000,
            "binary": "0b" + "1" * 20_000,
            "octal": "0" + "7" * 20_000,
            "hexadecimal": "0x" + "f" * 20_000,
            "float": "1." + "0" * 20_000,
            "explicit leading underscores": "!!int " + "_" * 20_000 + "1:00",
            "explicit signed integer": "!!int -0x" + "f" * 20_000,
            "explicit float underscores": "!!float " + "_" * 20_000 + "1.0",
            "scalar mapping form": "!!int {=: '1" + ":0" * 2_000 + "'}",
        }
        for label, scalar in scalars.items():
            with self.subTest(label=label):
                self.assert_numeric_document_rejected(scalar)

    def test_normal_numeric_forms_keep_their_values(self):
        raw = b"""decimal: 42
negative: -42
positive: +42
grouped: 1_000_000
binary: 0b101010
octal: 052
hexadecimal: 0x2a
sexagesimal: 1:02:03
fraction: 1:02:03.5
exponent: 1.25e+2
explicit_integer: !!int _42
explicit_float: !!float _1.5
scalar_mapping: !!int {=: '42'}
enabled: true
optional: null
name: example
"""
        self.assertEqual(parse_document(raw, "yaml"), {
            "decimal": 42, "negative": -42, "positive": 42,
            "grouped": 1_000_000, "binary": 42, "octal": 42,
            "hexadecimal": 42, "sexagesimal": 3723, "fraction": 3723.5,
            "exponent": 125.0, "explicit_integer": 42, "explicit_float": 1.5,
            "scalar_mapping": 42, "enabled": True, "optional": None,
            "name": "example",
        })

    def test_long_strings_remain_supported_in_yaml_and_frontmatter(self):
        numeric_text = "7" * 20_000
        underscored_text = "_" * 20_000 + "1:00"
        raw = ("description: '" + numeric_text + "'\nname: " + underscored_text + "\n").encode()
        expected = {"description": numeric_text, "name": underscored_text}
        self.assertEqual(parse_document(raw, "yaml"), expected)
        self.assertEqual(parse_document(b"---\n" + raw + b"---\nBody\n", "markdown"), expected)


if __name__ == "__main__":
    unittest.main()
