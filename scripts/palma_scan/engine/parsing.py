"""Bounded, non-executing configuration decoders."""
import json
import math
import plistlib
import tomllib
from .._vendor import json5, yaml

class ParseError(ValueError):
    pass


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ParseError("duplicate key")
        result[key] = value
    return result


class MetadataLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise ParseError("YAML aliases are unsupported")
        return super().compose_node(parent, index)


def _yaml_mapping(loader, node):
    return unique_pairs((loader.construct_object(key), loader.construct_object(value)) for key, value in node.value)


MetadataLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _yaml_mapping)


def validate_tree(data, depth=0, budget=None):
    budget = budget if budget is not None else [20_000]
    budget[0] -= 1
    if depth > 30 or budget[0] < 0:
        raise ParseError("structure limit")
    if isinstance(data, dict):
        if not all(isinstance(key, str) for key in data):
            raise ParseError("non-string key")
        for value in data.values():
            validate_tree(value, depth + 1, budget)
    elif isinstance(data, list):
        for value in data:
            validate_tree(value, depth + 1, budget)
    elif data is not None and not isinstance(data, (str, int, float, bool)):
        raise ParseError("non-JSON scalar")
    elif isinstance(data, float) and not math.isfinite(data):
        raise ParseError("non-finite number")


def parse_document(raw: bytes, format_name: str) -> dict:
    try:
        text = raw.decode("utf-8-sig") if format_name != "plist" else ""
        if format_name == "json":
            data = json.loads(text, object_pairs_hook=unique_pairs)
        elif format_name in {"jsonc", "json5"}:
            data = json5.loads(text, allow_duplicate_keys=False)
        elif format_name == "toml":
            data = tomllib.loads(text)
        elif format_name == "plist":
            data = plistlib.loads(raw)
        elif format_name in {"yaml", "markdown"}:
            frontmatter = text
            if format_name == "markdown":
                lines = text.splitlines()
                if not lines or lines[0].strip() != "---":
                    return {}
                end = next((i for i, line in enumerate(lines[1:501], 1) if line.strip() == "---"), None)
                if end is None:
                    raise ParseError("unclosed frontmatter")
                frontmatter = "\n".join(lines[1:end])
            data = yaml.load(frontmatter, Loader=MetadataLoader) or {}
        else:
            raise ParseError("unknown format")
        validate_tree(data)
        if not isinstance(data, dict):
            raise ParseError("root must be an object")
        return data
    except (ValueError, TypeError, UnicodeError, yaml.YAMLError, RecursionError, OverflowError) as error:
        raise ParseError("invalid bounded document") from error
