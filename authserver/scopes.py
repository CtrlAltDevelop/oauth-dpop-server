"""Scope strings (RFC 6749 §3.3)."""

import re

# scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")


def parse_scope(value: str) -> list[str]:
    """Split a space-delimited scope string, keeping order and dropping repeats.

    Raises ``ValueError`` if any token is outside RFC 6749's grammar.
    """
    tokens = value.split(" ")
    if not all(_SCOPE_TOKEN.match(token) for token in tokens):
        raise ValueError("malformed scope")
    return list(dict.fromkeys(tokens))


def format_scope(scopes: list[str]) -> str:
    return " ".join(scopes)
