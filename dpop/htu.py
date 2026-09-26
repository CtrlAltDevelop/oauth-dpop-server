"""Comparing a proof's ``htu`` claim with the URI a request actually hit.

RFC 9449 §4.3 step 9 requires the ``htu`` to match the request URI "ignoring
any query and fragment parts", and points at RFC 3986 §6.2.2 (syntax-based)
and §6.2.3 (scheme-based) normalization for the comparison. Both sides are
put through the same function below and compared as strings.

This is where DPoP integrations most often break, so the rules are spelled
out:

* scheme and host are case-insensitive, so both are lowercased;
* a port equal to the scheme's default is dropped;
* an empty path is ``/`` (RFC 9110 §4.2.3);
* percent-encoding is normalized: triplets for unreserved characters are
  decoded and the rest uppercased (RFC 3986 §6.2.2.1-2);
* dot segments are removed (RFC 3986 §6.2.2.3);
* query and fragment are discarded.

A URI with userinfo is rejected outright rather than normalized: a request
target has no userinfo, so its presence means the client built the claim
from something other than the request.
"""

import re
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_PERCENT_TRIPLET = re.compile(r"%([0-9A-Fa-f]{2})")


def _normalize_percent_encoding(path: str) -> str:
    def replace(match: re.Match[str]) -> str:
        char = chr(int(match.group(1), 16))
        return char if char in _UNRESERVED else f"%{match.group(1).upper()}"

    return _PERCENT_TRIPLET.sub(replace, path)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4, over whole segments."""
    output: list[str] = []
    segments = path.split("/")
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == ".":
            if last:
                output.append("")
        elif segment == "..":
            if len(output) > 1:
                output.pop()
            if last:
                output.append("")
        else:
            output.append(segment)
    return "/".join(output)


def normalize_htu(uri: str) -> str:
    """Normalize an absolute ``http``/``https`` URI for ``htu`` comparison.

    Raises ``ValueError`` for anything that cannot be a request target.
    """
    parts = urlsplit(uri)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise ValueError("htu must be an absolute http or https URI")
    if parts.username is not None or parts.password is not None:
        raise ValueError("htu must not carry userinfo")
    host = parts.hostname
    if not host:
        raise ValueError("htu has no host")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port  # raises ValueError for an out-of-range or non-numeric port
    netloc = host if port is None or port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
    path = _remove_dot_segments(_normalize_percent_encoding(parts.path)) or "/"
    return f"{scheme}://{netloc}{path}"
