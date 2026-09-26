"""RFC 9449 §4.3 step 9 — htu comparison under RFC 3986 §6.2 normalization."""

import pytest

from dpop.htu import normalize_htu


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("https://api.example.test/orders", "https://api.example.test/orders"),
        # §6.2.2.1: scheme and host are case-insensitive; the path is not.
        ("HTTPS://API.Example.TEST/Orders", "https://api.example.test/Orders"),
        # §6.2.3: a default port is the same as none.
        ("https://api.example.test:443/orders", "https://api.example.test/orders"),
        ("http://api.example.test:80/orders", "http://api.example.test/orders"),
        ("https://api.example.test:8443/orders", "https://api.example.test:8443/orders"),
        # §6.2.3: an empty path is "/".
        ("https://api.example.test", "https://api.example.test/"),
        # RFC 9449 §4.3 step 9: query and fragment are ignored.
        ("https://api.example.test/orders?limit=20#top", "https://api.example.test/orders"),
        # §6.2.2.2: unreserved characters are decoded, other triplets uppercased.
        ("https://api.example.test/%7Euser/a%2fb", "https://api.example.test/~user/a%2Fb"),
        # §6.2.2.3: dot segments are removed.
        ("https://api.example.test/a/./b/../c", "https://api.example.test/a/c"),
        ("https://api.example.test/a/..", "https://api.example.test/"),
        ("https://api.example.test/..", "https://api.example.test/"),
        ("https://api.example.test/a/.", "https://api.example.test/a/"),
        # IPv6 literals keep their brackets.
        ("https://[::1]:8443/x", "https://[::1]:8443/x"),
    ],
)
def test_normalization(given: str, expected: str) -> None:
    assert normalize_htu(given) == expected


@pytest.mark.parametrize(
    "bad",
    [
        "/orders",  # relative
        "ftp://api.example.test/orders",  # not http(s)
        "https:///orders",  # no host
        "https://user:pass@api.example.test/orders",  # userinfo
        "https://api.example.test:99999/orders",  # port out of range
    ],
)
def test_non_request_uris_are_refused(bad: str) -> None:
    with pytest.raises(ValueError, match=r"."):
        normalize_htu(bad)


def test_the_trailing_slash_is_significant() -> None:
    """Syntax-based normalization never adds or drops a trailing slash."""
    assert normalize_htu("https://a.test/orders") != normalize_htu("https://a.test/orders/")
