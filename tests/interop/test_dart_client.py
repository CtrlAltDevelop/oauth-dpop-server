"""Interop: the published Dart ``dpop_client`` against a live server.

Runs ``interop/dart/bin/interop.dart`` against pytest-django's live server:
discovery, the ``use_dpop_nonce`` round trip, a DPoP-bound token from the
client credentials grant, calls to the example API, and three refusals
(replay, Bearer, a stranger's key). The Dart side builds every proof with
``package:dpop_client``; nothing about DPoP is reimplemented there.

Skipped unless the Dart SDK is on PATH and ``dpop_client`` is checked out
next to this repository — CI's interop job arranges both.
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from django.test import override_settings
from pytest_django.live_server_helper import LiveServer

from authserver.clients import register_client
from config.settings import resource_server
from ninja_dpop import jwks

ROOT = Path(__file__).resolve().parents[2]
DART_PROJECT = ROOT / "interop" / "dart"
DPOP_CLIENT = ROOT.parent / "dpop_client"
DART = shutil.which("dart")

pytestmark = [
    pytest.mark.interop,
    pytest.mark.skipif(DART is None, reason="the Dart SDK is not on PATH"),
    pytest.mark.skipif(
        not (DPOP_CLIENT / "pubspec.yaml").exists(),
        reason=f"dpop_client is not checked out at {DPOP_CLIENT}",
    ),
]


@pytest.mark.django_db(transaction=True)
def test_dart_dpop_client_gets_a_bound_token_and_calls_the_api(live_server: LiveServer) -> None:
    assert DART is not None
    issuer = live_server.url
    client, secret = register_client(
        name="Dart interop",
        client_type="confidential",
        grant_types=["client_credentials"],
        redirect_uris=[],
        scopes=["orders:read", "orders:write"],
    )
    assert secret is not None
    jwks.clear_cache()
    host = issuer.split("//", 1)[1].split(":", 1)[0]

    with override_settings(
        OAUTH_ISSUER=issuer,
        NINJA_DPOP=resource_server(issuer),
        ALLOWED_HOSTS=[host],
    ):
        subprocess.run([DART, "pub", "get"], cwd=DART_PROJECT, check=True, timeout=300)  # noqa: S603
        result = subprocess.run(  # noqa: S603
            [
                DART, "run", "bin/interop.dart",
                "--issuer", issuer,
                "--client-id", client.client_id,
                "--client-secret", secret,
            ],
            cwd=DART_PROJECT,
            capture_output=True,
            text=True,
            timeout=300,
        )
    print(result.stdout)  # noqa: T201 - the step log is the point of this test
    assert result.returncode == 0, result.stdout + result.stderr
    assert "interop checks passed" in result.stdout
