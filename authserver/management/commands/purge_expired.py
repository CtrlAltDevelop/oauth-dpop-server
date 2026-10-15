from typing import Any

from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from authserver.models import (
    AccessToken,
    AuthorizationCode,
    PushedAuthorizationRequest,
    TokenFamily,
)


class Command(BaseCommand):
    help = (
        "Delete expired authorization codes, pushed requests, token families (with their "
        "refresh and access tokens) and access tokens. Schedule it; nothing else does."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        now = timezone.now()
        # A family is kept, revoked or not, until it expires: reuse detection
        # needs its rotated-away refresh tokens until then. Deleting it takes
        # its refresh and access tokens with it.
        families, _ = TokenFamily.objects.filter(expires_at__lt=now).delete()
        access, _ = AccessToken.objects.filter(expires_at__lt=now).delete()
        # A redeemed code is kept while its family lives, so a replay can
        # still revoke what the first redemption issued.
        codes, _ = (
            AuthorizationCode.objects.filter(expires_at__lt=now)
            .filter(Q(family__isnull=True) | Q(family__expires_at__lt=now))
            .delete()
        )
        pushed, _ = PushedAuthorizationRequest.objects.filter(expires_at__lt=now).delete()
        self.stdout.write(
            f"deleted rows: {families} in families, {access} access tokens, "
            f"{codes} codes, {pushed} pushed requests"
        )
