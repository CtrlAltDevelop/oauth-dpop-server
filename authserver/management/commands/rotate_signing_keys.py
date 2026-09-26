from typing import Any

from django.core.management.base import BaseCommand

from authserver.keys import rotate


class Command(BaseCommand):
    help = (
        "Promote the pending signing key, retire the active one and publish a new pending key. "
        "Schedule it; never run it more often than resource servers refresh their JWKS."
    )

    def handle(self, *args: Any, **options: Any) -> None:
        result = rotate()
        self.stdout.write(f"active:  {result.activated}")
        if result.retired:
            self.stdout.write(f"retired: {result.retired}")
        self.stdout.write(f"pending: {result.pending}")
        for kid in result.deleted:
            self.stdout.write(f"deleted: {kid}")
