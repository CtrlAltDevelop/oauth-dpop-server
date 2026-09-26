import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from authserver.clients import register_client
from authserver.models import Client


class Command(BaseCommand):
    help = "Register an OAuth client. A confidential client's secret is printed once, here."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("name")
        parser.add_argument(
            "--type",
            dest="client_type",
            choices=Client.ClientType.values,
            default=Client.ClientType.CONFIDENTIAL,
        )
        parser.add_argument(
            "--grant",
            dest="grant_types",
            action="append",
            choices=Client.GrantType.values,
            required=True,
        )
        parser.add_argument("--redirect-uri", dest="redirect_uris", action="append", default=[])
        parser.add_argument("--scope", dest="scopes", action="append", default=[])
        parser.add_argument(
            "--introspect",
            action="store_true",
            help="Allow this client to introspect tokens issued to other clients.",
        )
        parser.add_argument("--json", action="store_true", help="Print the result as JSON.")

    def handle(self, *args: Any, **options: Any) -> None:
        try:
            client, secret = register_client(
                name=options["name"],
                client_type=options["client_type"],
                grant_types=options["grant_types"],
                redirect_uris=options["redirect_uris"],
                scopes=options["scopes"],
                can_introspect=options["introspect"],
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        if options["json"]:
            self.stdout.write(json.dumps({"client_id": client.client_id, "client_secret": secret}))
            return
        self.stdout.write(f"client_id:     {client.client_id}")
        if secret is not None:
            self.stdout.write(f"client_secret: {secret}")
            self.stdout.write(
                self.style.WARNING("The secret is not stored and cannot be shown again.")
            )
