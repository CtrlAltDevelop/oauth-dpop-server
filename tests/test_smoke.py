import pytest
from django.core.management import call_command


# Django 6.1 checks JSONField support against the database.
@pytest.mark.django_db
def test_system_checks_pass() -> None:
    call_command("check", fail_level="WARNING")
