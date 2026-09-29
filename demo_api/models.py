from django.db import models
from django.utils import timezone


class Order(models.Model):
    """An order placed through the example API, owned by a token subject."""

    owner = models.CharField(max_length=255, db_index=True)
    item = models.CharField(max_length=200)
    quantity = models.PositiveIntegerField()
    placed_by_client = models.CharField(max_length=64)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self) -> str:
        return f"{self.quantity} x {self.item}"
