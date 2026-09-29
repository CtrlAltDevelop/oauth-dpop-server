"""An example resource server protected by ``ninja_dpop``.

It lives in the authorization server's process for convenience; nothing in
it depends on that. Pointed at the issuer's JWKS URL instead, it would run
unchanged as a separate service.
"""

from datetime import datetime

from django.http import HttpRequest
from ninja import NinjaAPI, Schema, Status
from ninja.errors import HttpError

from demo_api.models import Order
from ninja_dpop import DPoPAuth, DPoPPrincipal, install

api = NinjaAPI(
    title="Example orders API",
    version="1",
    urls_namespace="demo-api",
    auth=DPoPAuth(),
    description=(
        "Every operation needs `Authorization: DPoP <access token>` and a `DPoP` proof "
        "covering the method, the URL and the token."
    ),
)
install(api)


class Me(Schema):
    subject: str
    client_id: str
    scopes: list[str]
    jkt: str


class OrderIn(Schema):
    item: str
    quantity: int


class OrderOut(Schema):
    id: int
    item: str
    quantity: int
    placed_by_client: str
    created_at: datetime


def _principal(request: HttpRequest) -> DPoPPrincipal:
    principal = getattr(request, "auth", None)
    if not isinstance(principal, DPoPPrincipal):  # unreachable behind DPoPAuth
        raise HttpError(401, "not authenticated")
    return principal


@api.get("/me", response=Me, auth=DPoPAuth(scopes=["profile"]))
def me(request: HttpRequest) -> Me:
    principal = _principal(request)
    return Me(
        subject=principal.subject,
        client_id=principal.client_id,
        scopes=sorted(principal.scopes),
        jkt=principal.jkt,
    )


@api.get("/orders", response=list[OrderOut], auth=DPoPAuth(scopes=["orders:read"]))
def list_orders(request: HttpRequest) -> list[Order]:
    return list(Order.objects.filter(owner=_principal(request).subject).order_by("-id"))


@api.post("/orders", response={201: OrderOut}, auth=DPoPAuth(scopes=["orders:write"]))
def place_order(request: HttpRequest, payload: OrderIn) -> Status[Order]:
    if not 0 < payload.quantity <= 1000:
        raise HttpError(422, "quantity must be between 1 and 1000")
    principal = _principal(request)
    order = Order.objects.create(
        owner=principal.subject,
        item=payload.item[:200],
        quantity=payload.quantity,
        placed_by_client=principal.client_id,
    )
    return Status(201, order)
