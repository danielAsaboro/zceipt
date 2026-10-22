"""Framework helpers: an HTTP 402 "prove you paid" gate and a webhook handler.

Standard library only; the same two functions plug into FastAPI, Django, Flask or anything else.

FastAPI::

    from fastapi import FastAPI, Request, Response
    from zcash_receipts import Receipts
    from zcash_receipts.web import check_gate, handle_webhook

    app, receipts = FastAPI(), Receipts(os.environ["RECEIPTS_KEY"])

    @app.get("/report.pdf")
    def report(request: Request, response: Response):
        gate = check_gate(receipts, payee=SHOP_UA, amount_zatoshis=1_000_000,
                          request_id=request.headers.get("receipt-request"), bind_to=request.session["id"])
        if not gate.allow:
            response.status_code = 402
            return gate.body
        return FileResponse("report.pdf")

    @app.post("/webhooks/receipts")
    async def hooks(request: Request):
        handle_webhook(await request.body(), request.headers.get("receipts-signature"), WHSEC,
                       {"request.fulfilled": mark_paid})

Django: ``gate = check_gate(..., request_id=request.headers.get("Receipt-Request"))`` then
``JsonResponse(gate.body, status=402)``; for webhooks, ``handle_webhook(request.body, request.headers.get("Receipts-Signature"), ...)``.
Flask: the same with ``request.get_data()``.
"""
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from . import InvalidRequestError, Receipts, construct_event


@dataclass
class Gate:
    allow: bool
    status: int = 200
    body: Dict[str, Any] = field(default_factory=dict)
    request: Optional[Dict[str, Any]] = None


def _challenge(r: Dict[str, Any], state: str) -> Dict[str, Any]:
    return {
        "error": {"type": "payment_required", "state": state,
                  "message": f"Pay {r['amount_zatoshis'] / 1e8} ZEC, answer the receipt link with a receipt, "
                             f"then retry with the header Receipt-Request: {r['id']}"},
        "request": r["id"], "payment_uri": r["payment_uri"], "receipt_link": r["receipt_link"],
        "hosted_url": r.get("hosted_url"), "expires_at": r.get("expires_at"),
        "retry_with_header": {"Receipt-Request": r["id"]},
    }


_issued: Dict[str, Any] = {}
_window = {"start": 0.0, "count": 0}
_lock = threading.Lock()


def check_gate(receipts: Receipts, *, payee: str, amount_zatoshis: int, request_id: Optional[str] = None,
               bind_to: Optional[str] = None, route: Optional[str] = None, label: Optional[str] = None,
               expires_in: int = 3600, require_final: bool = False, max_age_seconds: Optional[int] = 86_400,
               max_new_per_minute: int = 30) -> Gate:
    """Let the caller through if `request_id` names a fulfilled request this gate issued for the
    same payee, `route` (default: the label) and `bind_to`, with at least the price paid net of
    refunds (and, with `max_age_seconds`, recently). Otherwise a 402 body with the caller's open
    request, or a new one; at most `max_new_per_minute` new requests in all (then 429).

    A fulfilled request id is a bearer token, so pass `bind_to`: a server-side session or account
    id, never something the client sends (like X-Forwarded-For)."""
    route_key = str(route or label or "default")
    bind = None if bind_to is None else str(bind_to)
    if request_id:
        try:
            r = receipts.requests.retrieve(request_id)
        except InvalidRequestError:
            r = None
        m = (r or {}).get("metadata") or {}
        refunded = sum(x["amount_zatoshis"] for x in (r or {}).get("refunds", []) if x.get("status") == "succeeded")
        matches = bool(r) and r.get("kind") == "single" and r["payee"] == payee and m.get("gate_route") == route_key \
            and (bind is None or m.get("gate_bind") == bind)
        if matches and r["status"] == "fulfilled" and (r.get("received_zatoshis") or 0) - refunded >= amount_zatoshis:
            paid_at = ((r.get("fulfillment") or {}).get("fulfilled_at") or 0)
            fresh = max_age_seconds is None or paid_at > time.time() - max_age_seconds
            if fresh and (not require_final or r.get("final")):
                return Gate(allow=True, request=r)
            if fresh:
                return Gate(allow=False, status=402, body=_challenge(r, "paid; waiting for 10 confirmations"))
        elif matches and r["status"] == "open":
            return Gate(allow=False, status=402, body=_challenge(r, "waiting for the receipt"))
    key = f"{bind or '*'}|{route_key}"
    # Only a bound caller reuses its open request: unbound callers sharing one id would all get
    # through once anyone paid it.
    with _lock:
        prev = _issued.get(key) if bind is not None else None
    if prev and time.time() - prev[1] < min(expires_in, 600):
        try:
            r = receipts.requests.retrieve(prev[0])
            if r["status"] == "open":
                return Gate(allow=False, status=402, body=_challenge(r, "payment required"))
        except InvalidRequestError:
            pass
    with _lock:
        now = time.time()
        if now - _window["start"] > 60:
            _window.update(start=now, count=0)
        _window["count"] += 1
        if _window["count"] > max_new_per_minute:
            return Gate(allow=False, status=429, body={"error": {"type": "rate_limited", "message": "too many new payment requests; retry in a minute"}})
    meta = {"gate_route": route_key}
    if bind is not None:
        meta["gate_bind"] = bind
    r = receipts.requests.create(payee=payee, amount_zatoshis=amount_zatoshis, label=label, expires_in=expires_in, metadata=meta)
    with _lock:
        if len(_issued) > 10_000:
            _issued.clear()
        if bind is not None:
            _issued[key] = (r["id"], time.time())
    return Gate(allow=False, status=402, body=_challenge(r, "payment required"))


def handle_webhook(raw_body: Any, signature_header: Optional[str], secret: str,
                   handlers: Optional[Dict[str, Callable[[Dict[str, Any]], Any]]] = None,
                   tolerance_secs: int = 300) -> Dict[str, Any]:
    """Verify a webhook's signature and call `handlers[event_type]` (or `handlers["*"]`).
    Raises WebhookSignatureError on a bad signature: answer 400 then."""
    event = construct_event(raw_body, signature_header, secret, tolerance_secs)
    fn = (handlers or {}).get(event.get("type")) or (handlers or {}).get("*")
    if fn:
        fn(event)
    return event
