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
                          request_id=request.headers.get("receipt-request"), bind_to=request.client.host)
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


def check_gate(receipts: Receipts, *, payee: str, amount_zatoshis: int, request_id: Optional[str] = None,
               bind_to: Optional[str] = None, label: Optional[str] = None, expires_in: int = 3600,
               require_final: bool = False) -> Gate:
    """Let the caller through if `request_id` names a fulfilled request this gate issued (for the
    same payee, at least the amount, and the same `bind_to`); otherwise a 402 body with a new or
    still-open request. A fulfilled request id is a bearer token, so pass `bind_to` (a session or
    account id) when access should stay with one caller."""
    if request_id:
        try:
            r = receipts.requests.retrieve(request_id)
        except InvalidRequestError:
            r = None
        bound = bind_to is None or (r or {}).get("metadata", {}).get("gate_bind") == str(bind_to)
        if r and bound and r["payee"] == payee and (r.get("amount_zatoshis") or 0) >= amount_zatoshis:
            if r["status"] == "fulfilled" and (not require_final or r.get("final")):
                return Gate(allow=True, request=r)
            if r["status"] in ("open", "fulfilled"):
                return Gate(allow=False, status=402, body=_challenge(r, "waiting for 10 confirmations" if r["status"] == "fulfilled" else "waiting for the receipt"))
    r = receipts.requests.create(payee=payee, amount_zatoshis=amount_zatoshis, label=label, expires_in=expires_in,
                                 metadata=None if bind_to is None else {"gate_bind": str(bind_to)})
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
