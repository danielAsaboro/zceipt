"""Python client for the Receipts API.

    from zcash_receipts import Receipts, VerificationError

    receipts = Receipts("rcpt_test_…", base_url="http://127.0.0.1:8723")
    req = receipts.requests.create(payee="utest1…", amount_zatoshis=1_000_000, label="Order #42")
    # the payer answers with: receipts create … --request req["receipt_link"]
    try:
        done = receipts.requests.submit_receipt(req["id"], receipt=receipt_text)
    except VerificationError as e:
        print(e.code)  # e.g. "challenge_mismatch", "wrong_payee", "insufficient_amount"

No dependencies (standard library only). Network errors, 429 and 5xx are retried with
backoff, and every POST carries an Idempotency-Key so a retry never acts twice.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Iterator, Optional

__all__ = [
    "Receipts",
    "ReceiptsError",
    "AuthenticationError",
    "InvalidRequestError",
    "VerificationError",
    "ApiError",
    "ConnectionError",
    "WebhookSignatureError",
    "construct_event",
    "sign_payload",
]
__version__ = "0.1.0"


class ReceiptsError(Exception):
    def __init__(self, status: int, body: Optional[Dict[str, Any]] = None):
        err = (body or {}).get("error") or {}
        super().__init__(err.get("message") or f"HTTP {status}")
        self.status = status
        self.type = err.get("type")
        self.code = err.get("code")
        self.param = err.get("param")
        self.doc_url = err.get("doc_url")
        self.body = body


class AuthenticationError(ReceiptsError):
    """401: missing or unknown API key."""


class InvalidRequestError(ReceiptsError):
    """400/404/409: bad parameter, unknown id, already fulfilled…"""


class VerificationError(ReceiptsError):
    """422: the receipt does not prove what is required. See ``code``."""


class ApiError(ReceiptsError):
    """5xx, including 502 ``chain_unavailable``. Safe to retry."""


class ConnectionError(ReceiptsError):  # noqa: A001 - mirrors the other SDKs
    def __init__(self, cause: BaseException):
        super().__init__(0, {"error": {"type": "connection_error", "code": "connection_failed", "message": str(cause)}})
        self.__cause__ = cause


class WebhookSignatureError(Exception):
    pass


def _error_for(status: int, body: Dict[str, Any]) -> ReceiptsError:
    if status == 401:
        return AuthenticationError(status, body)
    if status == 422:
        return VerificationError(status, body)
    if status >= 500:
        return ApiError(status, body)
    return InvalidRequestError(status, body)


class _Resource:
    def __init__(self, client: "Receipts"):
        self._c = client


class _Requests(_Resource):
    def create(self, *, payee: str, amount_zatoshis: Optional[int] = None, label: Optional[str] = None,
               metadata: Optional[Dict[str, Any]] = None, expires_in: Optional[int] = None,
               kind: Optional[str] = None, test_clock: Optional[str] = None,
               source_of_funds: Optional[Dict[str, Any]] = None,
               idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """kind: "single" (default), "partial" (receipts add up) or "campaign" (public tally).
        source_of_funds: a deposit desk, {"required": True, "blocked_addresses": [...]}."""
        body = {k: v for k, v in dict(payee=payee, amount_zatoshis=amount_zatoshis, label=label,
                                      metadata=metadata, expires_in=expires_in, kind=kind,
                                      test_clock=test_clock, source_of_funds=source_of_funds).items() if v is not None}
        return self._c._request("POST", "/v1/requests", body, idempotency_key)

    def retrieve(self, id: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/v1/requests/{urllib.parse.quote(id)}")

    def list(self, *, status: Optional[str] = None, limit: Optional[int] = None,
             starting_after: Optional[str] = None) -> Dict[str, Any]:
        q = {k: v for k, v in dict(status=status, limit=limit, starting_after=starting_after).items() if v is not None}
        return self._c._request("GET", "/v1/requests" + (f"?{urllib.parse.urlencode(q)}" if q else ""))

    def each(self, **params: Any) -> Iterator[Dict[str, Any]]:
        """Iterate every request across pages."""
        after = None
        while True:
            page = self.list(starting_after=after, **params)
            yield from page["data"]
            if not page["has_more"] or not page["data"]:
                return
            after = page["data"][-1]["id"]

    def submit_receipt(self, id: str, *, receipt: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self._c._request("POST", f"/v1/requests/{urllib.parse.quote(id)}/receipts", {"receipt": receipt}, idempotency_key)

    def review(self, id: str, *, decision: str, note: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """Deposit desks: accept or reject a deposit held for review (decision "accept" or "reject")."""
        body = {k: v for k, v in dict(decision=decision, note=note).items() if v is not None}
        return self._c._request("POST", f"/v1/requests/{urllib.parse.quote(id)}/review", body, idempotency_key)

    def qr(self, id: str) -> str:
        """The request's ZIP-321 payment URI as an SVG QR code."""
        return self._c._text(f"/v1/requests/{urllib.parse.quote(id)}/qr.svg")


class _Refunds(_Resource):
    def create(self, request_id: str, *, amount_zatoshis: Optional[int] = None, reason: Optional[str] = None,
               payment_txid: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        """Refund a payment to the address the payer signed into their receipt (--refund-to)."""
        body = {k: v for k, v in dict(amount_zatoshis=amount_zatoshis, reason=reason, payment_txid=payment_txid).items() if v is not None}
        return self._c._request("POST", f"/v1/requests/{urllib.parse.quote(request_id)}/refunds", body, idempotency_key)

    def retrieve(self, id: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/v1/refunds/{urllib.parse.quote(id)}")

    def submit_receipt(self, id: str, *, receipt: str, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self._c._request("POST", f"/v1/refunds/{urllib.parse.quote(id)}/receipts", {"receipt": receipt}, idempotency_key)


class _Attestations(_Resource):
    def create(self, request_id: str, *, at_least_zatoshis: Optional[int] = None, before: Optional[str] = None,
               disclose: Optional[list] = None) -> Dict[str, Any]:
        """A signed, minimal statement about a fulfilled request (SD-JWT). Hidden by default: txid,
        exact amount, exact time, request id, label; reveal them with `disclose` or later."""
        body = {k: v for k, v in dict(at_least_zatoshis=at_least_zatoshis, before=before, disclose=disclose).items() if v is not None}
        return self._c._request("POST", f"/v1/requests/{urllib.parse.quote(request_id)}/attestations", body)

    def verify(self, attestation: str) -> Dict[str, Any]:
        return self._c._request("POST", "/v1/attestations/verify", {"attestation": attestation})

    def jwks(self) -> Dict[str, Any]:
        return self._c._request("GET", "/.well-known/jwks.json")


class _TestClocks(_Resource):
    def create(self, *, frozen_time: Optional[int] = None, height: Optional[int] = None) -> Dict[str, Any]:
        """Sandbox: a frozen time and block height that requests can run on."""
        return self._c._request("POST", "/v1/test_clocks", {k: v for k, v in dict(frozen_time=frozen_time, height=height).items() if v is not None})

    def retrieve(self, id: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/v1/test_clocks/{urllib.parse.quote(id)}")

    def advance(self, id: str, *, seconds: Optional[int] = None, blocks: Optional[int] = None) -> Dict[str, Any]:
        """Move the clock; returns it with `fired` (request.expired / request.final events)."""
        return self._c._request("POST", f"/v1/test_clocks/{urllib.parse.quote(id)}/advance", {k: v for k, v in dict(seconds=seconds, blocks=blocks).items() if v is not None})


    def reorg(self, id: str, *, depth: int = 1) -> Dict[str, Any]:
        """Roll the clock's chain back; unconfirmed payments fire request.payment_reorged."""
        return self._c._request("POST", f"/v1/test_clocks/{urllib.parse.quote(id)}/reorg", {"depth": depth})


class _SignIn(_Resource):
    def create_challenge(self, *, domain: Optional[str] = None) -> Dict[str, Any]:
        """Sign in with Zcash: a single-use nonce bound to domain, valid 5 minutes."""
        return self._c._request("POST", "/v1/sign_in/challenges", {"domain": domain} if domain else {})

    def verify(self, sign_in: str) -> Dict[str, Any]:
        """Check a zsig1… sign-in once; returns the proven address."""
        return self._c._request("POST", "/v1/sign_in/verify", {"sign_in": sign_in})


class _Public(_Resource):
    """What hosted pay and campaign pages use: no API key, a per-request client secret."""
    def get_request(self, id: str, secret: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/v1/public/requests/{urllib.parse.quote(id)}?secret={urllib.parse.quote(secret)}")

    def submit_receipt(self, id: str, *, receipt: str, client_secret: Optional[str] = None) -> Dict[str, Any]:
        body = {"receipt": receipt, **({"client_secret": client_secret} if client_secret else {})}
        return self._c._request("POST", f"/v1/public/requests/{urllib.parse.quote(id)}/receipts", body)

    def campaign(self, id: str) -> Dict[str, Any]:
        return self._c._request("GET", f"/v1/public/campaigns/{urllib.parse.quote(id)}")


class _WebhookEndpoints(_Resource):
    def create(self, *, url: str, events: Optional[list] = None) -> Dict[str, Any]:
        return self._c._request("POST", "/v1/webhook_endpoints", {"url": url, **({"events": events} if events else {})})

    def list(self) -> Dict[str, Any]:
        return self._c._request("GET", "/v1/webhook_endpoints")

    def delete(self, id: str) -> Dict[str, Any]:
        return self._c._request("DELETE", f"/v1/webhook_endpoints/{urllib.parse.quote(id)}")


class _Events(_Resource):
    def list(self, *, limit: Optional[int] = None) -> Dict[str, Any]:
        return self._c._request("GET", "/v1/events" + (f"?limit={limit}" if limit else ""))

    def resend(self, id: str) -> Dict[str, Any]:
        return self._c._request("POST", f"/v1/events/{urllib.parse.quote(id)}/resend", {})


class Receipts:
    def __init__(self, api_key: str, *, base_url: str = "http://127.0.0.1:8723", max_retries: int = 2, timeout: float = 60.0):
        if not api_key:
            raise AuthenticationError(401, {"error": {"code": "missing_api_key", "message": "pass your rcpt_test_… or rcpt_live_… key"}})
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.max_retries = max_retries
        self.timeout = timeout
        self.livemode = api_key.startswith("rcpt_live_")
        self.requests = _Requests(self)
        self.refunds = _Refunds(self)
        self.public = _Public(self)
        self.sign_in = _SignIn(self)
        self.test_clocks = _TestClocks(self)
        self.attestations = _Attestations(self)
        self.webhook_endpoints = _WebhookEndpoints(self)
        self.events = _Events(self)

    def verify(self, receipt: str, *, expect_address: Optional[str] = None, min_zatoshis: Optional[int] = None,
               challenge: Optional[str] = None, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        body = {k: v for k, v in dict(receipt=receipt, expect_address=expect_address, min_zatoshis=min_zatoshis,
                                      challenge=challenge).items() if v is not None}
        return self._request("POST", "/v1/verify", body, idempotency_key)

    def check_payment_link(self, uri: str, *, network: Optional[str] = None) -> Dict[str, Any]:
        """Lint a ZIP-321 link before printing it."""
        return self._request("POST", "/v1/payment_links/check", {"uri": uri, **({"network": network} if network else {})})

    def list_deliveries(self, *, limit: Optional[int] = None) -> Dict[str, Any]:
        return self._request("GET", "/v1/deliveries" + (f"?limit={limit}" if limit else ""))

    def sandbox_fixtures(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/sandbox/fixtures")

    def list_errors(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/errors")

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/v1/health")

    def _text(self, path: str) -> str:
        req = urllib.request.Request(self.base_url + path, headers={"Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as res:
                return res.read().decode()
        except urllib.error.HTTPError as e:
            text = e.read().decode()
            e.close()
            raise _error_for(e.code, json.loads(text) if text.startswith("{") else {"error": {"message": text}}) from None

    def _request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
                 idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Authorization": f"Bearer {self.api_key}", "User-Agent": f"zcash-receipts-python/{__version__}"}
        data = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = idempotency_key or secrets.token_hex(16)
            data = json.dumps(body or {}).encode()
        attempt = 0
        while True:
            req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as res:
                    text = res.read().decode()
                    return json.loads(text) if text else {}
            except urllib.error.HTTPError as e:
                text = e.read().decode()
                e.close()
                try:
                    payload = json.loads(text) if text else {}
                except ValueError:
                    payload = {"error": {"message": text}}
                if (e.code == 429 or e.code >= 500) and attempt < self.max_retries:
                    after = e.headers.get("Retry-After") if e.headers else None
                    time.sleep(min(float(after), 60.0) if after and after.isdigit() else 0.5 * 2 ** attempt)
                    attempt += 1
                    continue
                raise _error_for(e.code, payload) from None
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                if attempt < self.max_retries:
                    time.sleep(0.5 * 2 ** attempt)
                    attempt += 1
                    continue
                raise ConnectionError(e) from None


def sign_payload(raw_body: str, secret: str, t: Optional[int] = None) -> str:
    """Builds a valid ``Receipts-Signature`` header value (for tests)."""
    t = int(time.time()) if t is None else t
    mac = hmac.new(secret.encode(), f"{t}.{raw_body}".encode(), hashlib.sha256).hexdigest()
    return f"t={t},v1={mac}"


def construct_event(raw_body: bytes | str, signature_header: Optional[str], secret: str, tolerance_secs: int = 300) -> Dict[str, Any]:
    """Verifies a webhook delivery and returns the event. Pass the raw request body."""
    body = raw_body.decode() if isinstance(raw_body, (bytes, bytearray)) else raw_body
    parts = dict(p.split("=", 1) for p in (signature_header or "").split(",") if "=" in p)
    try:
        t = int(parts["t"])
        v1 = parts["v1"]
    except (KeyError, ValueError):
        raise WebhookSignatureError("missing or malformed Receipts-Signature header") from None
    if abs(time.time() - t) > tolerance_secs:
        raise WebhookSignatureError("timestamp outside the tolerance window")
    expected = hmac.new(secret.encode(), f"{t}.{body}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, v1):
        raise WebhookSignatureError("signature does not match")
    return json.loads(body)
