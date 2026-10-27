"""Run: python3 -m unittest discover tests. The API tests use ZCEIPT_URL and ZCEIPT_KEY if set,
else a throwaway local `zceipt serve` ($ZCEIPT, PATH or this repository's release build)."""
import atexit
import json
import os
import pathlib
import random
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request

from zceipt import (AuthenticationError, ZceiptError, InvalidRequestError, Zceipt, VerificationError,
                            WebhookSignatureError, construct_event, sign_payload)

EX = pathlib.Path(__file__).resolve().parents[3] / "examples"


def _local_api():
    repo = EX.parent
    target = os.environ.get("CARGO_TARGET_DIR")
    for b in [os.environ.get("ZCEIPT"), target and os.path.join(target, "release/zceipt"), str(repo / "target/release/zceipt"), shutil.which("zceipt")]:
        if b and os.path.exists(b):
            break
    else:
        return None, None
    d = tempfile.mkdtemp(prefix="zceipt-sdk-test-")
    port = random.randint(20000, 40000)
    log = open(os.path.join(d, "log"), "w+")
    p = subprocess.Popen([b, "serve", "--listen", f"127.0.0.1:{port}", "--db", os.path.join(d, "api.db")], stdout=log, stderr=log)
    atexit.register(p.kill)
    for _ in range(100):
        log.seek(0)
        m = re.search(r"rcpt_test_[A-Za-z0-9_]+", log.read())
        if m:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/v1/health", timeout=1)
                return f"http://127.0.0.1:{port}", m.group(0)
            except OSError:
                pass
        time.sleep(0.1)
    p.kill()
    return None, None


URL, KEY = os.environ.get("ZCEIPT_URL"), os.environ.get("ZCEIPT_KEY")
if not (URL and KEY):
    URL, KEY = _local_api()


class Webhooks(unittest.TestCase):
    def test_roundtrip_and_rejections(self):
        body = json.dumps({"id": "evt_1", "type": "request.fulfilled"})
        h = sign_payload(body, "whsec_x")
        self.assertEqual(construct_event(body, h, "whsec_x")["id"], "evt_1")
        with self.assertRaises(WebhookSignatureError):
            construct_event(body + " ", h, "whsec_x")
        with self.assertRaises(WebhookSignatureError):
            construct_event(body, sign_payload(body, "whsec_x", int(time.time()) - 3600), "whsec_x")


@unittest.skipUnless(URL and KEY, "set ZCEIPT_URL and ZCEIPT_KEY")
class Api(unittest.TestCase):
    def setUp(self):
        self.r = Zceipt(KEY, base_url=URL)
        self.payee = (EX / "testnet/merchant.ua").read_text().strip()

    def test_auth(self):
        with self.assertRaises(AuthenticationError):
            Zceipt("rcpt_test_nope", base_url=URL).requests.list()

    def test_requests(self):
        a = self.r.requests.create(payee=self.payee, amount_zatoshis=1_000_000, label="py", idempotency_key="py-1")
        b = self.r.requests.create(payee=self.payee, amount_zatoshis=1_000_000, label="py", idempotency_key="py-1")
        self.assertEqual(a["id"], b["id"])
        self.assertTrue(a["payment_uri"].startswith("zcash:utest1"))
        self.assertEqual(self.r.requests.retrieve(a["id"])["status"], "open")
        with self.assertRaises(InvalidRequestError) as cm:
            self.r.requests.create(payee="nope")
        self.assertEqual(cm.exception.param, "payee")

    def test_verify(self):
        receipt = (EX / "testnet/receipt.txt").read_text()
        self.assertEqual(self.r.verify(receipt)["mined_height"], 4500997)
        with self.assertRaises(VerificationError) as cm:
            self.r.verify(receipt, challenge="00112233aabbccdd")
        self.assertEqual(cm.exception.code, "challenge_mismatch")


if __name__ == "__main__":
    unittest.main()


class WebHelpers(unittest.TestCase):
    PAYEE = "utest14te2vs2rwfe54mal8dwgejft2e9smlyasrku87ay4rq3dxnwcukp0vyck6exmjg60jttxz9y4a94772x0zc7xhj8gg7k00g4rg0zmdfa"

    def test_webhook_dispatch(self):
        from zceipt.web import handle_webhook
        body = json.dumps({"id": "evt_9", "type": "refund.succeeded"})
        seen = []
        handle_webhook(body, sign_payload(body, "whsec_y"), "whsec_y", {"refund.succeeded": lambda e: seen.append(e["id"])})
        self.assertEqual(seen, ["evt_9"])
        with self.assertRaises(WebhookSignatureError):
            handle_webhook(body, "t=1,v1=00", "whsec_y")

    @unittest.skipUnless(URL and KEY, "needs ZCEIPT_URL and ZCEIPT_KEY")
    def test_gate(self):
        from zceipt.web import check_gate
        c = Zceipt(KEY, base_url=URL)
        g = check_gate(c, payee=self.PAYEE, amount_zatoshis=1_000_000, bind_to="alice")
        self.assertEqual((g.allow, g.status), (False, 402))
        rid = g.body["request"]
        self.assertFalse(check_gate(c, payee=self.PAYEE, amount_zatoshis=1_000_000, request_id=rid, bind_to="alice").allow)
        c.requests.submit_receipt(rid, receipt="zip311_test_valid")
        self.assertTrue(check_gate(c, payee=self.PAYEE, amount_zatoshis=1_000_000, request_id=rid, bind_to="alice").allow)
        self.assertFalse(check_gate(c, payee=self.PAYEE, amount_zatoshis=1_000_000, request_id=rid, bind_to="mallory").allow)
        self.assertFalse(check_gate(c, payee=self.PAYEE, amount_zatoshis=5_000_000, request_id=rid, bind_to="alice").allow)


@unittest.skipUnless(URL and KEY, "needs ZCEIPT_URL and ZCEIPT_KEY")
class Parity(unittest.TestCase):
    """Calls every API operation through this SDK and checks the list against conformance/sdk-parity.json."""
    PAYEE = WebHelpers.PAYEE

    def test_every_operation(self):
        table = {k for k in json.loads((EX.parent / "conformance" / "sdk-parity.json").read_text()) if not k.startswith("_")}
        c, done = Zceipt(KEY, base_url=URL), set()

        def call(op, value):
            done.add(op)
            return value
        call("health", c.health())
        call("listErrors", c.list_errors())
        call("listSandboxFixtures", c.sandbox_fixtures())
        call("verify", c.verify("zip311_test_valid"))
        call("checkPaymentLink", c.check_payment_link(f"zcash:{self.PAYEE}?amount=0.01"))
        clock = call("createTestClock", c.test_clocks.create())
        call("getTestClock", c.test_clocks.retrieve(clock["id"]))
        req = call("createRequest", c.requests.create(payee=self.PAYEE, amount_zatoshis=1_000_000, test_clock=clock["id"]))
        call("getRequest", c.requests.retrieve(req["id"]))
        call("listRequests", c.requests.list(limit=2))
        self.assertIn("<svg", call("requestQr", c.requests.qr(req["id"])))
        call("publicGetRequest", c.public.get_request(req["id"], req["client_secret"]))
        call("publicSubmitReceipt", c.public.submit_receipt(req["id"], receipt="zip311_test_refund_to", client_secret=req["client_secret"]))
        call("advanceTestClock", c.test_clocks.advance(clock["id"], blocks=9))
        call("reorgTestClock", c.test_clocks.reorg(clock["id"], depth=1))
        rf = call("createRefund", c.refunds.create(req["id"], amount_zatoshis=1000))
        call("getRefund", c.refunds.retrieve(rf["id"]))
        call("submitRefundReceipt", c.refunds.submit_receipt(rf["id"], receipt="zip311_test_valid"))
        other = c.requests.create(payee=self.PAYEE, amount_zatoshis=1_000_000)
        call("submitReceipt", c.requests.submit_receipt(other["id"], receipt="zip311_test_valid"))
        with self.assertRaises(ZceiptError) as cm:
            c.requests.review(other["id"], decision="accept")
        self.assertEqual(cm.exception.code, "not_held_for_review")
        done.add("reviewDeposit")
        att = call("createAttestation", c.attestations.create(other["id"]))
        call("verifyAttestation", c.attestations.verify(att["presentation"]))
        call("jwks", c.attestations.jwks())
        camp = c.requests.create(payee=self.PAYEE, kind="campaign")
        call("publicCampaign", c.public.campaign(camp["id"]))
        call("createSignInChallenge", c.sign_in.create_challenge(domain="parity.test"))
        with self.assertRaises(InvalidRequestError):
            c.sign_in.verify("zsig1AAAA")
        done.add("verifySignIn")
        with self.assertRaises(InvalidRequestError):
            c.claims.verify("zip311t1AAAA", domain="round")
        done.add("verifyClaim")
        ep = call("createWebhookEndpoint", c.webhook_endpoints.create(url="http://127.0.0.1:9/parity"))
        call("listWebhookEndpoints", c.webhook_endpoints.list())
        call("deleteWebhookEndpoint", c.webhook_endpoints.delete(ep["id"]))
        ev = call("listEvents", c.events.list(limit=1))
        call("resendEvent", c.events.resend(ev["data"][0]["id"]))
        call("listDeliveries", c.list_deliveries(limit=1))
        self.assertEqual(table - done, set())
