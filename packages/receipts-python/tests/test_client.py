"""Run: RECEIPTS_URL=http://127.0.0.1:8723 RECEIPTS_KEY=rcpt_test_… python3 -m unittest discover tests"""
import json
import os
import pathlib
import time
import unittest

from zcash_receipts import (AuthenticationError, InvalidRequestError, Receipts, VerificationError,
                            WebhookSignatureError, construct_event, sign_payload)

URL, KEY = os.environ.get("RECEIPTS_URL"), os.environ.get("RECEIPTS_KEY")
EX = pathlib.Path(__file__).resolve().parents[3] / "examples"


class Webhooks(unittest.TestCase):
    def test_roundtrip_and_rejections(self):
        body = json.dumps({"id": "evt_1", "type": "request.fulfilled"})
        h = sign_payload(body, "whsec_x")
        self.assertEqual(construct_event(body, h, "whsec_x")["id"], "evt_1")
        with self.assertRaises(WebhookSignatureError):
            construct_event(body + " ", h, "whsec_x")
        with self.assertRaises(WebhookSignatureError):
            construct_event(body, sign_payload(body, "whsec_x", int(time.time()) - 3600), "whsec_x")


@unittest.skipUnless(URL and KEY, "set RECEIPTS_URL and RECEIPTS_KEY")
class Api(unittest.TestCase):
    def setUp(self):
        self.r = Receipts(KEY, base_url=URL)
        self.payee = (EX / "testnet/merchant.ua").read_text().strip()

    def test_auth(self):
        with self.assertRaises(AuthenticationError):
            Receipts("rcpt_test_nope", base_url=URL).requests.list()

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
