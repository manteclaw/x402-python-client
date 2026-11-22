"""Tests for x402-python-client.

Run:  python -m unittest test_client -v

Live tests hit https://manteclaw-x402.fly.dev and are skipped when the
service is unreachable. They never spend money: the only signing uses
ephemeral throwaway accounts created in memory (``Account.create()``),
which are never written to disk, and no paid call is ever completed —
dry runs stop before signing, and the signature-recovery test signs a
payment for an empty throwaway wallet that holds no USDC.

No real wallet address, private key, or credential-shaped value appears
anywhere in this file. Offline fixtures use obviously fake placeholder
addresses (0x1111... / 0x2222...); live tests derive the real payee from
the service's own public /health response at runtime instead of hardcoding
it.
"""

import base64
import json
import re
import time
import unittest

import requests
from eth_account import Account
from eth_account.messages import encode_typed_data

from client import (
    DEFAULT_BASE_URL,
    TRANSFER_WITH_AUTHORIZATION_TYPES,
    NoAccountError,
    PaymentRequired,
    UnsupportedSchemeError,
    X402Client,
    X402Error,
    decode_payment_required,
    format_usdc,
    parse_network,
)

ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Fake placeholder addresses for offline fixtures — not real wallets.
FAKE_PAY_TO = "0x" + "11" * 20
FAKE_USDC = "0x" + "22" * 20


def fixture_terms() -> dict:
    """Synthetic 402 terms in the exact shape the live service returns."""
    return {
        "x402Version": 2,
        "error": "Payment required",
        "resource": {
            "url": "/mcp/status",
            "description": "MCP server status. $0.001 USDC per call.",
            "mimeType": "application/json",
        },
        "accepts": [
            {
                "scheme": "exact",
                "network": "eip155:8453",
                "asset": FAKE_USDC,
                "amount": "1000",
                "payTo": FAKE_PAY_TO,
                "maxTimeoutSeconds": 300,
                "extra": {"name": "USD Coin", "version": "2"},
            }
        ],
    }


def fixture_header() -> str:
    """The synthetic terms above, base64-encoded like a real header."""
    return base64.b64encode(json.dumps(fixture_terms()).encode()).decode()


def live_available() -> bool:
    try:
        r = requests.get(DEFAULT_BASE_URL + "/health", timeout=10)
        return r.status_code == 200
    except requests.RequestException:
        return False


def live_payee() -> str:
    """The service's public payee wallet, from its own /health response."""
    r = requests.get(DEFAULT_BASE_URL + "/health", timeout=10)
    r.raise_for_status()
    return r.json()["payee"]


LIVE = live_available()


class TestDecodeAndFormat(unittest.TestCase):
    def test_decode_402_header(self):
        terms = decode_payment_required(fixture_header())
        self.assertEqual(terms["x402Version"], 2)
        accept = terms["accepts"][0]
        self.assertEqual(accept["scheme"], "exact")
        self.assertEqual(accept["network"], "eip155:8453")
        self.assertEqual(accept["asset"], FAKE_USDC)
        self.assertEqual(accept["amount"], "1000")
        self.assertEqual(accept["payTo"], FAKE_PAY_TO)
        self.assertEqual(accept["maxTimeoutSeconds"], 300)
        self.assertEqual(accept["extra"], {"name": "USD Coin", "version": "2"})

    def test_decode_tolerates_missing_padding(self):
        terms = decode_payment_required(fixture_header().rstrip("="))
        self.assertEqual(terms["accepts"][0]["amount"], "1000")

    def test_format_usdc(self):
        self.assertEqual(format_usdc("1000"), "0.001")
        self.assertEqual(format_usdc("5000"), "0.005")
        self.assertEqual(format_usdc("1000000"), "1")
        self.assertEqual(format_usdc("2500000"), "2.5")
        self.assertEqual(format_usdc(20000), "0.02")

    def test_parse_network(self):
        self.assertEqual(parse_network("eip155:8453"), 8453)
        with self.assertRaises(X402Error):
            parse_network("eip155:abc")
        with self.assertRaises(X402Error):
            parse_network("solana:101")
        with self.assertRaises(X402Error):
            parse_network("8453")


class TestClientOffline(unittest.TestCase):
    def setUp(self):
        self.terms = fixture_terms()
        self.accept = self.terms["accepts"][0]
        # Ephemeral throwaway account — in memory only, never saved.
        self.client = X402Client(account=Account.create())

    def test_url_joining(self):
        self.assertEqual(
            self.client.url("/defi/gas-tracker"),
            DEFAULT_BASE_URL + "/defi/gas-tracker",
        )
        self.assertEqual(
            self.client.url("https://example.com/x"), "https://example.com/x"
        )

    def test_pick_accept(self):
        self.assertIs(self.client.pick_accept(self.terms), self.accept)
        with self.assertRaises(UnsupportedSchemeError):
            self.client.pick_accept({"accepts": [{"scheme": "upto"}]})

    def test_build_authorization_matches_terms(self):
        signing_auth, payload_auth = self.client.build_authorization(self.accept)
        self.assertEqual(signing_auth["to"], FAKE_PAY_TO)
        self.assertEqual(signing_auth["value"], 1000)
        self.assertEqual(len(signing_auth["nonce"]), 32)
        self.assertEqual(signing_auth["from"], self.client.account.address)
        # Payload form: strings + 0x nonce, same values.
        self.assertEqual(payload_auth["to"], FAKE_PAY_TO)
        self.assertEqual(payload_auth["value"], "1000")
        self.assertTrue(payload_auth["nonce"].startswith("0x"))
        self.assertEqual(len(payload_auth["nonce"]), 66)
        # validAfter ~60s in the past, validBefore ~300s out.
        now = int(time.time())
        self.assertAlmostEqual(signing_auth["validAfter"], now - 60, delta=5)
        self.assertAlmostEqual(signing_auth["validBefore"], now + 300, delta=5)

    def test_build_payment_shape(self):
        _, payload_auth = self.client.build_authorization(self.accept)
        payment = self.client.build_payment(self.accept, payload_auth, "0xdeadbeef")
        self.assertEqual(payment["x402Version"], 2)
        self.assertEqual(payment["scheme"], "exact")
        self.assertEqual(payment["network"], "eip155:8453")
        self.assertEqual(payment["accepted"], self.accept)
        self.assertEqual(payment["payload"]["signature"], "0xdeadbeef")
        self.assertEqual(payment["payload"]["authorization"], payload_auth)
        # Header round-trips through base64.
        header = self.client.encode_payment_header(payment)
        self.assertEqual(json.loads(base64.b64decode(header)), payment)

    def test_signature_recovers_to_ephemeral_account(self):
        """Sign the exact authorization the terms demand, then recover the
        signer from the EIP-712 signature — proving the typed data, domain
        and field encoding are correct without spending anything."""
        signing_auth, _ = self.client.build_authorization(self.accept)
        signature = self.client.sign_authorization(self.accept, signing_auth)
        self.assertTrue(signature.startswith("0x"))
        self.assertEqual(len(signature), 132)  # 0x + 65 bytes
        domain = {
            "name": "USD Coin",
            "version": "2",
            "chainId": 8453,
            "verifyingContract": FAKE_USDC,
        }
        signable = encode_typed_data(
            domain, TRANSFER_WITH_AUTHORIZATION_TYPES, signing_auth
        )
        recovered = Account.recover_message(
            signable, signature=bytes.fromhex(signature[2:])
        )
        self.assertEqual(recovered, self.client.account.address)

    def test_payment_required_message_shows_price(self):
        err = PaymentRequired(self.terms, DEFAULT_BASE_URL + "/mcp/status")
        self.assertIn("0.001", str(err))
        self.assertIn(FAKE_PAY_TO, str(err))

    def test_no_account_errors(self):
        anon = X402Client()
        with self.assertRaises(NoAccountError):
            anon.build_authorization(self.accept)
        with self.assertRaises(NoAccountError):
            anon.sign_authorization(self.accept, {})


@unittest.skipUnless(LIVE, "live service unreachable")
class TestClientLive(unittest.TestCase):
    def test_health_returns_200(self):
        client = X402Client()
        r = client.get("/health", pay=False)
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["status"], "ok")
        self.assertEqual(body["endpoints"], 200)
        self.assertTrue(ADDRESS_RE.match(body["payee"]))

    def test_mcp_status_402_terms(self):
        client = X402Client()
        terms = client.get_payment_terms("/mcp/status")
        accept = client.pick_accept(terms)
        self.assertEqual(accept["amount"], "1000")
        self.assertEqual(accept["payTo"], live_payee())
        self.assertTrue(ADDRESS_RE.match(accept["asset"]))
        self.assertEqual(accept["network"], "eip155:8453")
        self.assertEqual(accept["scheme"], "exact")
        self.assertEqual(accept["extra"], {"name": "USD Coin", "version": "2"})

    def test_get_pay_false_raises_payment_required(self):
        client = X402Client()
        with self.assertRaises(PaymentRequired) as ctx:
            client.get("/mcp/status", pay=False)
        self.assertEqual(ctx.exception.terms["accepts"][0]["amount"], "1000")

    def test_dry_run_builds_matching_payload(self):
        # Ephemeral account: no real key, nothing signed, nothing spent.
        client = X402Client(account=Account.create())
        result = client.dry_run("/mcp/status")
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["price_usdc"], "0.001")
        self.assertEqual(result["pay_to"], live_payee())
        self.assertEqual(result["network"], "eip155:8453")
        self.assertTrue(ADDRESS_RE.match(result["asset"]))
        auth = result["authorization"]
        self.assertEqual(auth["to"], live_payee())
        self.assertEqual(auth["value"], "1000")
        self.assertTrue(auth["nonce"].startswith("0x"))
        self.assertEqual(len(auth["nonce"]), 66)
        self.assertIsNone(result["payment"]["payload"]["signature"])
        self.assertEqual(
            result["payment"]["payload"]["authorization"], auth
        )
        # validBefore - validAfter is the 60s backdate + 300s window.
        self.assertEqual(
            int(auth["validBefore"]) - int(auth["validAfter"]), 360
        )

    def test_get_dry_run_returns_dict_not_response(self):
        client = X402Client(account=Account.create())
        result = client.get("/mcp/status", dry_run=True)
        self.assertIsInstance(result, dict)
        self.assertTrue(result["dry_run"])

    def test_dry_run_signature_would_recover(self):
        """End-to-end payload check: build the dry-run authorization from
        live terms, sign it with the ephemeral account, and recover the
        signer — the same typed data the live service would verify."""
        client = X402Client(account=Account.create())
        prepared = client.prepare_payment("/mcp/status")
        signing_auth = prepared["_signing_auth"]
        signature = client.sign_authorization(prepared["accept"], signing_auth)
        domain = {
            "name": "USD Coin",
            "version": "2",
            "chainId": 8453,
            "verifyingContract": prepared["accept"]["asset"],
        }
        signable = encode_typed_data(
            domain, TRANSFER_WITH_AUTHORIZATION_TYPES, signing_auth
        )
        recovered = Account.recover_message(
            signable, signature=bytes.fromhex(signature[2:])
        )
        self.assertEqual(recovered, client.account.address)


if __name__ == "__main__":
    unittest.main()
