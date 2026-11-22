"""
x402-python-client — a tiny Python client for x402 pay-per-call endpoints on Base.

Talks to the Manteclaw x402 service (https://manteclaw-x402.fly.dev) and to any
other x402 v2 service using the "exact" scheme that puts its terms in the
base64 ``payment-required`` header and verifies EIP-3009
``transferWithAuthorization`` signatures.

How a paid call works
---------------------
1. GET the endpoint. It answers HTTP 402 Payment Required, with the price in
   the ``payment-required`` response header (base64 JSON): the USDC amount,
   the network (``eip155:8453`` = Base), the token contract and the ``payTo``
   wallet.
2. Build an EIP-3009 authorization: from / to / value / validAfter /
   validBefore / nonce (32 random bytes).
3. Sign it with EIP-712. The signature is off-chain — no gas, no ETH needed.
   The facilitator submits the transfer on-chain.
4. Retry the same GET with the base64 payment in the ``X-PAYMENT`` header
   (and ``PAYMENT-SIGNATURE``, same value). The server verifies the payment
   and returns the data as JSON.

The payment payload mirrors the catalog page's Pay & Call flow, which is the
format verified working against the live service: authorization values are
strings in the JSON payload, ``validAfter`` is 60 seconds in the past, the
nonce is ``0x`` + 64 hex chars, the signature is ``0x``-prefixed, and the
payload carries the accepted terms under ``accepted``.

Keys
----
This library never reads a private key from disk or from the environment.
Pass an ``eth_account`` Account (or a key) explicitly. ``dry_run`` mode
builds and prints the payment payload without signing anything, so you can
inspect exactly what a call would cost and authorise before any key exists.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any, Optional

import requests
from eth_account import Account

DEFAULT_BASE_URL = "https://manteclaw-x402.fly.dev"
DEFAULT_TIMEOUT = 30
USDC_DECIMALS = 6

# EIP-712 type definition for USDC transferWithAuthorization (EIP-3009).
TRANSFER_WITH_AUTHORIZATION_TYPES = {
    "TransferWithAuthorization": [
        {"name": "from", "type": "address"},
        {"name": "to", "type": "address"},
        {"name": "value", "type": "uint256"},
        {"name": "validAfter", "type": "uint256"},
        {"name": "validBefore", "type": "uint256"},
        {"name": "nonce", "type": "bytes32"},
    ]
}


class X402Error(Exception):
    """Base error for this client."""


class PaymentRequired(X402Error):
    """Raised when an endpoint answers 402 and no payment was made.

    Carries the decoded payment terms so the caller can show the price,
    or sign and retry.
    """

    def __init__(self, terms: dict, url: str):
        self.terms = terms
        self.url = url
        accept = (terms.get("accepts") or [{}])[0]
        amount = accept.get("amount", "?")
        super().__init__(
            f"Payment required for {url}: "
            f"{format_usdc(amount)} USDC to {accept.get('payTo', '?')} "
            f"on {accept.get('network', '?')}"
        )


class NoAccountError(X402Error):
    """Raised when a paid call needs a signing account and none was given."""


class UnsupportedSchemeError(X402Error):
    """Raised when the 402 terms offer no 'exact' scheme entry."""


def decode_payment_required(header_value: str) -> dict:
    """Decode a base64 ``payment-required`` header into its terms dict."""
    padded = header_value.strip()
    padded += "=" * (-len(padded) % 4)  # tolerate missing padding
    return json.loads(base64.b64decode(padded).decode("utf-8"))


def parse_network(network: str) -> int:
    """Turn an x402 network id like ``eip155:8453`` into a chain id (8453)."""
    try:
        scheme, chain_id = network.split(":", 1)
    except ValueError:
        raise X402Error(f"Unrecognised network id: {network!r}") from None
    if scheme != "eip155":
        raise X402Error(f"Unsupported network scheme: {network!r}")
    try:
        return int(chain_id)
    except ValueError:
        raise X402Error(f"Unrecognised network id: {network!r}") from None


def format_usdc(amount: str | int) -> str:
    """Format a raw USDC amount (6 decimals) as a dollar string, e.g. 1000 -> '0.001'."""
    raw = int(amount)
    whole, frac = divmod(raw, 10 ** USDC_DECIMALS)
    return f"{whole}.{frac:06d}".rstrip("0").rstrip(".") or "0"


def _eip712_domain(accept: dict) -> dict:
    """EIP-712 domain for the token in the 402 terms (USDC on Base)."""
    extra = accept.get("extra") or {}
    return {
        "name": extra.get("name", "USD Coin"),
        "version": extra.get("version", "2"),
        "chainId": parse_network(accept["network"]),
        "verifyingContract": accept["asset"],
    }


def _authorization_for_signing(
    accept: dict,
    payer: str,
    valid_after: int,
    valid_before: int,
    nonce: bytes,
) -> dict:
    """Authorization values as typed for EIP-712 signing (ints + raw bytes)."""
    return {
        "from": payer,
        "to": accept["payTo"],
        "value": int(accept["amount"]),
        "validAfter": valid_after,
        "validBefore": valid_before,
        "nonce": nonce,
    }


def _authorization_for_payload(signing_auth: dict) -> dict:
    """The same authorization as it goes into the JSON payment payload.

    Values are strings and the nonce is ``0x``-prefixed hex — the format the
    live service's Pay & Call flow sends.
    """
    return {
        "from": signing_auth["from"],
        "to": signing_auth["to"],
        "value": str(signing_auth["value"]),
        "validAfter": str(signing_auth["validAfter"]),
        "validBefore": str(signing_auth["validBefore"]),
        "nonce": "0x" + bytes(signing_auth["nonce"]).hex(),
    }


class X402Client:
    """Minimal client for an x402 v2 'exact'-scheme service."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        account: Optional[Account] = None,
        timeout: int = DEFAULT_TIMEOUT,
        session: Optional[requests.Session] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.account = account
        self.timeout = timeout
        self.session = session or requests.Session()

    @classmethod
    def from_private_key(
        cls,
        private_key: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> "X402Client":
        """Build a client from a private key string.

        The key is held in memory only. Never paste a key that controls
        meaningful funds, and never commit one — use a dedicated low-balance
        wallet for pay-per-call.
        """
        return cls(base_url=base_url, account=Account.from_key(private_key), timeout=timeout)

    # -- URLs -----------------------------------------------------------------

    def url(self, path_or_url: str) -> str:
        """Resolve a path (``/defi/gas-tracker``) or a full URL against the base."""
        if path_or_url.startswith(("http://", "https://")):
            return path_or_url
        return self.base_url + "/" + path_or_url.lstrip("/")

    # -- 402 terms ------------------------------------------------------------

    def get_payment_terms(self, path_or_url: str) -> dict:
        """GET an endpoint and return its decoded 402 payment terms.

        Raises X402Error if the endpoint does not answer 402 (e.g. it is
        free, or it already returned data).
        """
        r = self.session.get(self.url(path_or_url), timeout=self.timeout)
        if r.status_code != 402:
            raise X402Error(
                f"Expected HTTP 402 from {self.url(path_or_url)}, "
                f"got {r.status_code}"
            )
        header = r.headers.get("payment-required")
        if not header:
            raise X402Error("402 reply carried no 'payment-required' header")
        return decode_payment_required(header)

    @staticmethod
    def pick_accept(terms: dict) -> dict:
        """Pick the 'exact'-scheme entry from decoded 402 terms."""
        for accept in terms.get("accepts", []):
            if accept.get("scheme") == "exact":
                return accept
        raise UnsupportedSchemeError(
            "402 terms offer no 'exact' scheme entry: "
            f"{[a.get('scheme') for a in terms.get('accepts', [])]}"
        )

    # -- payment construction -------------------------------------------------

    def build_authorization(
        self,
        accept: dict,
        valid_after: Optional[int] = None,
        valid_before: Optional[int] = None,
        nonce: Optional[bytes] = None,
    ) -> tuple[dict, dict]:
        """Build the EIP-3009 authorization for one call.

        Returns ``(signing_auth, payload_auth)``: the first is typed for
        EIP-712 signing (ints + raw nonce bytes), the second is the same
        authorization as it goes into the JSON payment payload (strings +
        ``0x`` nonce). ``valid_after`` defaults to 60 seconds in the past
        and ``valid_before`` to now + the terms' ``maxTimeoutSeconds``
        (default 300), matching the live service's own Pay & Call flow.
        """
        now = int(time.time())
        if valid_after is None:
            valid_after = now - 60
        if valid_before is None:
            valid_before = now + int(accept.get("maxTimeoutSeconds", 300))
        if nonce is None:
            nonce = secrets.token_bytes(32)
        if self.account is None:
            raise NoAccountError(
                "No signing account on this client — pass account= to "
                "X402Client or use from_private_key()."
            )
        signing_auth = _authorization_for_signing(
            accept, self.account.address, valid_after, valid_before, nonce
        )
        return signing_auth, _authorization_for_payload(signing_auth)

    def sign_authorization(self, accept: dict, signing_auth: dict) -> str:
        """EIP-712 sign an authorization; returns the ``0x``-prefixed signature."""
        if self.account is None:
            raise NoAccountError("No signing account on this client.")
        signed = self.account.sign_typed_data(
            _eip712_domain(accept),
            TRANSFER_WITH_AUTHORIZATION_TYPES,
            signing_auth,
        )
        return "0x" + signed.signature.hex()

    def build_payment(self, accept: dict, payload_auth: dict, signature: Optional[str]) -> dict:
        """Assemble the x402 v2 payment object (signature None = unsigned draft)."""
        return {
            "x402Version": 2,
            "scheme": accept.get("scheme", "exact"),
            "network": accept["network"],
            "accepted": accept,
            "payload": {"signature": signature, "authorization": payload_auth},
        }

    @staticmethod
    def encode_payment_header(payment: dict) -> str:
        """Base64-encode a payment object for the X-PAYMENT header."""
        return base64.b64encode(json.dumps(payment).encode("utf-8")).decode("ascii")

    def prepare_payment(
        self, path_or_url: str, valid_seconds: Optional[int] = None
    ) -> dict:
        """Fetch the 402 terms and build the (unsigned) payment for a call.

        Returns a dict with ``terms``, ``accept``, ``authorization`` (payload
        form) and ``payment`` (signature None). Nothing is signed and nothing
        is sent — this is the dry-run path.
        """
        terms = self.get_payment_terms(path_or_url)
        accept = self.pick_accept(terms)
        valid_before = None
        if valid_seconds is not None:
            valid_before = int(time.time()) + valid_seconds
        signing_auth, payload_auth = self.build_authorization(
            accept, valid_before=valid_before
        )
        return {
            "terms": terms,
            "accept": accept,
            "authorization": payload_auth,
            "payment": self.build_payment(accept, payload_auth, signature=None),
            "_signing_auth": signing_auth,  # internal: typed values for signing
        }

    def dry_run(self, path_or_url: str, valid_seconds: Optional[int] = None) -> dict:
        """Show exactly what a paid call would authorise — without signing.

        Needs a signing account only to fill in the ``from`` address; use
        an ephemeral one (``Account.create()``) to inspect the payload with
        no key at all. Returns the prepared payment with ``signature`` set
        to None and a human-readable summary. No payment is made.
        """
        prepared = self.prepare_payment(path_or_url, valid_seconds=valid_seconds)
        return self._dry_run_result(
            self.url(path_or_url), prepared["terms"], prepared["accept"],
            prepared["authorization"], prepared["payment"],
        )

    @staticmethod
    def _dry_run_result(
        target: str, terms: dict, accept: dict, payload_auth: dict, payment: dict
    ) -> dict:
        return {
            "dry_run": True,
            "url": target,
            "price_usdc": format_usdc(accept["amount"]),
            "pay_to": accept["payTo"],
            "network": accept["network"],
            "asset": accept["asset"],
            "authorization": payload_auth,
            "payment": payment,
            "note": (
                "Dry run: nothing was signed and no payment was sent. "
                "The 'payment' object above is the exact payload a real call "
                "would send, minus the signature."
            ),
        }

    # -- paid calls -----------------------------------------------------------

    def get(
        self,
        path_or_url: str,
        pay: bool = True,
        dry_run: bool = False,
        valid_seconds: Optional[int] = None,
        **kwargs: Any,
    ) -> requests.Response | dict:
        """GET an endpoint, paying with an EIP-3009 signature when it 402s.

        - Free endpoints (200 on the first try) return the response as-is.
        - ``pay=False``: a 402 raises :class:`PaymentRequired` with the terms.
        - ``dry_run=True``: returns the dry-run dict instead of paying.
        - Otherwise the call is signed with this client's account and retried
          with the payment in the ``X-PAYMENT`` (and ``PAYMENT-SIGNATURE``)
          headers, and the second response is returned.
        """
        target = self.url(path_or_url)
        r = self.session.get(target, timeout=self.timeout, **kwargs)
        if r.status_code != 402:
            return r
        terms = decode_payment_required(r.headers["payment-required"])
        accept = self.pick_accept(terms)
        if dry_run:
            if self.account is None:
                raise NoAccountError(
                    "Dry run needs an account to fill in the 'from' address — "
                    "use an ephemeral one (Account.create()) or call "
                    "client.dry_run() on a client built with an account. "
                    "Nothing is signed in a dry run."
                )
            valid_before = None
            if valid_seconds is not None:
                valid_before = int(time.time()) + valid_seconds
            signing_auth, payload_auth = self.build_authorization(
                accept, valid_before=valid_before
            )
            payment = self.build_payment(accept, payload_auth, signature=None)
            return self._dry_run_result(target, terms, accept, payload_auth, payment)
        if not pay:
            raise PaymentRequired(terms, target)
        if self.account is None:
            raise NoAccountError(
                "Endpoint requires payment but this client has no signing "
                "account. Pass account= to X402Client, use "
                "from_private_key(), or call with pay=False and inspect "
                "PaymentRequired.terms."
            )
        valid_before = None
        if valid_seconds is not None:
            valid_before = int(time.time()) + valid_seconds
        signing_auth, payload_auth = self.build_authorization(
            accept, valid_before=valid_before
        )
        signature = self.sign_authorization(accept, signing_auth)
        payment = self.build_payment(accept, payload_auth, signature)
        header = self.encode_payment_header(payment)
        return self.session.get(
            target,
            headers={"X-PAYMENT": header, "PAYMENT-SIGNATURE": header},
            timeout=self.timeout,
            **kwargs,
        )

    def get_json(self, path_or_url: str, **kwargs: Any) -> dict:
        """GET an endpoint (paying if needed) and return the parsed JSON body."""
        r = self.get(path_or_url, **kwargs)
        if isinstance(r, dict):  # dry-run result
            return r
        r.raise_for_status()
        return r.json()
