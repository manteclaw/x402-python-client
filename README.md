# x402-python-client

A tiny Python client for **x402 pay-per-call endpoints on Base** — built
against the live Manteclaw x402 service
([manteclaw-x402.fly.dev](https://manteclaw-x402.fly.dev), 200 endpoints,
$0.001–$0.02 per call in USDC), and usable against any x402 v2 service
using the `"exact"` scheme.

## How a paid call works

1. You `GET` an endpoint. It answers **HTTP 402 Payment Required**, with
   the price in the `payment-required` response header (base64 JSON): the
   USDC amount, the network (`eip155:8453` = Base), the token contract and
   the `payTo` wallet.
2. The client builds an EIP-3009 `transferWithAuthorization` — from / to /
   value / validAfter / validBefore / nonce (32 random bytes).
3. It signs the authorization with EIP-712. The signature is **off-chain —
   no gas, no ETH needed**. The facilitator submits the transfer on-chain.
4. The client retries the same `GET` with the base64 payment in the
   `X-PAYMENT` header (and `PAYMENT-SIGNATURE`, same value). The server
   verifies the payment and returns the data as JSON.

The payment payload mirrors the service's own catalog-page Pay & Call flow,
which is the format verified working against the live service: authorization
values are strings in the JSON payload, `validAfter` is 60 seconds in the
past, the nonce is `0x` + 64 hex chars, the signature is `0x`-prefixed,
and the payload carries the accepted terms under `accepted`.

## Install

```bash
pip install -r requirements.txt
```

Dependencies, pinned: `eth-account==0.13.7`, `requests==2.32.3`. Python 3.10+.

## Library usage

```python
from client import X402Client

# Read-only: no key needed to inspect prices.
client = X402Client()
terms = client.get_payment_terms("/defi/gas-tracker")
print(terms["accepts"][0])  # amount "5000", payTo, network, asset ...

# Dry run: see exactly what a call would authorise, sign nothing.
# An ephemeral throwaway account fills in the `from` address — no key at all.
from eth_account import Account
dry = X402Client(account=Account.create())
print(dry.dry_run("/defi/gas-tracker"))
# {'dry_run': True, 'price_usdc': '0.005', 'pay_to': '0x...', ...,
#  'payment': {'x402Version': 2, ..., 'payload': {'signature': None, ...}}}

# Real call: pass an account explicitly. The key lives in memory only.
client = X402Client.from_private_key("0xYOUR_PRIVATE_KEY")
print(client.get_json("/defi/gas-tracker"))
```

Or with an `Account` object directly:

```python
from eth_account import Account
client = X402Client(account=Account.from_key("0xYOUR_PRIVATE_KEY"))
```

## CLI usage

```bash
# Free check — is the service up?
python cli.py health

# What does an endpoint cost? (no payment)
python cli.py terms /mcp/status
python cli.py terms /defi/gas-tracker --json

# Dry run — print the payment payload, sign nothing, spend nothing.
python cli.py call /defi/gas-tracker --dry-run

# Real paid call. Key via --private-key or X402_PRIVATE_KEY.
python cli.py call /defi/gas-tracker --private-key 0xYOUR_PRIVATE_KEY

# List all endpoints with prices.
python cli.py catalog --limit 20
```

Every command accepts `--base-url` to point at a different x402 service.

## Keys — read this first

- This library **never reads a private key from disk or the environment**.
  You pass it explicitly. The CLI accepts `--private-key` or the
  `X402_PRIVATE_KEY` environment variable.
- Only ever use a key for a **dedicated low-balance wallet** — never your
  main wallet, never paste a key into a shared terminal, and never commit
  one. A pay-per-call wallet holding a few dollars of USDC is the right
  shape: worst case, a leaked key loses the small balance, not your funds.
- Dry runs need no key at all: the CLI creates an ephemeral throwaway
  account in memory (`Account.create()`) just to fill in the `from` field.

## What this is — and what it is not

**It is:**

- A minimal client for the x402 v2 `"exact"` scheme: 402 decoding,
  EIP-3009 authorization building, EIP-712 signing, paid retry.
- Verified against the live service: `/health` returns 200, paid endpoints
  return 402 with decodable terms, and the signed authorization recovers
  to the signing account (see Tests).

**It is not:**

- A server or a paywall — see
  [manteclaw-x402](https://github.com/manteclaw/manteclaw-x402) for the
  service side, or
  [x402-flask-gate](https://github.com/manteclaw/x402-flask-gate) for a
  minimal gate template.
- A wallet: it holds no funds and never broadcasts a transaction. The
  facilitator submits the authorized transfer after verifying the signature.
- A guarantee the facilitator will accept a given payment — a signature is
  only valid while the wallet holds enough USDC on Base and inside the
  payment's validity window (default 300 seconds). A 402 after payment
  means the signature was rejected or the balance is short; sign a fresh
  one and retry.

## Tests

```bash
pip install -r requirements.txt
python -m unittest test_client -v
```

Live tests hit `https://manteclaw-x402.fly.dev` and skip themselves if the
service is unreachable. They never spend money: the only signing uses
ephemeral throwaway accounts created in memory, and no paid call is ever
completed — dry runs stop before signing, and the signature-recovery test
signs a payment for an empty throwaway wallet that holds no USDC.

What the tests verify against the live service:

- `GET /health` returns 200 with `endpoints: 100`.
- `GET /mcp/status` returns 402 with a decodable `payment-required`
  header: amount `"1000"` ($0.001), network `eip155:8453`, asset USDC on
  Base, `payTo` the service wallet, scheme `"exact"`.
- The dry-run payload built from those live terms matches them exactly
  (`to`, `value`, nonce format, 60s backdate + 300s window).
- An EIP-712 signature over the authorization recovers to the signing
  account — proving the domain, types and field encoding are correct.

## License

MIT — see [LICENSE](LICENSE).
