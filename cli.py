#!/usr/bin/env python3
"""CLI for the x402-python-client.

Usage:
    python cli.py health
        Free check — GET /health, print the service status.

    python cli.py terms <path-or-url>
        Show the 402 payment terms for an endpoint (price, payTo, network,
        asset) without paying anything.

    python cli.py call <path-or-url> [--dry-run] [--private-key KEY] [--json]
        Pay and call an endpoint. --dry-run prints the exact payment payload
        that would be signed, using an ephemeral throwaway account — no key
        needed, nothing signed, nothing spent.

    python cli.py catalog [--limit N]
        List the service's paid endpoints with their prices.

The private key can be passed with --private-key or the X402_PRIVATE_KEY
environment variable. Only use a key for a dedicated low-balance wallet —
never your main wallet, never paste a key into a shared terminal, and never
commit one. The key is held in memory only and is never written to disk.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from eth_account import Account

from client import (
    DEFAULT_BASE_URL,
    NoAccountError,
    PaymentRequired,
    X402Client,
    X402Error,
    format_usdc,
)


def _client_for_call(args, need_account: bool) -> X402Client:
    """Build a client; for real calls resolve the key, for dry runs use an
    ephemeral throwaway account (created in memory, never saved)."""
    if args.dry_run or not need_account:
        return X402Client(base_url=args.base_url, account=Account.create())
    key = args.private_key or os.environ.get("X402_PRIVATE_KEY")
    if not key:
        print(
            "No private key: pass --private-key or set X402_PRIVATE_KEY.\n"
            "Use a dedicated low-balance wallet — never your main wallet.",
            file=sys.stderr,
        )
        sys.exit(2)
    return X402Client.from_private_key(key, base_url=args.base_url)


def cmd_health(args) -> int:
    client = X402Client(base_url=args.base_url)
    r = client.get("/health", pay=False)
    print(json.dumps(r.json(), indent=2))
    return 0 if r.status_code == 200 else 1


def cmd_terms(args) -> int:
    client = X402Client(base_url=args.base_url)
    try:
        terms = client.get_payment_terms(args.target)
    except X402Error as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    accept = client.pick_accept(terms)
    print(f"URL:     {client.url(args.target)}")
    print(f"Price:   ${format_usdc(accept['amount'])} USDC")
    print(f"Pay to:  {accept['payTo']}")
    print(f"Network: {accept['network']}")
    print(f"Asset:   {accept['asset']} (USDC)")
    print(f"Scheme:  {accept['scheme']}")
    print(f"Timeout: {accept.get('maxTimeoutSeconds', 300)}s")
    if args.json:
        print(json.dumps(terms, indent=2))
    return 0


def cmd_call(args) -> int:
    client = _client_for_call(args, need_account=True)
    try:
        result = client.get(
            args.target,
            pay=not args.dry_run,
            dry_run=args.dry_run,
            valid_seconds=args.valid_seconds,
        )
    except PaymentRequired as exc:
        print(f"Payment required and not paid: {exc}", file=sys.stderr)
        return 1
    except NoAccountError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if isinstance(result, dict):  # dry run
        print(json.dumps(result, indent=2))
        return 0
    if result.status_code == 402:
        print(
            "Still 402 after payment — the signature was rejected or the "
            "wallet holds too little USDC. No retry was made.",
            file=sys.stderr,
        )
        return 1
    try:
        print(json.dumps(result.json(), indent=2))
    except ValueError:
        print(result.text)
    return 0 if result.status_code == 200 else 1


def cmd_catalog(args) -> int:
    client = X402Client(base_url=args.base_url)
    try:
        catalog = client.get_json("/.well-known/agent-catalog.json", pay=False)
    except X402Error as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    endpoints = catalog.get("assets") or catalog.get("endpoints") or (
        catalog if isinstance(catalog, list) else []
    )
    shown = 0
    for ep in endpoints:
        path = ep.get("endpoint", ep.get("path", ep.get("url", "?")))
        price = ep.get("price_usdc", ep.get("price", "?"))
        name = ep.get("name", ep.get("id", ""))
        print(f"${str(price):>7}  {path}" + (f"  ({name})" if name else ""))
        shown += 1
        if args.limit and shown >= args.limit:
            break
    print(f"\n{len(endpoints)} endpoints total (showing {shown}).")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Tiny client for x402 pay-per-call endpoints on Base.",
    )
    parser.add_argument(
        "--base-url", default=DEFAULT_BASE_URL,
        help=f"Service base URL (default: {DEFAULT_BASE_URL})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("health", help="Free check: GET /health.")

    p_terms = sub.add_parser("terms", help="Show the 402 terms for an endpoint.")
    p_terms.add_argument("target", help="Endpoint path or full URL, e.g. /mcp/status")
    p_terms.add_argument("--json", action="store_true", help="Also print raw terms JSON.")

    p_call = sub.add_parser("call", help="Pay and call an endpoint.")
    p_call.add_argument("target", help="Endpoint path or full URL, e.g. /defi/gas-tracker")
    p_call.add_argument("--private-key", help="Signing key (or set X402_PRIVATE_KEY).")
    p_call.add_argument(
        "--dry-run", action="store_true",
        help="Print the payment payload that would be signed; sign nothing, spend nothing.",
    )
    p_call.add_argument("--json", action="store_true", help="(accepted; output is JSON)")
    p_call.add_argument("--valid-seconds", type=int, default=None,
                        help="Payment validity window in seconds (default: terms' maxTimeoutSeconds).")

    p_cat = sub.add_parser("catalog", help="List endpoints with prices.")
    p_cat.add_argument("--limit", type=int, default=0, help="Max endpoints to show (0 = all).")

    args = parser.parse_args(argv)
    handlers = {
        "health": cmd_health,
        "terms": cmd_terms,
        "call": cmd_call,
        "catalog": cmd_catalog,
    }
    try:
        return handlers[args.command](args)
    except X402Error as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
