#!/usr/bin/env python3
"""
PDG CREATOR-PROVENANCE STAMP  v1.0.0
=====================================
Stakes a dated, tamper-evident claim of authorship over a Cognitive Layer.

This is the same move as the manifesto (content + timestamp = priority evidence),
made repeatable and machine-verifiable for every Layer you author.

THE HASH BOUNDARY (this is the whole point):
  - Components 1-8 of the Cognitive Layer are canonicalized and SHA-256 hashed.
    That hash IS the immutable creator-IP fingerprint, bound to your author identity.
  - <issued_to> is NEVER inside that hash. It is stamped per-delivery, in a
    SEPARATE log, at inject time -> per-buyer leak attribution without touching
    the creator-IP fingerprint.

THE CHAIN:
  - Each stamp links to the previous one (prev_entry_hash). Altering any past
    record breaks every record after it. The newest entry_hash is the CHAIN HEAD.
  - Anchor the chain head externally (publish it / commit it / drop it on the
    manifesto site) to get a third-party dated record. That is your priority lock.

No external dependencies. Python 3 stdlib only. You run it; you own the logs.
"""

import argparse
import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timezone

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
PROVENANCE_LOG = "provenance_log.jsonl"      # append-only creator-IP chain
DELIVERY_LOG   = "delivery_log.jsonl"        # append-only issued_to attribution
GENESIS_HASH   = "0" * 64                     # prev_entry_hash of the first stamp

# The 8 components that make up the hashed creator-IP fingerprint (schema v1.0.0).
# Order of this tuple does NOT affect the hash (keys are sorted on canonicalize);
# it documents the spec.
LAYER_COMPONENTS = (
    "layer_id",          # 1
    "version",           # 2
    "domain",            # 3
    "author",            # 4  (your identity is INSIDE the hash by design)
    "frameworks",        # 5
    "vocabulary",        # 6
    "decision_patterns", # 7
    "heuristics",        # 8
)


# ----------------------------------------------------------------------------
# Core crypto helpers
# ----------------------------------------------------------------------------
def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def canonical(obj) -> str:
    """
    Deterministic serialization. Same content -> same bytes -> same hash,
    on any machine, any day. Dict keys are sorted; LIST ORDER IS PRESERVED
    (order of frameworks/vocabulary/heuristics is meaningful content).
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def content_hash_of_layer(layer: dict) -> str:
    """Hash ONLY the 8 spec components. Anything else in the file is ignored."""
    missing = [c for c in LAYER_COMPONENTS if c not in layer]
    if missing:
        raise ValueError(f"Layer is missing required component(s): {missing}")
    core = {c: layer[c] for c in LAYER_COMPONENTS}   # strips any stray fields
    return sha256_hex(canonical(core))


# ----------------------------------------------------------------------------
# Append-only log helpers
# ----------------------------------------------------------------------------
def read_jsonl(path: str) -> list:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def append_jsonl(path: str, record: dict) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(canonical(record) + "\n")


def chain_head(log: list) -> str:
    return log[-1]["entry_hash"] if log else GENESIS_HASH


# ----------------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------------
def cmd_stamp(args):
    with open(args.layer, "r", encoding="utf-8") as f:
        layer = json.load(f)

    ch = content_hash_of_layer(layer)
    log = read_jsonl(PROVENANCE_LOG)

    # Refuse to double-stamp identical content (idempotent on content).
    for rec in log:
        if rec["content_hash"] == ch:
            print(f"ALREADY STAMPED  seq={rec['seq']}  at {rec['stamped_at_utc']}")
            print(f"content_hash: {ch}")
            print("No new entry written (content is byte-identical to an existing stamp).")
            return

    prev = chain_head(log)
    body = {
        "seq": len(log),
        "stamped_at_utc": now_utc(),
        "layer_id": layer["layer_id"],
        "version": layer["version"],
        "author": layer["author"],
        "content_hash": ch,
        "prev_entry_hash": prev,
    }
    entry_hash = sha256_hex(canonical(body))
    record = {**body, "entry_hash": entry_hash}
    append_jsonl(PROVENANCE_LOG, record)

    print("STAMPED")
    print(f"  layer_id     : {layer['layer_id']}  v{layer['version']}")
    print(f"  author       : {layer['author']}")
    print(f"  stamped_at   : {body['stamped_at_utc']}")
    print(f"  content_hash : {ch}")
    print(f"  seq          : {body['seq']}")
    print(f"  CHAIN HEAD   : {entry_hash}")
    print()
    print("  -> Anchor that CHAIN HEAD externally for a dated third-party record.")


def cmd_verify(args):
    log = read_jsonl(PROVENANCE_LOG)
    if not log:
        print("Provenance log is empty. Nothing to verify.")
        return

    prev = GENESIS_HASH
    ok = True
    for i, rec in enumerate(log):
        # 1. sequence integrity
        if rec["seq"] != i:
            print(f"FAIL seq mismatch at line {i}: stored seq={rec['seq']}")
            ok = False
        # 2. chain linkage
        if rec["prev_entry_hash"] != prev:
            print(f"FAIL broken link at seq={rec['seq']}: prev does not match.")
            ok = False
        # 3. entry hash recomputation
        body = {k: rec[k] for k in (
            "seq", "stamped_at_utc", "layer_id", "version",
            "author", "content_hash", "prev_entry_hash")}
        recomputed = sha256_hex(canonical(body))
        if recomputed != rec["entry_hash"]:
            print(f"FAIL tampered record at seq={rec['seq']}: entry_hash does not recompute.")
            ok = False
        prev = rec["entry_hash"]

    if ok:
        print(f"CHAIN OK  ({len(log)} stamp(s))")
        print(f"CHAIN HEAD: {chain_head(log)}")
    else:
        print("CHAIN INTEGRITY FAILED — log has been altered.")
        sys.exit(1)


def cmd_check(args):
    """Given a layer file, prove (or disprove) it matches a stamped record."""
    with open(args.layer, "r", encoding="utf-8") as f:
        layer = json.load(f)
    ch = content_hash_of_layer(layer)
    log = read_jsonl(PROVENANCE_LOG)
    for rec in log:
        if rec["content_hash"] == ch:
            print("MATCH — this exact content was stamped.")
            print(f"  seq        : {rec['seq']}")
            print(f"  stamped_at : {rec['stamped_at_utc']}")
            print(f"  author     : {rec['author']}")
            print(f"  content_hash: {ch}")
            return
    print("NO MATCH — this content does not appear in the provenance log.")
    print(f"  computed content_hash: {ch}")
    sys.exit(1)


def cmd_deliver(args):
    """
    Stamp a per-buyer delivery. issued_to lives HERE, OUTSIDE the creator-IP hash.
    This is the leak-attribution layer: if a stamped layer leaks, the issued_to
    on the delivery record tells you which buyer's copy it was.
    """
    log = read_jsonl(PROVENANCE_LOG)
    if not any(r["content_hash"] == args.content_hash for r in log):
        print(f"REFUSED — content_hash not found in provenance log:\n  {args.content_hash}")
        print("Stamp the layer first, then deliver it.")
        sys.exit(1)

    record = {
        "delivery_id": str(uuid.uuid4()),
        "delivered_at_utc": now_utc(),
        "content_hash": args.content_hash,   # references the immutable creator IP
        "issued_to": args.issued_to,         # buyer identity — OUTSIDE the hash boundary
    }
    append_jsonl(DELIVERY_LOG, record)
    print("DELIVERY STAMPED")
    print(f"  delivery_id : {record['delivery_id']}")
    print(f"  delivered   : {record['delivered_at_utc']}")
    print(f"  issued_to   : {record['issued_to']}")
    print(f"  content_hash: {record['content_hash']}")


def cmd_head(args):
    log = read_jsonl(PROVENANCE_LOG)
    print(chain_head(log))


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
def main():
    p = argparse.ArgumentParser(
        prog="provenance",
        description="PDG creator-provenance stamp — dated, tamper-evident authorship claims.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stamp", help="Stamp a Cognitive Layer (hash 1-8 + chain).")
    s.add_argument("layer", help="Path to layer JSON file.")
    s.set_defaults(func=cmd_stamp)

    v = sub.add_parser("verify", help="Verify the whole chain's integrity.")
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser("check", help="Prove a layer file matches a stamped record.")
    c.add_argument("layer", help="Path to layer JSON file.")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("deliver", help="Stamp a per-buyer delivery (issued_to, outside hash).")
    d.add_argument("content_hash", help="content_hash of the stamped layer.")
    d.add_argument("issued_to", help="Buyer identity / handle.")
    d.set_defaults(func=cmd_deliver)

    h = sub.add_parser("head", help="Print the current chain head.")
    h.set_defaults(func=cmd_head)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
