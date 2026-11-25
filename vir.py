"""Verifiable inference records: early prototype.

One record per model answer. Each record holds keyed tags of input and output
(no plaintext), model identifier and settings, a time stamp and the hash of the
previous record. Records are written as one JSON object per line and form a
chain. Any change, deletion or reordering is found by verify_chain.

Status: early prototype, not security reviewed. Do not use in production.
"""
import argparse
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone

VERSION = 1
GENESIS = "0" * 64


def canonical(obj):
    """Deterministic encoding used for hashing: sorted keys, no spaces, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def tag(content_key, label, data):
    """Keyed tag of content. label separates input tags from output tags."""
    return hmac.new(content_key, label + b"\x00" + data, hashlib.sha256).hexdigest()


def record_hash(chain_key, body):
    return hmac.new(chain_key, canonical(body), hashlib.sha256).hexdigest()


class ChainWriter:
    """Appends records to a file and continues an existing chain."""

    def __init__(self, path, chain_key, content_key, key_id="k1"):
        self.path = path
        self.chain_key = chain_key
        self.content_key = content_key
        self.key_id = key_id
        self.index = 0
        self.prev = GENESIS
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        rec = json.loads(line)
                        self.index = rec["index"] + 1
                        self.prev = rec["hash"]
        except FileNotFoundError:
            pass

    def append(self, model_id, params, input_bytes, output_bytes, timestamp=None):
        body = {
            "version": VERSION,
            "index": self.index,
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "model_id": model_id,
            "params": params,
            "input_tag": tag(self.content_key, b"in", input_bytes),
            "output_tag": tag(self.content_key, b"out", output_bytes),
            "key_id": self.key_id,
            "prev": self.prev,
        }
        rec = dict(body)
        rec["hash"] = record_hash(self.chain_key, body)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        self.index += 1
        self.prev = rec["hash"]
        return rec


def verify_chain(path, chain_key):
    """Check the whole chain without any content. Returns (ok, errors)."""
    errors = []
    prev = GENESIS
    expected_index = 0
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                claimed = rec.pop("hash")
            except (ValueError, KeyError):
                errors.append("line %d: not a valid record" % n)
                return False, errors
            if rec.get("index") != expected_index:
                errors.append("line %d: index %r, expected %d (deleted or reordered)" % (n, rec.get("index"), expected_index))
            if rec.get("prev") != prev:
                errors.append("line %d: link to previous record does not match" % n)
            if not hmac.compare_digest(record_hash(chain_key, rec), claimed):
                errors.append("line %d: record hash does not match (changed or wrong key)" % n)
            prev = claimed
            expected_index += 1
    return (not errors), errors


def match_content(record, content_key, input_bytes, output_bytes):
    """True if the given original text belongs to this record."""
    return (
        hmac.compare_digest(record["input_tag"], tag(content_key, b"in", input_bytes))
        and hmac.compare_digest(record["output_tag"], tag(content_key, b"out", output_bytes))
    )


def _read_key(path):
    with open(path, "r", encoding="utf-8") as f:
        return bytes.fromhex(f.read().strip())


def main(argv=None):
    p = argparse.ArgumentParser(description="Verify a chain of inference records.")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify a chain file")
    v.add_argument("chain")
    v.add_argument("--chain-key-file", required=True, help="file holding the chain key as hex")
    args = p.parse_args(argv)
    ok, errors = verify_chain(args.chain, _read_key(args.chain_key_file))
    if ok:
        print("chain ok")
        return 0
    for e in errors:
        print(e)
    return 1


if __name__ == "__main__":
    sys.exit(main())
