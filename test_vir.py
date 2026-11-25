import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import vir

CK = bytes.fromhex("11" * 32)
TK = bytes.fromhex("22" * 32)


def make_chain(path, n=4):
    w = vir.ChainWriter(path, CK, TK)
    recs = [w.append("model-a", {"bits": 8}, b"in%d" % i, b"out%d" % i, timestamp="2027-06-01T10:00:0%dZ" % i) for i in range(n)]
    return recs


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "chain.jsonl")

    def lines(self):
        with open(self.path, encoding="utf-8") as f:
            return f.read().splitlines()

    def write(self, lines):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def test_valid_chain(self):
        make_chain(self.path)
        ok, errors = vir.verify_chain(self.path, CK)
        self.assertTrue(ok, errors)

    def test_no_plaintext_stored(self):
        make_chain(self.path)
        with open(self.path, encoding="utf-8") as f:
            text = f.read()
        self.assertNotIn("in0", text.replace("input_tag", ""))
        self.assertNotIn("out0", text.replace("output_tag", ""))

    def test_changed_field_detected(self):
        make_chain(self.path)
        ls = self.lines()
        rec = json.loads(ls[1])
        rec["model_id"] = "model-b"
        ls[1] = json.dumps(rec, sort_keys=True)
        self.write(ls)
        self.assertFalse(vir.verify_chain(self.path, CK)[0])

    def test_deleted_record_detected(self):
        make_chain(self.path)
        ls = self.lines()
        del ls[1]
        self.write(ls)
        self.assertFalse(vir.verify_chain(self.path, CK)[0])

    def test_reordered_records_detected(self):
        make_chain(self.path)
        ls = self.lines()
        ls[1], ls[2] = ls[2], ls[1]
        self.write(ls)
        self.assertFalse(vir.verify_chain(self.path, CK)[0])

    def test_truncated_tail_is_not_detected_by_chain_alone(self):
        # Known limit: removing the last record leaves a valid shorter chain.
        # Planned fix: periodic signed checkpoints, see SPECIFICATION.md.
        make_chain(self.path)
        ls = self.lines()
        self.write(ls[:-1])
        self.assertTrue(vir.verify_chain(self.path, CK)[0])

    def test_wrong_key_fails(self):
        make_chain(self.path)
        self.assertFalse(vir.verify_chain(self.path, bytes.fromhex("33" * 32))[0])

    def test_content_match(self):
        recs = make_chain(self.path)
        self.assertTrue(vir.match_content(recs[0], TK, b"in0", b"out0"))
        self.assertFalse(vir.match_content(recs[0], TK, b"in0", b"other"))

    def test_writer_continues_chain(self):
        make_chain(self.path, 2)
        w = vir.ChainWriter(self.path, CK, TK)
        w.append("model-a", {"bits": 4}, b"x", b"y", timestamp="2027-06-02T10:00:00Z")
        ok, errors = vir.verify_chain(self.path, CK)
        self.assertTrue(ok, errors)
        self.assertEqual(len(self.lines()), 3)


if __name__ == "__main__":
    unittest.main()
