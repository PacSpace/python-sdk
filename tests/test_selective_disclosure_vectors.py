"""Record hash v2 and record-disclosure/v1 against selective-disclosure-v1.json.

Every case with ``expected`` is asserted; the cases without one hold only
keccak-level values (``expectedChain``), and their number must equal the
file's ``chainOnlyCaseCount``. The envelope cases are opened with
``cryptography`` (test-only; tests/requirements-test.txt) and are never
skipped. The vectors are a byte-for-byte copy of the shared file, which the
generator's ``--check`` compares.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pacspace_sdk import verify_record_disclosure_v1, verify_record_link_copy_v1
from pacspace_sdk.record_disclosure import (
    _disclosure_form_of,
    canonicalize_jcs,
    commit_record_content_v2,
    compute_leaf_hash_v2,
    compute_record_disclosure_digest_v1,
    derive_leaf_salt_v2,
    record_leaves_v2,
)

VECTORS = Path(__file__).parent / "vectors"
FILE = json.loads((VECTORS / "selective-disclosure-v1.json").read_text(encoding="utf-8"))
LINK_COPIES = json.loads((VECTORS / "record-link-copy-v1.json").read_text(encoding="utf-8"))
CASE_IDS = [c["id"] for c in FILE["cases"]]

CHAIN_CHECK_NOTE = (
    "This check covers each shown field up to its record hash and compares it with the record's seal history. "
    "It does not check the seal or the ledger; run @pacspace-io/check for that."
)
NOTE_V1 = "This entry was sealed before record hash v2; check it with @pacspace-io/check."

# --------------------------------------------------- envelope (test-only, section 7)

PAD_BLOCK = FILE["constants"]["padBlock"]
ENVELOPE_MAX_CHARS = FILE["constants"]["envelopeMaxChars"]
AAD_LABEL = b"pacspace:record-disclosure:v1"
B64URL = re.compile(r"[A-Za-z0-9_-]*")
FRAGMENT = re.compile(r"dk=([A-Za-z0-9_-]{43})")
ENVELOPE_REASONS = {
    "DISCLOSURE_ENVELOPE_MALFORMED": "This link's sealed disclosure is not in a form this version can open.",
    "DISCLOSURE_ENVELOPE_TOO_LARGE": "This link's sealed disclosure is larger than a disclosure may be.",
    "DISCLOSURE_ENVELOPE_AUTH_FAILED": (
        "This disclosure could not be opened with this link. The link may be incomplete, "
        "or the disclosure belongs to another link."
    ),
}


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(text: str) -> Optional[bytes]:
    """Canonical unpadded base64url only: decoding and re-encoding gives the same text."""
    if B64URL.fullmatch(text) is None or len(text) % 4 == 1:
        return None
    data = base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))
    return data if b64url_encode(data) == text else None


def envelope_shape(text: Any) -> Dict[str, Any]:
    """Steps 1 and 2 of the envelope's refusals: size, encoding, version byte, padded length."""
    if not isinstance(text, str):
        return {"ok": False, "code": "DISCLOSURE_ENVELOPE_MALFORMED"}
    if len(text) > ENVELOPE_MAX_CHARS:
        return {"ok": False, "code": "DISCLOSURE_ENVELOPE_TOO_LARGE"}
    data = b64url_decode(text)
    if data is None or not data or data[0] != 0x01:
        return {"ok": False, "code": "DISCLOSURE_ENVELOPE_MALFORMED"}
    cipher_length = len(data) - 29
    if cipher_length <= 0 or cipher_length % PAD_BLOCK != 0:
        return {"ok": False, "code": "DISCLOSURE_ENVELOPE_MALFORMED"}
    return {"ok": True, "byteLength": len(data)}


def aad_of(handle: str) -> bytes:
    return AAD_LABEL + b"\x00" + handle.encode("utf-8")


def padded(text: str) -> bytes:
    data = text.encode("utf-8")
    size = -(-len(data) // PAD_BLOCK) * PAD_BLOCK
    return data + b" " * (size - len(data))


def seal_raw(plain: bytes, key_hex: str, iv: bytes, handle: str) -> str:
    return b64url_encode(b"\x01" + iv + AESGCM(bytes.fromhex(key_hex)).encrypt(iv, plain, aad_of(handle)))


def open_envelope(text: str, key_hex: str, handle: str) -> Dict[str, Any]:
    """Section 7's decryption, in its order of refusals."""
    shape = envelope_shape(text)
    if not shape["ok"]:
        return {"ok": False, "code": shape["code"], "reason": ENVELOPE_REASONS[shape["code"]]}
    data = b64url_decode(text)
    try:
        plain = AESGCM(bytes.fromhex(key_hex)).decrypt(data[1:13], data[13:], aad_of(handle))
    except InvalidTag:
        code = "DISCLOSURE_ENVELOPE_AUTH_FAILED"
        return {"ok": False, "code": code, "reason": ENVELOPE_REASONS[code]}
    malformed = {"ok": False, "code": "DISCLOSURE_ENVELOPE_MALFORMED", "reason": ENVELOPE_REASONS["DISCLOSURE_ENVELOPE_MALFORMED"]}
    trimmed = plain.rstrip(b" ")
    if len(plain) - len(trimmed) >= PAD_BLOCK:
        return malformed
    try:
        disclosure = json.loads(trimmed.decode("utf-8"))
        if canonicalize_jcs(disclosure).encode("utf-8", "surrogatepass") != trimmed:
            return malformed
    except (UnicodeDecodeError, ValueError):
        return malformed
    return {"ok": True, "disclosure": disclosure}


def read_fragment(text: str) -> Optional[bytes]:
    match = FRAGMENT.fullmatch(text[1:] if text.startswith("#") else text)
    if match is None:
        return None
    key = b64url_decode(match.group(1))
    return key if key is not None and len(key) == 32 else None


# ------------------------------------------------------------------ the cases


def generated(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {rule["member"]: list(range(rule["length"]))}


def apply_fill(fill: Optional[Dict[str, Any]], disclosure: Dict[str, Any], verdict: Optional[Dict[str, Any]] = None) -> None:
    if not fill:
        return
    value = fill["char"] * fill["length"]
    entry = next(e for e in disclosure["entries"] if e["seq"] == fill["seq"])
    next(leaf for leaf in entry["revealed"] if leaf["pointer"] == fill["pointer"])["value"] = value
    expected = next((e for e in (verdict or {}).get("entries", []) if e["seq"] == fill["seq"]), None)
    if expected is not None:
        next(f for f in expected["fields"] if f["pointer"] == fill["pointer"])["value"] = value
        if expected.get("content"):
            expected["content"][fill["pointer"][1:]] = value


class SelectiveDisclosureVectorsTest(unittest.TestCase):
    """One method per kind; each returns the ids it asserted."""

    def check_case(self, c: Dict[str, Any]) -> bool:
        kind, inp, exp = c["kind"], c["input"], c.get("expected")
        if exp is None:
            return False
        handler = getattr(self, "kind_" + kind.replace("-", "_"))
        handler(c, inp, exp)
        return True

    def kind_leaf_rule(self, c, inp, exp) -> None:
        content = inp.get("content") or generated(inp["generate"])
        fields = record_leaves_v2(content)
        self.assertEqual(len(fields), exp["n"], c["id"])
        if "fields" in exp:
            self.assertEqual(fields, exp["fields"], c["id"])
        if "recordHash" in exp:
            self.assertEqual(commit_record_content_v2(content, inp["saltKey"])["recordHash"], exp["recordHash"], c["id"])

    def kind_leaf_rule_reject(self, c, inp, exp) -> None:
        content = inp["content"] if "content" in inp else generated(inp["generate"])
        self.assertTrue(exp["refused"])
        with self.assertRaises(ValueError, msg=c["id"]):
            record_leaves_v2(content)

    def kind_leaf_salt(self, c, inp, exp) -> None:
        self.assertEqual(derive_leaf_salt_v2(inp["saltKey"], inp["pointer"]), exp["salt"], c["id"])

    def kind_leaf_hash(self, c, inp, exp) -> None:
        value = json.loads(inp["valueJson"])
        self.assertEqual(canonicalize_jcs([inp["pointer"], value]), exp["jcs"], c["id"])
        self.assertEqual(compute_leaf_hash_v2({"pointer": inp["pointer"], "value": value, "salt": inp["salt"]}), exp["leafHash"], c["id"])

    def kind_record_hash_v2(self, c, inp, exp) -> None:
        # A layout case's content is the writer's (an attempt gains attemptedTarget and ruleId, which
        # `expected.content` gives); building the word and seal from it is keccak-level.
        content = inp.get("content", exp.get("content", (inp.get("report") or {}).get("content")))
        key = inp.get("saltKey") or inp.get("rowSaltKey")
        committed = commit_record_content_v2(content, key)
        self.assertEqual(committed, {"leaves": exp["leaves"], "revealed": exp["revealed"], "recordHash": exp["recordHash"]}, c["id"])

    def kind_row_receipt(self, c, inp, exp) -> None:
        row = inp["row"]
        committed = commit_record_content_v2(row["recordContent"], row["saltKey"])
        self.assertEqual(committed["leaves"], exp["leaves"], c["id"])
        self.assertEqual(committed["revealed"], exp["revealed"], c["id"])
        self.assertEqual(committed["recordHash"], exp["recordHash"], c["id"])
        self.assertEqual(row["recordHash"], exp["recordHash"], c["id"])

    def kind_disclosure(self, c, inp, exp) -> None:
        for disclosure in copy.deepcopy(inp.get("disclosures") or [inp["disclosure"]]):
            verdict = copy.deepcopy(exp.get("verdict"))
            apply_fill(inp.get("fill"), disclosure, verdict)
            result = verify_record_disclosure_v1(inp["form"], disclosure)
            self.assertEqual(result["chainCheck"], "not-checked", c["id"])
            self.assertEqual(result["chainCheckNote"], CHAIN_CHECK_NOTE, c["id"])
            if "python" in exp:
                got = {"ok": result["ok"], "entries": [{"seq": e["seq"], "status": e["status"]} for e in result["entries"]]}
                self.assertEqual(got, exp["python"], c["id"])
                self.assertIsNone(result["code"], c["id"])
            elif verdict["ok"]:
                got = {
                    "ok": result["ok"],
                    "entries": [
                        {"seq": e["seq"], "fields": e["fields"], "withheld": e["withheld"], "content": e["content"]}
                        for e in result["entries"]
                    ],
                }
                self.assertEqual(got, verdict, c["id"])
            else:
                got = {"ok": result["ok"], "code": result["code"], "seq": result["seq"], "reason": result["reason"]}
                self.assertEqual(got, verdict, c["id"])

    kind_disclosure_reject = kind_disclosure

    def kind_disclosure_digest(self, c, inp, exp) -> None:
        rest = {k: v for k, v in inp["disclosure"].items() if k != "digest"}
        self.assertEqual(canonicalize_jcs(rest), exp["jcsWithoutDigest"], c["id"])
        self.assertEqual((b"pacspace:record-disclosure-digest:v1" + b"\x00").hex(), exp["prefixHex"], c["id"])
        self.assertEqual(compute_record_disclosure_digest_v1(inp["disclosure"]), exp["digest"], c["id"])

    def kind_envelope(self, c, inp, exp) -> None:
        disclosure = copy.deepcopy(inp["disclosure"])
        apply_fill(inp.get("fill"), disclosure)
        plain = padded(canonicalize_jcs(disclosure))
        if "envelope" in exp:
            self.assertEqual(seal_raw(plain, inp["keyHex"], bytes.fromhex(inp["ivHex"]), inp["handle"]), exp["envelope"], c["id"])
            opened = AESGCM(bytes.fromhex(inp["keyHex"])).decrypt(
                b64url_decode(exp["envelope"])[1:13], b64url_decode(exp["envelope"])[13:], aad_of(inp["handle"])
            )
            self.assertEqual(len(opened), exp["plaintextLength"], c["id"])
            self.assertEqual(hashlib.sha256(opened).hexdigest(), exp["plaintextSha256"], c["id"])
            self.assertEqual(envelope_shape(exp["envelope"]), exp["shape"], c["id"])
            self.assertEqual(open_envelope(exp["envelope"], inp["keyHex"], inp["handle"]), {"ok": True, "disclosure": disclosure}, c["id"])
            return
        if "envelopeLength" in exp:
            envelope = seal_raw(plain, inp["keyHex"], bytes.fromhex(inp["ivHex"]), inp["handle"])
            self.assertEqual(len(envelope), exp["envelopeLength"], c["id"])
            self.assertEqual(hashlib.sha256(envelope.encode("ascii")).hexdigest(), exp["envelopeSha256"], c["id"])
            self.assertEqual(envelope_shape(envelope), exp["shape"], c["id"])
            self.assertEqual(open_envelope(envelope, inp["keyHex"], inp["handle"]), {"ok": True, "disclosure": disclosure}, c["id"])
            return
        envelope = seal_raw(plain, inp["keyHex"], os.urandom(12), inp["handle"])
        data = b64url_decode(envelope)
        self.assertEqual(data[0], exp["firstByte"], c["id"])
        self.assertEqual(len(data) - 29, exp["plaintextLength"], c["id"])
        self.assertEqual(envelope_shape(envelope), exp["shape"], c["id"])
        self.assertEqual(open_envelope(envelope, inp["keyHex"], inp["handle"]), {"ok": True, "disclosure": disclosure}, c["id"])

    def kind_envelope_reject(self, c, inp, exp) -> None:
        if "envelopes" in inp:
            envelopes = inp["envelopes"]
        elif "fill" in inp:
            envelopes = [inp["fill"]["char"] * inp["fill"]["length"]]
        else:
            envelopes = [inp["envelope"]]
        for envelope in envelopes:
            self.assertEqual(envelope_shape(envelope), exp["shape"], c["id"])
            self.assertEqual(open_envelope(envelope, inp["keyHex"], inp["handle"]), exp["result"], c["id"])

    def kind_fragment_key(self, c, inp, exp) -> None:
        for text in inp.get("keyTexts") or [inp["keyText"]]:
            key = read_fragment(f"{inp['prefix']}{text}{inp['suffix']}")
            self.assertEqual(None if key is None else key.hex(), exp["keyHex"], c["id"])
        if "fragment" in exp:
            self.assertEqual("dk=" + b64url_encode(bytes.fromhex(inp["keyHex"])), exp["fragment"]["prefix"] + exp["fragment"]["keyText"])

    def test_every_case_with_expected_and_the_chain_only_count(self) -> None:
        asserted: List[str] = []
        unasserted: List[str] = []
        for c in FILE["cases"]:
            with self.subTest(case=c["id"]):
                (asserted if self.check_case(c) else unasserted).append(c["id"])
        self.assertEqual(len(asserted) + len(unasserted), FILE["caseCount"])
        self.assertEqual(len(unasserted), FILE["chainOnlyCaseCount"])
        self.assertEqual(
            sorted(unasserted),
            sorted(["XV-01", "XV-02", "D-03", "DX-06", "DX-07", "DX-16", "DX-24", "DX-25", "DX-26"]),
        )

    def test_the_suite_names_every_case(self) -> None:
        # The coverage gate reads these literal ids (scripts/records/check-vector-coverage.mjs).
        named = [
            "LR-01", "LR-02", "LR-03", "LR-04", "LR-05", "LR-06", "LRX-01", "LRX-02", "LRX-03", "LRX-04",
            "LS-01", "LS-02", "LS-03", "LH-01", "LH-02", "LH-03", "LH-04", "LH-05", "LH-06", "LH-07", "LH-08",
            "LH-09", "LH-10", "LH-11", "LH-12", "RH-01", "RH-02", "RH-03", "RH-04", "RR-01", "D-01", "D-02",
            "DX-23", "DX-27", "D-04", "DX-01", "DX-02", "DX-03", "DX-04", "DX-05", "DX-08", "DX-09", "DX-10",
            "DX-11", "DX-12", "DX-13", "DX-14", "DX-15", "DX-17", "DX-18", "DX-19", "DX-20", "DX-21", "DX-22",
            "E-01", "E-02", "E-03", "EX-01", "EX-02", "EX-03", "EX-04", "EX-05", "EX-06", "EX-07", "EX-08",
            "EX-09", "EX-10", "EX-11", "EX-12", "EX-13", "EX-14", "EX-15", "FK-01", "FK-02", "FK-03", "FK-04",
            "FK-05",
        ]
        with_expected = sorted(c["id"] for c in FILE["cases"] if "expected" in c)
        self.assertEqual(sorted(named), with_expected)


def case(case_id: str) -> Dict[str, Any]:
    return copy.deepcopy(next(c for c in FILE["cases"] if c["id"] == case_id))


class DisclosureResultTest(unittest.TestCase):
    """R2 v5 section 7's result (L1d Proved by 18)."""

    def test_d02_against_a_form_with_every_record_hash_is_ok(self) -> None:
        c = case("D-02")
        result = verify_record_disclosure_v1(c["input"]["form"], c["input"]["disclosure"])
        self.assertIs(result["ok"], True)
        self.assertEqual([e["status"] for e in result["entries"]], ["checked", "checked"])
        self.assertTrue(all(e["note"] is None for e in result["entries"]))
        self.assertIsNone(result["code"])

    def test_dx27_checks_seq_0_only_and_answers_none(self) -> None:
        c = case("DX-27")
        result = verify_record_disclosure_v1(c["input"]["form"], c["input"]["disclosure"])
        self.assertIsNone(result["ok"])
        self.assertIsNone(result["code"])
        self.assertEqual([(e["seq"], e["status"]) for e in result["entries"]], [(0, "checked"), (1, "not-checked")])
        self.assertEqual(
            result["entries"][1]["note"],
            "The record's sealed history gives no record hash for this entry to compare with; check it with @pacspace-io/check.",
        )

    def test_a_v1_disclosure_alone_is_not_checked(self) -> None:
        c = case("D-03")
        result = verify_record_disclosure_v1(c["input"]["form"], c["input"]["disclosure"])
        self.assertIsNone(result["ok"])
        self.assertIsNone(result["code"])
        self.assertEqual([e["status"] for e in result["entries"]], ["not-checked"])
        self.assertEqual(result["entries"][0]["note"], NOTE_V1)

    def test_a_leaf_mismatch_is_refused(self) -> None:
        c = case("DX-01")
        result = verify_record_disclosure_v1(c["input"]["form"], c["input"]["disclosure"])
        self.assertIs(result["ok"], False)
        self.assertEqual(result["code"], "DISCLOSURE_LEAF_MISMATCH")

    def test_a_record_hash_mismatch_is_refused_with_the_step_6_3_reason(self) -> None:
        c = case("DX-04")
        result = verify_record_disclosure_v1(c["input"]["form"], c["input"]["disclosure"])
        self.assertIs(result["ok"], False)
        self.assertEqual(result["code"], "DISCLOSURE_SEAL_MISMATCH")
        self.assertEqual(result["reason"], "Entry 1 of this disclosure does not match the record hash in the record's sealed history.")

    def test_every_result_says_the_seal_and_ledger_are_not_checked(self) -> None:
        for c in FILE["cases"]:
            if c["kind"] not in ("disclosure", "disclosure-reject"):
                continue
            for disclosure in c["input"].get("disclosures") or [c["input"]["disclosure"]]:
                result = verify_record_disclosure_v1(c["input"]["form"], disclosure)
                self.assertEqual((result["chainCheck"], result["chainCheckNote"]), ("not-checked", CHAIN_CHECK_NOTE), c["id"])
        for junk in (None, 1, "x", [], {"schema": "record-disclosure/v1"}):
            result = verify_record_disclosure_v1({}, junk)
            self.assertEqual((result["ok"], result["code"], result["chainCheck"]), (False, "DISCLOSURE_MALFORMED", "not-checked"))


# disclosureFormOfV1's form for the kept copies that carry a disclosure, as the SHA-256 of its JCS;
# packages/shared/src/records/record-link-copy-v1.test.ts pins TypeScript's form to the same digests.
FORM_SHA256 = {
    "LC-02": "dd49de96ca7e3b9e4264559bc7b1818a0432cc6783a1396851a20f929e462f10",
    "LC-03": "c42ab1e9746070f1ea9703baeddde8e9dddb0570712a771c48d6bd9e25f5c0b3",
}


class LinkCopyTest(unittest.TestCase):
    def link_copy(self, case_id: str) -> Dict[str, Any]:
        c = next(x for x in LINK_COPIES["cases"] if x["id"] == case_id)
        return {"schema": "record-link-copy/v1", "sealHistory": c["input"]["sealHistory"], "disclosure": c["input"]["disclosure"]}

    def test_the_form_python_builds_equals_typescripts(self) -> None:
        for case_id, digest in FORM_SHA256.items():
            kept = self.link_copy(case_id)
            form = _disclosure_form_of(kept["sealHistory"], kept["disclosure"])
            self.assertEqual(hashlib.sha256(canonicalize_jcs(form).encode("utf-8")).hexdigest(), digest, case_id)

    def test_a_kept_copy_gives_its_disclosures_result_against_its_seal_history(self) -> None:
        for case_id in FORM_SHA256:
            kept = self.link_copy(case_id)
            form = _disclosure_form_of(kept["sealHistory"], kept["disclosure"])
            self.assertEqual(verify_record_link_copy_v1(kept), verify_record_disclosure_v1(form, kept["disclosure"]), case_id)
        self.assertIs(verify_record_link_copy_v1(self.link_copy("LC-02"))["ok"], True)

    def test_a_kept_copy_with_no_disclosure_or_another_shape_is_refused(self) -> None:
        for kept in (self.link_copy("LC-01"), {"schema": "record-link-copy/v1"}, None, []):
            result = verify_record_link_copy_v1(kept)
            self.assertEqual((result["ok"], result["code"]), (False, "DISCLOSURE_MALFORMED"))


if __name__ == "__main__":
    unittest.main()
