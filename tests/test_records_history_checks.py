"""What Python checks on a history before it opens anything (David's rulings of
11 and 15 November 2026): the history's own digest, the layout it was written
under, and whether its seals reproduce; and what history(), bundle(),
keep_copy(), rekey(), check() and open() do with each answer.

The histories are the door proof captured on Sandbox under layout 8 and the
shared vectors. A changed history is made by changing the real one; a history
"under layout 6" is the real one rewritten to name layout 6 with its digest
recomputed, as the TypeScript tests make theirs."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from records_encrypted_support import (
    VECTOR_KEYRING,
    VECTOR_KEYRING_V1,
    FakeEncryptedApi,
    bundle_digest,
    disclosure_link,
    door_proof_bundle,
    vector_histories,
)

from pacspace_sdk import PacSpace, PacSpaceError, memory_pin_store
from pacspace_sdk import records_encryption as R
from pacspace_sdk.encrypted_records import AEAD
from pacspace_sdk.keccak import keccak256
from pacspace_sdk.record_disclosure import canonicalize_jcs, verify_record_link_copy_v1

KEY_A, KEY_C = "pk_test_A.SECRET", "pk_test_C.SECRET"
OWNER = "cfixtureworkspacea0000001"
DIGEST_SENTENCE = "Bundle digest does not match the bundle contents."
SEAL_SENTENCE = "The sealed record does not recompute to the seal tag carried by the word."
LAYOUT_SENTENCE = "This file was written under a record layout this version does not read, so it could not be checked."
LINK_COPIES = json.loads((Path(__file__).resolve().parent / "vectors" / "record-link-copy-v1.json").read_text(encoding="utf-8"))


def ring_of(text: str) -> R.RecordsKeyring:
    return R.RecordsKeyring.from_provider(R.local_records_key_provider(text))


def key_of(bundle: Dict[str, Any]) -> R.RecordKey:
    return R.record_key_of(ring_of(VECTOR_KEYRING_V1).by_version(1), bundle["entityId"])


def redigest(bundle: Dict[str, Any]) -> Dict[str, Any]:
    bundle["bundleDigest"] = bundle_digest(bundle)
    return bundle


def code_of(result: Dict[str, Any]) -> Any:
    return None if result["ok"] else result["code"]


def changed(value: Any) -> Any:
    """Another value of the same JSON kind."""
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value + 1
    if isinstance(value, str):
        return value + "x"
    if isinstance(value, list):
        return value + [copy.deepcopy(value[0])] if value else [0]
    if isinstance(value, dict):
        return {**value, "added": 1}
    return 0


def under_layout_6(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """The history rewritten to name layout 6 throughout, digest recomputed."""
    bundle["layout"]["layoutId"] = 6
    bundle["layout"]["layoutVersion"] = 1
    for receipt in bundle["receipts"]:
        receipt["layoutId"] = 6
        receipt["layoutVersion"] = 1
    return redigest(bundle)


def with_one_seal_broken(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """One entry's record opening changed, digest recomputed: every envelope
    still opens and matches its record hash, and one seal does not reproduce."""
    receipt = next(r for r in bundle["receipts"] if r["seq"] == 1)
    opening = receipt["recordOpening"]
    receipt["recordOpening"] = opening[:-1] + ("0" if opening[-1] != "0" else "1")
    return redigest(bundle)


def setup(bundle: Dict[str, Any], secret: str = VECTOR_KEYRING_V1) -> Tuple[FakeEncryptedApi, PacSpace]:
    api = FakeEncryptedApi()
    api.add_workspace(KEY_A, OWNER)
    api.add_workspace(KEY_C, "cfixtureworkspacec0000001")
    api.serve_history(OWNER, bundle)
    a = PacSpace(KEY_A, base_url="https://api.test", max_retries=0, transport=api, records={"secret": secret, "pin_store": memory_pin_store()})
    a.records.identity.register()
    return api, a


def outcome(result: Dict[str, Any]) -> Tuple[Any, Any, Any]:
    return result["ok"], result["failedCheck"], result["reason"]


class DigestTest(unittest.TestCase):
    def test_the_packages_digest_is_typescripts_on_every_real_history(self) -> None:
        door = door_proof_bundle()
        self.assertEqual(R.compute_history_bundle_digest(door), door["bundleDigest"])
        histories = vector_histories()
        self.assertGreaterEqual(len(histories), 20)
        for case_id, history, code in histories:
            with self.subTest(case=case_id):
                if code == "RECORD_HISTORY_DIGEST":
                    self.assertNotEqual(R.compute_history_bundle_digest(history), history["bundleDigest"])
                else:
                    self.assertEqual(R.compute_history_bundle_digest(history), history["bundleDigest"])

    def test_the_untouched_history_and_its_copy_still_open(self) -> None:
        bundle = door_proof_bundle()
        result = R.open_record_history_v3(AEAD, bundle, key_of(bundle))
        self.assertTrue(result["ok"], result)
        self.assertIs(result["sealsVerified"], True)

    def test_every_member_the_digest_covers_changed_in_turn_is_refused(self) -> None:
        bundle = door_proof_bundle()
        covered = [k for k in R.digestable_history_bundle(bundle) if k not in ("schema",)]
        self.assertGreater(len(covered), 6)
        for member in covered:
            with self.subTest(member=member):
                other = door_proof_bundle()
                other[member] = changed(other[member])
                self.assertEqual(code_of(R.open_record_history_v3(AEAD, other, key_of(bundle))), "RECORD_HISTORY_DIGEST")

    def test_one_value_changed_inside_a_receipt_the_layout_and_an_envelope_is_refused(self) -> None:
        def receipt_member(b: Dict[str, Any]) -> None:
            b["receipts"][0]["batchId"] = changed(b["receipts"][0]["batchId"])

        def layout_member(b: Dict[str, Any]) -> None:
            b["layout"]["name"] = changed(b["layout"]["name"])

        def envelope_character(b: Dict[str, Any]) -> None:
            ct = b["receipts"][1]["envelopes"][0]["ct"]
            b["receipts"][1]["envelopes"][0]["ct"] = ("B" if ct[0] == "A" else "A") + ct[1:]

        def refused_envelope(b: Dict[str, Any]) -> None:
            ct = b["refused"][0]["envelope"]["ct"]
            b["refused"][0]["envelope"]["ct"] = ("B" if ct[0] == "A" else "A") + ct[1:]

        def the_digest_itself(b: Dict[str, Any]) -> None:
            d = b["bundleDigest"]
            b["bundleDigest"] = d[:-1] + ("0" if d[-1] != "0" else "1")

        for change in (receipt_member, layout_member, envelope_character, refused_envelope, the_digest_itself):
            with self.subTest(change=change.__name__):
                bundle = door_proof_bundle()
                change(bundle)
                self.assertEqual(code_of(R.open_record_history_v3(AEAD, bundle, key_of(bundle))), "RECORD_HISTORY_DIGEST")

    def test_what_the_digest_does_not_cover_may_change(self) -> None:
        bundle = door_proof_bundle()
        bundle["entries"] = []
        bundle["pendingEntries"] = [{"seq": None, "status": "queued"}]
        bundle["nextFromSeq"] = 9
        bundle["receipts"][0].update({"status": "failed", "code": "X", "sentence": "Y"})
        self.assertTrue(R.open_record_history_v3(AEAD, bundle, key_of(bundle))["ok"])

    def test_a_history_served_with_no_digest_is_read_as_before(self) -> None:
        bundle = door_proof_bundle()
        del bundle["bundleDigest"]
        self.assertTrue(R.open_record_history_v3(AEAD, bundle, key_of(bundle))["ok"])

    def test_a_digest_that_is_not_a_string_is_refused_and_upper_case_hex_is_read(self) -> None:
        for value in (None, 7, True, [door_proof_bundle()["bundleDigest"]], {}):
            with self.subTest(value=repr(value)[:20]):
                bundle = door_proof_bundle()
                bundle["bundleDigest"] = value
                self.assertEqual(code_of(R.open_record_history_v3(AEAD, bundle, key_of(bundle))), "RECORD_HISTORY_DIGEST")
        bundle = door_proof_bundle()
        bundle["bundleDigest"] = "0x" + bundle["bundleDigest"][2:].upper()
        self.assertTrue(R.open_record_history_v3(AEAD, bundle, key_of(bundle))["ok"])

    def test_a_digest_that_cannot_be_computed_is_refused_and_nothing_is_raised(self) -> None:
        deep: Any = 0
        for _ in range(5000):
            deep = [deep]
        for extra in (float("nan"), float("inf"), 1e400, deep, {1: "a member name that is not a string"}):
            with self.subTest(extra=repr(extra)[:20]):
                bundle = door_proof_bundle()
                bundle["extra"] = extra
                self.assertEqual(code_of(R.open_record_history_v3(AEAD, bundle, key_of(bundle))), "RECORD_HISTORY_DIGEST")

    def test_the_digest_is_answered_before_any_receipt_is_looked_at(self) -> None:
        bundle = door_proof_bundle()
        bundle["receipts"][0]["schema"] = "semantic-receipt/v3"
        self.assertEqual(code_of(R.open_record_history_v3(AEAD, bundle, key_of(bundle))), "RECORD_HISTORY_DIGEST")
        self.assertEqual(code_of(R.open_record_history_v3(AEAD, redigest(bundle), key_of(bundle))), "RECORD_HISTORY_RECEIPT_FORM")

    def test_a_copy_whose_history_was_changed_is_refused(self) -> None:
        bundle = door_proof_bundle()
        kept = {"schema": "pacspace-record-copy/v1", "recordKey": R.b64url_encode(R.export_key_bytes(key_of(bundle))), "history": bundle}
        self.assertTrue(R.open_record_copy_v1(AEAD, copy.deepcopy(kept))["ok"])
        kept["history"]["exportedAt"] = changed(kept["history"]["exportedAt"])
        self.assertEqual(code_of(R.open_record_copy_v1(AEAD, kept)), "RECORD_HISTORY_DIGEST")


class LayoutTest(unittest.TestCase):
    def open(self, bundle: Dict[str, Any], key: Optional[R.RecordKey] = None) -> Any:
        return code_of(R.open_record_history_v3(AEAD, bundle, key or key_of(bundle)))

    def test_a_history_under_layout_6_is_not_read_and_nothing_is_opened(self) -> None:
        bundle = under_layout_6(door_proof_bundle())
        self.assertEqual(self.open(bundle), "RECORDS_LAYOUT_NOT_READ")
        # A key that opens nothing gets the same answer: the refusal comes before any envelope.
        self.assertEqual(self.open(bundle, R.record_key_from_bytes(b"\x01" * 32)), "RECORDS_LAYOUT_NOT_READ")
        kept = {"schema": "pacspace-record-copy/v1", "recordKey": R.b64url_encode(R.export_key_bytes(key_of(bundle))), "history": bundle}
        self.assertEqual(code_of(R.open_record_copy_v1(AEAD, kept)), "RECORDS_LAYOUT_NOT_READ")

    def test_the_same_history_with_its_digest_left_stale_is_reported_as_changed(self) -> None:
        bundle = door_proof_bundle()
        stale = bundle["bundleDigest"]
        under_layout_6(bundle)["bundleDigest"] = stale
        self.assertEqual(self.open(bundle), "RECORD_HISTORY_DIGEST")

    def test_a_layout_id_is_any_json_number(self) -> None:
        cases: List[Tuple[Any, Any]] = [(6.0, "RECORDS_LAYOUT_NOT_READ"), (8.0, None), (8.5, "RECORDS_LAYOUT_NOT_READ"), (0, "RECORDS_LAYOUT_NOT_READ")]
        for value, expected in cases:
            with self.subTest(value=value):
                bundle = door_proof_bundle()
                bundle["layout"]["layoutId"] = value
                self.assertEqual(self.open(redigest(bundle)), expected)

    def test_a_history_with_receipts_and_no_layout_id_to_read_is_not_in_a_form_read(self) -> None:
        def as_true(b: Dict[str, Any]) -> None:
            b["layout"]["layoutId"] = True

        def as_text(b: Dict[str, Any]) -> None:
            b["layout"]["layoutId"] = "8"

        def no_id(b: Dict[str, Any]) -> None:
            del b["layout"]["layoutId"]

        def no_layout(b: Dict[str, Any]) -> None:
            del b["layout"]

        def layout_null(b: Dict[str, Any]) -> None:
            b["layout"] = None

        for change in (as_true, as_text, no_id, no_layout, layout_null):
            with self.subTest(change=change.__name__):
                bundle = door_proof_bundle()
                change(bundle)
                self.assertEqual(self.open(redigest(bundle)), "RECORD_HISTORY_RECEIPT_FORM")

    def test_a_layout_6_history_relabelled_as_layout_8_is_not_read(self) -> None:
        bundle = under_layout_6(door_proof_bundle())
        bundle["layout"]["layoutId"] = 8
        bundle["layout"]["layoutVersion"] = 2
        self.assertEqual(self.open(redigest(bundle)), "RECORDS_LAYOUT_NOT_READ")

    def test_the_carried_layouts_digest_is_the_one_the_real_receipts_carry(self) -> None:
        from pacspace_sdk.record_disclosure import carried_layout

        bundle = door_proof_bundle()
        self.assertEqual(carried_layout(8), (2, bundle["receipts"][0]["layoutDigest"]))
        self.assertEqual(carried_layout(8.0), carried_layout(8))
        for other in (6, 6.0, 8.5, True, "8", None, float("nan")):
            self.assertIsNone(carried_layout(other))

    def test_a_receipt_that_does_not_name_the_carried_layout_by_id_version_and_digest_is_not_read(self) -> None:
        def another_id(r: Dict[str, Any]) -> None:
            r["layoutId"] = 6

        def a_float_id(r: Dict[str, Any]) -> None:
            r["layoutId"] = 6.0

        def another_version(r: Dict[str, Any]) -> None:
            r["layoutVersion"] = 1

        def another_digest(r: Dict[str, Any]) -> None:
            r["layoutDigest"] = "0x" + "ab" * 32

        def no_digest(r: Dict[str, Any]) -> None:
            del r["layoutDigest"]

        def no_id(r: Dict[str, Any]) -> None:
            del r["layoutId"]

        def id_as_true(r: Dict[str, Any]) -> None:
            r["layoutId"] = True

        def digest_as_number(r: Dict[str, Any]) -> None:
            r["layoutDigest"] = 7

        for index in (0, 3):
            for change in (another_id, a_float_id, another_version, another_digest):
                with self.subTest(receipt=index, change=change.__name__):
                    bundle = door_proof_bundle()
                    change(bundle["receipts"][index])
                    self.assertEqual(self.open(redigest(bundle)), "RECORDS_LAYOUT_NOT_READ")
            # A receipt that states no layout to hold it to is not in a form read.
            for change in (no_digest, no_id, id_as_true, digest_as_number):
                with self.subTest(receipt=index, change=change.__name__):
                    bundle = door_proof_bundle()
                    change(bundle["receipts"][index])
                    self.assertEqual(self.open(redigest(bundle)), "RECORD_HISTORY_RECEIPT_FORM")

    def test_upper_case_hex_in_a_receipts_layout_digest_is_read(self) -> None:
        bundle = door_proof_bundle()
        for receipt in bundle["receipts"]:
            receipt["layoutDigest"] = "0x" + receipt["layoutDigest"][2:].upper()
        result = R.open_record_history_v3(AEAD, redigest(bundle), key_of(bundle))
        self.assertEqual(code_of(result), None)


class SdkTest(unittest.TestCase):
    def raised(self, call: Callable[[], Any]) -> Tuple[str, str]:
        with self.assertRaises(PacSpaceError) as caught:
            call()
        return caught.exception.code, caught.exception.message

    def readers(self, api: FakeEncryptedApi, a: PacSpace, bundle: Dict[str, Any]) -> Dict[str, Callable[[], Any]]:
        wire = bundle["entityId"]
        return {
            "history": lambda: a.records.history(None, wire_record_id=wire),
            "bundle": lambda: a.records.bundle(None, wire_record_id=wire),
            "keep_copy": lambda: a.records.keep_copy(wire_record_id=wire),
            "rekey": lambda: a.records.rekey(wire_record_id=wire, to_version=2),
        }

    def each_reader(self, bundle: Dict[str, Any], expected: Tuple[str, str]) -> None:
        api, a = setup(bundle, VECTOR_KEYRING)
        for name, call in self.readers(api, a, bundle).items():
            with self.subTest(reader=name):
                api.requests.clear()
                self.assertEqual(self.raised(call), expected)
                # Nothing was written: a re-key sent no envelope and no wrap.
                self.assertEqual([r["method"] for r in api.requests if r["method"] != "GET"], [])

    def test_the_untouched_history_is_read_copied_and_checked(self) -> None:
        bundle = door_proof_bundle()
        api, a = setup(bundle)
        self.assertEqual(len(a.records.history(None, wire_record_id=bundle["entityId"])["opened"]), 3)
        kept = json.loads(a.records.keep_copy(wire_record_id=bundle["entityId"])["bytes"].decode("utf-8"))
        self.assertTrue(R.open_record_copy_v1(AEAD, kept)["ok"])
        self.assertEqual(outcome(a.records.check(bundle)), (True, None, None))

    def test_a_changed_history_is_refused_with_the_digest_sentence(self) -> None:
        bundle = door_proof_bundle()
        bundle["exportedAt"] = changed(bundle["exportedAt"])
        self.each_reader(bundle, ("RECORD_HISTORY_DIGEST", DIGEST_SENTENCE))
        _, a = setup(bundle)
        self.assertEqual(outcome(a.records.check(bundle)), (False, "schema", DIGEST_SENTENCE))

    def test_a_history_under_another_layout_is_not_read(self) -> None:
        bundle = under_layout_6(door_proof_bundle())
        self.each_reader(bundle, ("RECORDS_LAYOUT_NOT_READ", LAYOUT_SENTENCE))
        _, a = setup(bundle)
        checked = a.records.check(bundle)
        self.assertEqual(outcome(checked), (False, "semantic", LAYOUT_SENTENCE))
        self.assertTrue(all(row["kind"] is None for row in checked["entries"]))

    def test_a_history_whose_seals_do_not_reproduce_is_not_handed_back(self) -> None:
        bundle = with_one_seal_broken(door_proof_bundle())
        opened = R.open_record_history_v3(AEAD, bundle, key_of(bundle))
        self.assertTrue(opened["ok"])
        self.assertIs(opened["sealsVerified"], False)
        self.each_reader(bundle, ("RECORD_HISTORY_SEAL", SEAL_SENTENCE))
        _, a = setup(bundle)
        self.assertEqual(outcome(a.records.check(bundle)), (False, "semantic", SEAL_SENTENCE))

    def test_no_copy_is_written_of_a_history_that_carries_no_digest(self) -> None:
        bundle = door_proof_bundle()
        del bundle["bundleDigest"]
        api, a = setup(bundle)
        self.assertEqual(len(a.records.history(None, wire_record_id=bundle["entityId"])["opened"]), 3)
        code, _ = self.raised(lambda: a.records.keep_copy(wire_record_id=bundle["entityId"]))
        self.assertEqual(code, "RECORD_COPY_MALFORMED")
        for value in (None, 7):
            bundle["bundleDigest"] = value
            with self.assertRaises(PacSpaceError) as caught:
                a.records._encrypted().copy_of(bundle, key_of(bundle))
            self.assertEqual(caught.exception.code, "RECORD_COPY_MALFORMED")

    def test_the_sentence_list_is_unchanged(self) -> None:
        from pacspace_sdk.records_words import RECORDS_ENCRYPTION_WORDS

        self.assertEqual(len(RECORDS_ENCRYPTION_WORDS), 20)
        self.assertNotIn("RECORD_HISTORY_SEAL", RECORDS_ENCRYPTION_WORDS)
        self.assertNotIn("RECORD_HISTORY_DIGEST", RECORDS_ENCRYPTION_WORDS)


def plaintext_history(schema: str = "record-history-bundle/v1") -> Dict[str, Any]:
    """A plaintext history in the form the API serves, with a digest that
    recomputes. check() reads its entries and compares fingerprints; it
    checks no seal on a plaintext history."""
    door = door_proof_bundle()
    layout = door["layout"]
    receipt = {
        "schema": "semantic-receipt/v2",
        "seq": 0,
        "status": "committed",
        "layoutId": layout["layoutId"],
        "layoutVersion": layout["layoutVersion"],
        "layoutDigest": door["receipts"][0]["layoutDigest"],
        "recordContent": {"title": "t", "payloads": [{"alg": "sha-256", "digest": "a" * 64, "byteLength": "10"}]},
    }
    history = {
        "schema": schema,
        "recordKey": door["recordKey"],
        "layout": copy.deepcopy(layout),
        "receipts": [receipt],
        "entries": [{"seq": 0, "status": "committed"}],
        "exportedAt": "2026-11-15T00:00:00.000Z",
    }
    history["bundleDigest"] = "0x" + keccak256(canonicalize_jcs(R.digestable_history_bundle(history)).encode("utf-8")).hex()
    return history


class PlaintextCheckTest(unittest.TestCase):
    def check(self, history: Dict[str, Any]) -> Tuple[Any, Any, Any]:
        client = PacSpace(KEY_A, base_url="https://api.test", max_retries=0, transport=FakeEncryptedApi())
        return outcome(client.records.check(history))

    def test_each_plaintext_form(self) -> None:
        for schema in ("record-history-bundle/v1", "record-history-bundle/v2"):
            with self.subTest(schema=schema):
                self.assertEqual(self.check(plaintext_history(schema)), (True, None, None))

                changed_history = plaintext_history(schema)
                changed_history["receipts"][0]["recordContent"]["title"] = "another"
                self.assertEqual(self.check(changed_history), (False, "schema", DIGEST_SENTENCE))

                other_layout = plaintext_history(schema)
                other_layout["layout"]["layoutId"] = 6
                other_layout["receipts"][0]["layoutId"] = 6
                stale = dict(other_layout)
                self.assertEqual(self.check(stale), (False, "schema", DIGEST_SENTENCE))
                self.assertEqual(self.check(redigest(other_layout)), (False, "semantic", LAYOUT_SENTENCE))

                receipt_only = plaintext_history(schema)
                receipt_only["receipts"][0]["layoutId"] = 6.0
                self.assertEqual(self.check(redigest(receipt_only)), (False, "semantic", LAYOUT_SENTENCE))

                no_digest = plaintext_history(schema)
                del no_digest["bundleDigest"]
                self.assertEqual(self.check(no_digest), (True, None, None))

    def test_a_history_that_states_no_layout_is_read_as_before(self) -> None:
        history = plaintext_history()
        del history["layout"]
        del history["receipts"][0]["layoutId"]
        self.assertEqual(self.check(redigest(history)), (True, None, None))

    def test_the_digest_is_answered_ahead_of_a_failed_entry(self) -> None:
        history = plaintext_history()
        history["entries"].append({"seq": 1, "status": "failed", "sentence": "A queued write did not commit."})
        self.assertEqual(self.check(history), (False, "schema", "A queued write did not commit."))
        history["exportedAt"] = "2026-11-16T00:00:00.000Z"
        self.assertEqual(self.check(history), (False, "schema", DIGEST_SENTENCE))


def seal_redigest(form: Dict[str, Any]) -> Dict[str, Any]:
    rest = {k: v for k, v in form.items() if k != "digest"}
    form["digest"] = "0x" + keccak256(canonicalize_jcs(rest).encode("utf-8")).hex()
    return form


class LinkTest(unittest.TestCase):
    def link(self, form: Dict[str, Any], envelope: Any = "keep") -> Tuple[FakeEncryptedApi, PacSpace, str]:
        fixture = disclosure_link()
        api = FakeEncryptedApi()
        api.add_workspace(KEY_C, "cfixtureworkspacec0000001")
        api.links[fixture["handle"]] = {"form": form, "envelope": fixture["envelope"] if envelope == "keep" else envelope, "accessCode": None}
        reader = PacSpace(KEY_C, base_url="https://api.test", max_retries=0, transport=api)
        return api, reader, f"https://app.pacspace.io/c/{fixture['handle']}#{fixture['fragment']}"

    def test_the_fixtures_seal_history_carries_the_digest_python_computes(self) -> None:
        form = disclosure_link()["form"]
        before = form["digest"]
        self.assertEqual(seal_redigest(copy.deepcopy(form))["digest"], before)
        _, reader, url = self.link(form)
        self.assertEqual(len(reader.records.open(url)["entries"]), 2)

    def test_a_link_whose_seal_history_was_changed_is_refused(self) -> None:
        form = disclosure_link()["form"]
        form["currentWord"] = form["currentWord"][:-1] + ("0" if form["currentWord"][-1] != "0" else "1")
        for envelope in ("keep", None):
            with self.subTest(envelope=envelope):
                api, reader, url = self.link(copy.deepcopy(form), envelope)
                with self.assertRaises(PacSpaceError) as caught:
                    reader.records.open(url)
                self.assertEqual(caught.exception.code, "DISCLOSURE_MALFORMED")
                # Refused on what anyone with the link reads: no key wrap was asked for.
                self.assertEqual([r["url"].rsplit("/", 1)[1] for r in api.requests], ["history", "disclosure"])

    def test_a_link_under_another_layout_is_not_read_before_any_key(self) -> None:
        form = disclosure_link()["form"]
        form["layout"]["layoutId"] = 6
        seal_redigest(form)
        for envelope in ("keep", None):
            with self.subTest(envelope=envelope):
                api, reader, url = self.link(copy.deepcopy(form), envelope)
                with self.assertRaises(PacSpaceError) as caught:
                    reader.records.open(url if envelope else url.split("#")[0])
                self.assertEqual((caught.exception.code, caught.exception.message), ("RECORDS_LAYOUT_NOT_READ", LAYOUT_SENTENCE))
                self.assertEqual([r["url"].rsplit("/", 1)[1] for r in api.requests], ["history", "disclosure"])
        # With its digest left stale it is a changed file, not "not read".
        form["digest"] = disclosure_link()["form"]["digest"]
        _, reader, url = self.link(form)
        with self.assertRaises(PacSpaceError) as caught:
            reader.records.open(url)
        self.assertEqual(caught.exception.code, "DISCLOSURE_MALFORMED")

    def test_a_link_naming_a_carried_layout_with_another_version_or_digest_is_refused(self) -> None:
        """A carried id is not enough: the version and the digest beside it are
        the carried layout's, as in TypeScript (DISCLOSURE_MALFORMED there)."""
        digest = disclosure_link()["form"]["layout"]["layoutDigest"]
        other_digest = digest[:-1] + ("0" if digest[-1] != "0" else "1")
        for member, value in (
            ("layoutVersion", 1),
            ("layoutVersion", "2"),
            ("layoutVersion", None),
            ("layoutDigest", other_digest),
            ("layoutDigest", digest.upper()),
            ("layoutDigest", None),
        ):
            with self.subTest(member=member, value=value):
                form = disclosure_link()["form"]
                form["layout"][member] = value
                seal_redigest(form)
                api, reader, url = self.link(form)
                with self.assertRaises(PacSpaceError) as caught:
                    reader.records.open(url)
                self.assertEqual(caught.exception.code, "DISCLOSURE_MALFORMED")
                self.assertEqual([r["url"].rsplit("/", 1)[1] for r in api.requests], ["history", "disclosure"])

                kept = self.first_copy()
                kept["sealHistory"]["layout"][member] = value
                seal_redigest(kept["sealHistory"])
                result = verify_record_link_copy_v1(kept)
                self.assertEqual((result["ok"], result["code"]), (False, "DISCLOSURE_MALFORMED"))

    def first_copy(self) -> Dict[str, Any]:
        given = copy.deepcopy(next(c for c in LINK_COPIES["cases"] if c["id"] == "LC-02")["input"])
        return {"schema": "record-link-copy/v1", "sealHistory": given["sealHistory"], "disclosure": given["disclosure"]}

    def test_a_link_copy_is_held_to_its_seal_historys_digest_and_layout(self) -> None:
        kept = self.first_copy()
        self.assertIs(verify_record_link_copy_v1(copy.deepcopy(kept))["ok"], True)

        changed_copy = copy.deepcopy(kept)
        word = changed_copy["sealHistory"]["currentWord"]
        changed_copy["sealHistory"]["currentWord"] = word[:-1] + ("0" if word[-1] != "0" else "1")
        result = verify_record_link_copy_v1(changed_copy)
        self.assertEqual((result["ok"], result["code"]), (False, "DISCLOSURE_MALFORMED"))

        other = copy.deepcopy(kept)
        other["sealHistory"]["layout"]["layoutId"] = 6
        stale = copy.deepcopy(other)
        result = verify_record_link_copy_v1(stale)
        self.assertEqual((result["ok"], result["code"]), (False, "DISCLOSURE_MALFORMED"))
        seal_redigest(other["sealHistory"])
        result = verify_record_link_copy_v1(other)
        self.assertEqual((result["ok"], result["code"], result["reason"]), (False, "RECORDS_LAYOUT_NOT_READ", LAYOUT_SENTENCE))
        self.assertEqual(result["entries"], [])


if __name__ == "__main__":
    unittest.main()
