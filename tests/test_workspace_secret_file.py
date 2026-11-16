"""EN1 (D-20, 11 October item 1): Sandbox's workspace secret file is named
pacspace-workspace-secret-sandbox-v1.json, so it never shares a name with
Production's. The SDK reads it under either name; the mirror of the
TypeScript spec."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from records_encrypted_support import VECTOR_KEYRING, FakeEncryptedApi

from pacspace_sdk import (
    RECORDS_ENCRYPTION_WORDS,
    PacSpace,
    PacSpaceError,
    memory_pin_store,
    read_workspace_secret_file,
    workspace_secret_file_name,
)

KEY_A = "pk_test_A.SECRET"


class WorkspaceSecretFileNameTest(unittest.TestCase):
    def test_names_sandbox_for_its_environment_and_production_as_always(self) -> None:
        self.assertEqual(workspace_secret_file_name(1, "sandbox"), "pacspace-workspace-secret-sandbox-v1.json")
        self.assertEqual(workspace_secret_file_name(2, "production"), "pacspace-workspace-secret-v2.json")
        self.assertEqual(workspace_secret_file_name(3), "pacspace-workspace-secret-v3.json")
        with self.assertRaises(PacSpaceError) as caught:
            workspace_secret_file_name(0, "sandbox")
        self.assertEqual(str(caught.exception), RECORDS_ENCRYPTION_WORDS["RECORDS_SECRET_INVALID"])


class ReadWorkspaceSecretFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def write(self, name: str, text: str) -> Path:
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_reads_the_file_under_either_name_as_the_same_secret(self) -> None:
        sandbox = self.write(workspace_secret_file_name(1, "sandbox"), VECTOR_KEYRING)
        plain = self.write(workspace_secret_file_name(1), VECTOR_KEYRING)
        self.assertEqual(read_workspace_secret_file(sandbox), VECTOR_KEYRING)
        self.assertEqual(read_workspace_secret_file(str(plain)), VECTOR_KEYRING)

    def test_gives_records_secret_what_it_needs_an_encrypted_write_from_sandboxs_file(self) -> None:
        path = self.write(workspace_secret_file_name(1, "sandbox"), VECTOR_KEYRING)
        api = FakeEncryptedApi()
        api.add_workspace(KEY_A, "cfixtureworkspacea0000001")
        pac = PacSpace(
            KEY_A,
            base_url="https://api.test",
            max_retries=0,
            transport=api,
            records={"secret": read_workspace_secret_file(path), "pin_store": memory_pin_store()},
        )
        pac.records.identity.register()
        out = pac.records.emit(
            record="invoice-77",
            title="Encrypted entry",
            occurred_at="2026-10-05T12:00:00Z",
            actor_id="agent-7",
            payloads=[{"alg": "sha-256", "digest": "a" * 64, "byteLength": "10"}],
        )
        self.assertTrue(out["encrypted"])

    def test_refuses_a_file_that_is_not_a_workspace_secret(self) -> None:
        for text in ('{"schema":"pacspace-workspace-secret/v1","secrets":[]}', "not a secret"):
            path = self.write("pacspace-workspace-secret-sandbox-v9.json", text)
            with self.assertRaises(PacSpaceError) as caught:
                read_workspace_secret_file(path)
            self.assertEqual(caught.exception.code, "RECORDS_SECRET_INVALID")
            self.assertEqual(str(caught.exception), RECORDS_ENCRYPTION_WORDS["RECORDS_SECRET_INVALID"])

    def test_refuses_a_file_larger_than_any_workspace_secret(self) -> None:
        path = self.write("large.json", " " * (64 * 1024 + 1))
        with self.assertRaises(PacSpaceError) as caught:
            read_workspace_secret_file(path)
        self.assertEqual(caught.exception.code, "RECORDS_SECRET_INVALID")

    def test_refuses_bytes_that_are_not_utf8(self) -> None:
        path = self.root / "binary.json"
        path.write_bytes(b"\xff\xfe\x00")
        with self.assertRaises(PacSpaceError) as caught:
            read_workspace_secret_file(path)
        self.assertEqual(caught.exception.code, "RECORDS_SECRET_INVALID")


if __name__ == "__main__":
    unittest.main()
