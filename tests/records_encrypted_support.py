"""A fake of the encrypted-records routes (L2b to L2d1), as the TypeScript
SDK's test support has it: several workspaces, each by its API key;
identities, versions, holders and holdings; encrypted writes with the version
rule; histories served from a stored v3 bundle with re-keyed envelopes added;
grants with wraps; disclosure wraps; a disclosure link's public routes. Every
request is kept, whole, for the interception spec. Python does not check a
bundle's digest, so a served bundle's digest is left as it was."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlparse

from pacspace_sdk import records_asymmetric as A
from pacspace_sdk import records_encryption as R
from pacspace_sdk.client import TransportResponse

# Byte-for-byte copies of the monorepo's fixtures (scripts/docs/python-sdk-test-files.test.mjs
# holds them equal): the public repository receives only pacspace_sdk/ and tests/.
HERE = Path(__file__).resolve().parent / "vectors"
VECTORS = json.loads((HERE / "records-encryption-v1.json").read_text(encoding="utf-8"))
VECTOR_KEYRING: str = VECTORS["fixtures"]["keyring"]
VECTOR_KEYRING_V1: str = json.dumps({"schema": "pacspace-workspace-secret/v1", "secrets": [json.loads(VECTOR_KEYRING)["secrets"][0]]})


def admission_cases() -> List[Tuple[Dict[str, Any], Any]]:
    """Each case of record-admission-cases-v1.json with its content built."""
    doc = json.loads((HERE / "record-admission-cases-v1.json").read_text(encoding="utf-8"))
    out = []
    for case in doc["cases"]:
        if "content" in case:
            content = copy.deepcopy(case["content"])
        else:
            content = {**copy.deepcopy(doc["bases"][case["recordType"]]), **copy.deepcopy(case.get("set", {}))}
            for field in case.get("drop", []):
                content.pop(field, None)
        if case.get("bulk"):
            content["bulk"] = [0] * case["bulk"]
        out.append((case, content))
    return out


def door_proof_bundle() -> Dict[str, Any]:
    return json.loads((HERE / "encrypted-door-proof-sandbox-v1.json").read_text(encoding="utf-8"))


def disclosure_link() -> Dict[str, Any]:
    return json.loads((HERE / "disclosure-fixture.json").read_text(encoding="utf-8"))


def _answer(status: int, body: Any, headers: Optional[Dict[str, str]] = None) -> TransportResponse:
    return TransportResponse(status_code=status, headers={"content-type": "application/json", **(headers or {})}, body=json.dumps(body).encode("utf-8"))


def _ok(data: Any) -> TransportResponse:
    return _answer(200, {"success": True, "data": data})


def _refuse(status: int, code: str, **extra: Any) -> TransportResponse:
    return _answer(status, {"success": False, "error": {"code": code, "message": f"refused {code}", **extra}})


class FakeEncryptedApi:
    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.workspaces: Dict[str, Dict[str, Any]] = {}
        self.holders: List[Dict[str, Any]] = []
        self.grants: List[Dict[str, Any]] = []
        self.histories: Dict[str, Dict[str, Any]] = {}
        self.rekeyed: Dict[str, Dict[int, Any]] = {}
        self.writes: Dict[str, List[Dict[str, Any]]] = {}
        self.record_kid: Dict[str, str] = {}
        # Card 10, F1: intake's RECORDS_HASH_V3, and each encrypted record's stamp.
        self.hash_v3 = False
        self.record_hash_version: Dict[str, int] = {}
        # Card 10, F2: intake's idempotency claims on encrypted writes, when switched on.
        self.idempotency = False
        self.claims: Dict[str, Dict[str, Any]] = {}
        self.disclosure_wraps: List[Dict[str, Any]] = []
        self.substituted: Dict[str, Dict[str, str]] = {}
        self.own_key_swapped: Dict[str, str] = {}
        self.links: Dict[str, Dict[str, Any]] = {}
        self.fail: Optional[Any] = None
        self._next = 1
        # Card 10, F3: every PUT versions body, and a change counter folded into the holder set token.
        self.version_puts: List[Dict[str, Any]] = []
        self.holder_set_epoch = 0

    def holder_set_of(self, workspace_id: str) -> str:
        ids = sorted(h["holderId"] for h in self.holders if h["ownerWorkspaceId"] == workspace_id and h["scope"] == "workspace" and not h["removedAt"])
        return json.dumps([self.holder_set_epoch, ids])

    def _id(self) -> int:
        self._next += 1
        return self._next

    def add_workspace(self, api_key: str, workspace_id: str) -> None:
        self.workspaces[api_key] = {"apiKey": api_key, "workspaceId": workspace_id, "identity": None, "retired": [], "versions": {}}

    def by_id(self, workspace_id: str) -> Optional[Dict[str, Any]]:
        return next((w for w in self.workspaces.values() if w["workspaceId"] == workspace_id), None)

    def serve_history(self, owner: str, bundle: Dict[str, Any], as_entity_id: Optional[str] = None) -> None:
        self.histories[f"{bundle['recordType']}\0{as_entity_id or bundle['entityId']}"] = {"owner": owner, "bundle": bundle}

    def served_bundle(self, key: str) -> Optional[Dict[str, Any]]:
        entry = self.histories.get(key)
        if entry is None:
            return None
        swapped = self.rekeyed.get(key)
        if not swapped:
            return entry["bundle"]
        bundle = copy.deepcopy(entry["bundle"])
        for receipt in bundle["receipts"]:
            extra = swapped.get(receipt["seq"])
            if extra is not None and isinstance(receipt.get("envelopes"), list):
                receipt["envelopes"] = [receipt["envelopes"][0], extra]
        return bundle

    # ------------------------------------------------------------ transport

    def __call__(self, method: str, url: str, headers: Dict[str, str], body: Optional[str], timeout_ms: int) -> TransportResponse:
        lowered = {k.lower(): str(v) for k, v in headers.items()}
        self.requests.append({"method": method, "url": url, "headers": lowered, "body": body or ""})
        if self.fail is not None:
            self.fail(method, url)
        return self._handle(urlparse(url).path, method, lowered, json.loads(body) if body else None)

    def _handle(self, path: str, method: str, headers: Dict[str, str], body: Any) -> TransportResponse:
        link = re.fullmatch(r"/api/v1/c/([^/]+)/(history|disclosure|access/verify)", path)
        if link:
            served = self.links.get(unquote(link.group(1)))
            if served is None:
                return _refuse(404, "CUSTOMER_LINK_NOT_FOUND")
            if link.group(2) == "access/verify":
                if (body or {}).get("value") == served["accessCode"]:
                    return _answer(200, {"success": True}, {"set-cookie": "ps_link=session-1; Path=/; HttpOnly"})
                return _refuse(401, "CUSTOMER_LINK_ACCESS_DENIED")
            if served["accessCode"] and headers.get("cookie") != "ps_link=session-1":
                return _refuse(401, "CUSTOMER_LINK_ACCESS_REQUIRED")
            if link.group(2) == "history":
                return _answer(200, served["form"])
            return _answer(200, {"envelope": served["envelope"]}) if served["envelope"] else _refuse(404, "CUSTOMER_LINK_NOT_FOUND")

        caller = self.workspaces.get(headers.get("x-api-key", ""))
        if caller is None:
            return _refuse(401, "INVALID_API_KEY")
        enc = re.fullmatch(r"/api/v1/records/encryption/(.+)", path)
        if enc:
            return self._encryption(caller, enc.group(1), method, body)
        if path == "/api/v1/records/disclosures/key-wrap" and method == "POST":
            found = next((w for w in self.disclosure_wraps if w["handle"] == (body or {}).get("handle") and w["workspaceId"] == caller["workspaceId"]), None)
            if found is None:
                return _refuse(404, "RECORD_DISCLOSURE_WRAP_NOT_FOUND")
            return _ok({"ownerWorkspaceId": found["owner"], "pinnedId": found["pinnedId"], "wrap": found["wrap"]})
        rec = re.fullmatch(r"/api/v1/records/([^/]+)/([^/]+)/(.+)", path)
        if rec is None:
            return _refuse(404, "NOT_FOUND")
        record_type, entity_id, tail = unquote(rec.group(1)), unquote(rec.group(2)), rec.group(3).split("?")[0]
        key = f"{record_type}\0{entity_id}"
        grant_token = headers.get("x-pacspace-grant")
        holder_for = headers.get("x-pacspace-holder-for")

        if tail == "transitions" and method == "POST":
            if body.get("envelope"):
                declared = body.get("recordHashVersion", 2)
                if declared != (3 if self.hash_v3 else 2):
                    return _refuse(409, "RECORD_FORMAT_RETIRED") if self.hash_v3 and declared == 2 else _refuse(403, "RECORD_HASH_VERSION_NOT_ENABLED")
                stamped = self.record_hash_version.get(key)
                if stamped is not None and stamped != declared:
                    return _refuse(409, "RECORD_FORMAT_RETIRED") if stamped < declared else _refuse(403, "RECORD_HASH_VERSION_NOT_ENABLED")
                self.record_hash_version[key] = declared
                kid = body["envelope"]["kid"]
                claim: Optional[Dict[str, Any]] = None
                if self.idempotency:
                    claim_key = f"{caller['workspaceId']}\0{body.get('referenceId')}"
                    payload = json.dumps([record_type, entity_id, body.get("lifecycle"), body.get("contentTag")])
                    existing = self.claims.get(claim_key)
                    if existing and existing["payload"] != payload and not (existing["status"] == "FAILED" and existing["kid"] != kid):
                        return _refuse(409, "IDEMPOTENCY_CONFLICT", claimKid=existing["kid"])
                    if existing and existing["status"] == "COMPLETED":
                        return _ok(existing["response"])
                    claim = {"payload": payload, "kid": kid, "status": "PENDING"}
                    self.claims[claim_key] = claim
                held = self.record_kid.get(key)
                if held and held != kid:
                    if claim:
                        claim["status"] = "FAILED"
                    return _refuse(409, "RECORD_ENCRYPTION_VERSION_MISMATCH", recordKid=held)
                if kid not in caller["versions"].values():
                    if claim:
                        claim["status"] = "FAILED"
                    return _refuse(409, "RECORD_ENCRYPTION_VERSION_UNREGISTERED")
                self.record_kid[key] = kid
                if claim:
                    self.writes.setdefault(key, []).append({"owner": caller["workspaceId"], "body": body})
                    response = {"status": "QUEUED", "recordType": record_type, "entityId": entity_id, "recordKey": "0x" + "ab" * 32, "referenceId": body.get("referenceId"), "intakeId": f"in_{self._id()}"}
                    claim.update(status="COMPLETED", response=response)
                    return _ok(response)
            self.writes.setdefault(key, []).append({"owner": caller["workspaceId"], "body": body})
            return _ok({"status": "QUEUED", "recordType": record_type, "entityId": entity_id, "recordKey": "0x" + "ab" * 32, "referenceId": body.get("referenceId"), "intakeId": f"in_{self._id()}"})

        served = self.histories.get(key)

        def may_read() -> bool:
            if served is None:
                return False
            if served["owner"] == caller["workspaceId"] and not grant_token and not holder_for:
                return True
            if grant_token:
                return any(g["token"] == grant_token and g["status"] == "ACTIVE" and g["recordType"] == record_type and g["entityId"] == entity_id for g in self.grants)
            if holder_for:
                return served["owner"] == holder_for and any(
                    h["ownerWorkspaceId"] == holder_for and h["holderWorkspaceId"] == caller["workspaceId"] and not h["removedAt"] for h in self.holders
                )
            return False

        if tail in ("bundle", "history") and method == "GET":
            if not may_read():
                return _refuse(404, "RECORD_NOT_FOUND")
            if headers.get("x-pacspace-records-encryption") != "1":
                return _refuse(409, "RECORDS_ENCRYPTION_SUPPORT_REQUIRED")
            return _answer(200, self.served_bundle(key))
        receipt = re.fullmatch(r"receipts/(\d+)", tail)
        if receipt and method == "GET":
            if not may_read():
                return _refuse(404, "RECORD_NOT_FOUND")
            bundle = self.served_bundle(key)
            found = next((r for r in bundle["receipts"] if r["seq"] == int(receipt.group(1))), None)
            if found is None:
                return _refuse(404, "RECEIPT_NOT_FOUND")
            return _ok({"recordType": bundle["recordType"], "entityId": bundle["entityId"], "receipt": found, "verify": {}})
        swap = re.fullmatch(r"entries/(\d+)/envelope", tail)
        if swap and method == "PUT":
            if served is None or served["owner"] != caller["workspaceId"] or grant_token or holder_for:
                return _refuse(403, "RECORD_REKEY_OWNER_ONLY")
            self.rekeyed.setdefault(key, {})[int(swap.group(1))] = body["envelope"]
            return _ok({"seq": int(swap.group(1)), "kid": body["envelope"]["kid"], "recordCompleted": False})
        if tail == "grants" and method == "POST":
            if body.get("readerWrap") and (body["readerWrap"].get("wrap") or {}).get("v") != 2:
                return _refuse(400, "RECORD_WRAP_MALFORMED")
            grant = {
                "grantId": f"grt_{self._id()}",
                "token": f"rgt_test_{self._id()}",
                "owner": caller["workspaceId"],
                "recordType": record_type,
                "entityId": entity_id,
                "kind": body["kind"],
                "status": "ACTIVE",
                "counterpartyWorkspaceId": body.get("counterpartyTenantId"),
                "readerWrap": body.get("readerWrap"),
            }
            self.grants.append(grant)
            answer = {"grantId": grant["grantId"], "grant": grant["token"]}
            if grant["readerWrap"]:
                answer["readerWrap"] = {"pinnedId": grant["readerWrap"]["pinnedId"], "rkid": grant["readerWrap"]["rkid"]}
            return _ok(answer)
        if tail == "grants" and method == "GET":
            return _ok(
                {
                    "grants": [
                        {
                            "grantId": g["grantId"],
                            "kind": g["kind"],
                            "status": g["status"],
                            "counterpartyWorkspaceId": g["counterpartyWorkspaceId"],
                            "readerWrap": {"pinnedId": g["readerWrap"]["pinnedId"], "rkid": g["readerWrap"]["rkid"]} if g["readerWrap"] else None,
                        }
                        for g in self.grants
                        if g["owner"] == caller["workspaceId"] and g["recordType"] == record_type and g["entityId"] == entity_id
                    ]
                }
            )
        grant_wrap = re.fullmatch(r"grants/([^/]+)/key-wrap", tail)
        if grant_wrap and method == "PUT":
            grant = next((g for g in self.grants if g["grantId"] == grant_wrap.group(1) and g["owner"] == caller["workspaceId"]), None)
            if grant is None:
                return _refuse(404, "RECEIPT_GRANT_NOT_FOUND")
            if (body.get("wrap") or {}).get("v") != 2:
                return _refuse(400, "RECORD_WRAP_MALFORMED")
            grant["readerWrap"] = {"pinnedId": body["pinnedId"], "rkid": body["rkid"], "wrap": body["wrap"]}
            return _ok({"grantId": grant["grantId"], "readerWrap": {"pinnedId": body["pinnedId"], "rkid": body["rkid"]}})
        revoke = re.fullmatch(r"grants/([^/]+)/revoke", tail)
        if revoke and method == "POST":
            grant = next((g for g in self.grants if g["grantId"] == revoke.group(1) and g["owner"] == caller["workspaceId"]), None)
            if grant is None:
                return _refuse(404, "RECEIPT_GRANT_NOT_FOUND")
            grant["status"], grant["readerWrap"] = "REVOKED", None
            return _ok({"grantId": grant["grantId"], "status": "REVOKED"})
        if tail == "grant-key" and method == "GET":
            grant = next(
                (g for g in self.grants if g["token"] == grant_token and g["status"] == "ACTIVE" and g["recordType"] == record_type and g["entityId"] == entity_id),
                None,
            )
            if grant is None or not grant["readerWrap"] or grant["counterpartyWorkspaceId"] != caller["workspaceId"]:
                return _refuse(404, "RECORD_GRANT_WRAP_NOT_FOUND")
            return _ok({"grantId": grant["grantId"], **grant["readerWrap"]})
        share = re.fullmatch(r"share/([^/]+)/key-wraps", tail)
        if share and method == "PUT":
            if (body.get("wrap") or {}).get("v") != 2:
                return _refuse(400, "RECORD_WRAP_MALFORMED")
            self.disclosure_wraps.append(
                {"handle": unquote(share.group(1)), "owner": caller["workspaceId"], "workspaceId": body["workspaceId"], "pinnedId": body["pinnedId"], "wrap": body["wrap"]}
            )
            return _ok({"readerWorkspaceId": body["workspaceId"], "pinnedId": body["pinnedId"], "stored": True})
        return _refuse(404, "NOT_FOUND")

    # Card 10, F4: the API's carried rule. A new version carries the current
    # key's seed and each retired key's with a seed wrap at the newest version.
    def _carried(self, w: Dict[str, Any]) -> List[str]:
        newest = max(w["versions"].keys(), default=0)
        ids = [w["identity"]["xwingPublicId"]] if w["identity"] else []
        return ids + [r["xwingPublicId"] for r in w["retired"] if any(s["version"] == newest for s in r["seedWraps"])]

    def _seed_wraps_refusal(self, w: Dict[str, Any], sent: Optional[Dict[str, Any]]) -> Optional[TransportResponse]:
        allowed = ([w["identity"]["xwingPublicId"]] if w["identity"] else []) + [r["xwingPublicId"] for r in w["retired"]]
        ids = list((sent or {}).keys())
        if any(i not in allowed for i in ids):
            return _refuse(409, "RECORDS_IDENTITY_SET_CHANGED")
        if any(i not in ids for i in self._carried(w)):
            return _refuse(409, "RECORDS_IDENTITY_SET_CHANGED" if ids else "RECORDS_WRAP_FORMAT_REQUIRED")
        return None

    @staticmethod
    def store_seed_wraps(w: Dict[str, Any], version: int, sent: Optional[Dict[str, Any]]) -> None:
        for key_id, wrap in (sent or {}).items():
            identity = w["identity"] if w["identity"] and w["identity"]["xwingPublicId"] == key_id else next(r for r in w["retired"] if r["xwingPublicId"] == key_id)
            identity["seedWraps"] = [*(s for s in identity["seedWraps"] if s["version"] != version), {"version": version, "wrap": wrap}]

    def replace_identity(self, api_key: str, version: int, kid: str, seed_wraps: Dict[str, Any], xwing_public: str) -> None:
        """What the key pages' replacement leaves (card 10, F4): the current key
        retired, the new one current, and the new version with both seeds."""
        w = self.workspaces[api_key]
        w["retired"].append({**w["identity"], "retiredAt": "2026-10-16T00:00:00.000Z"})
        w["identity"] = {"xwingPublic": xwing_public, "xwingPublicId": A.public_key_id(R.b64url_decode(xwing_public)), "seedWraps": []}
        w["versions"][version] = kid
        self.store_seed_wraps(w, version, seed_wraps)

    def _encryption(self, caller: Dict[str, Any], route: str, method: str, body: Any) -> TransportResponse:
        if route == "identity" and method == "GET":
            swapped = self.own_key_swapped.get(caller["workspaceId"])
            own = {"workspaceId": caller["workspaceId"], "holderSet": self.holder_set_of(caller["workspaceId"])}
            own["retiredIdentities"] = [dict(r) for r in caller["retired"]]
            if swapped and caller["identity"]:
                return _ok({**own, **caller["identity"], "xwingPublic": swapped})
            return _ok({**own, **(caller["identity"] or {"xwingPublic": None, "xwingPublicId": None, "seedWraps": []})})
        if route == "identity" and method == "PUT":
            public_id = A.public_key_id(R.b64url_decode(body["xwingPublic"]))
            if caller["identity"] and caller["identity"]["xwingPublicId"] != public_id:
                return _refuse(409, "RECORD_IDENTITY_CONFLICT")
            created = caller["identity"] is None
            if created:
                caller["identity"] = {"xwingPublic": body["xwingPublic"], "xwingPublicId": public_id, "seedWraps": []}
            version = body["seedWrap"]["version"]
            caller["identity"]["seedWraps"] = [*(w for w in caller["identity"]["seedWraps"] if w["version"] != version), body["seedWrap"]]
            return _ok({"xwingPublicId": public_id, "seedWrapVersion": version, "created": created})
        other = re.fullmatch(r"workspaces/([^/]+)/identity", route)
        if other and method == "GET":
            workspace_id = unquote(other.group(1))
            if workspace_id in self.substituted:
                return _ok({"workspaceId": workspace_id, **self.substituted[workspace_id]})
            w = self.by_id(workspace_id)
            if w is None or w["identity"] is None:
                return _refuse(404, "RECORD_IDENTITY_NOT_FOUND")
            return _ok({"workspaceId": workspace_id, "xwingPublic": w["identity"]["xwingPublic"], "xwingPublicId": w["identity"]["xwingPublicId"]})
        version = re.fullmatch(r"versions/(\d+)", route)
        if version and method == "PUT":
            v = int(version.group(1))
            held = caller["versions"].get(v)
            if held is not None and held != body["kid"]:
                return _refuse(409, "RECORD_ENCRYPTION_VERSION_CONFLICT")
            if held is None and v > 1 and body.get("wrapFormat") != 2:
                return _refuse(409, "RECORDS_WRAP_FORMAT_REQUIRED")
            if held is None:
                refused = self._seed_wraps_refusal(caller, body.get("seedWraps"))
                if refused is not None:
                    return refused
                self.store_seed_wraps(caller, v, body.get("seedWraps"))
            current = [h for h in self.holders if h["ownerWorkspaceId"] == caller["workspaceId"] and h["scope"] == "workspace" and not h["removedAt"]]
            if body.get("wrapFormat") == 2:
                if body.get("holderSet") != self.holder_set_of(caller["workspaceId"]):
                    return _refuse(409, "RECORDS_HOLDER_SET_CHANGED")
                for w in body.get("holderWraps") or []:
                    holder = next((h for h in current if h["holderId"] == w.get("holderId")), None)
                    if holder is None:
                        return _refuse(409, "RECORDS_HOLDER_SET_CHANGED")
                    if (w.get("wrap") or {}).get("v") != 2:
                        return _refuse(400, "RECORD_WRAP_MALFORMED")
                    if held is None:
                        holder["wraps"] = [*(x for x in holder["wraps"] if x["version"] != v), {"version": v, "wrap": w["wrap"], "rkid": None, "state": "stored"}]
            caller["versions"][v] = body["kid"]
            self.version_puts.append({"workspaceId": caller["workspaceId"], "version": v, "body": body})
            wrapped = {w.get("holderId") for w in body.get("holderWraps") or []}
            needing = [h["holderId"] for h in current if h["holderId"] not in wrapped]
            return _ok({"version": v, "kid": body["kid"], "created": held is None, "holdersNeedingConfirmation": needing})
        if route == "versions" and method == "GET":
            return _ok({"versions": [{"version": v, "kid": kid} for v, kid in caller["versions"].items()]})
        if route == "holders" and method == "POST":
            existing = next(
                (
                    h
                    for h in self.holders
                    if h["ownerWorkspaceId"] == caller["workspaceId"] and h["holderWorkspaceId"] == body["workspaceId"] and h["scope"] == body["scope"] and not h["removedAt"]
                ),
                None,
            )
            if existing:
                return _ok({"holderId": existing["holderId"], "created": False})
            holder = {
                "holderId": f"rhd_{self._id()}",
                "ownerWorkspaceId": caller["workspaceId"],
                "holderWorkspaceId": body["workspaceId"],
                "scope": body["scope"],
                "required": body["required"],
                "pinnedId": body["pinnedId"],
                "record": body.get("record"),
                "removedAt": None,
                "wraps": [],
            }
            self.holders.append(holder)
            return _ok({"holderId": holder["holderId"], "created": True})
        if route == "holders" and method == "GET":
            return _ok(
                {
                    "holderSet": self.holder_set_of(caller["workspaceId"]),
                    "holders": [
                        {**{k: v for k, v in h.items() if k != "wraps"}, "wraps": [{"version": w["version"], "state": w["state"]} for w in h["wraps"]]}
                        for h in self.holders
                        if h["ownerWorkspaceId"] == caller["workspaceId"]
                    ]
                }
            )
        remove = re.fullmatch(r"holders/([^/]+)", route)
        if remove and method == "DELETE":
            holder = next((h for h in self.holders if h["holderId"] == remove.group(1) and h["ownerWorkspaceId"] == caller["workspaceId"]), None)
            if holder is None:
                return _refuse(404, "RECORD_HOLDER_NOT_FOUND")
            holder["removedAt"] = "2026-10-05T12:00:00.000Z"
            return _ok({"holderId": holder["holderId"], "removedAt": holder["removedAt"]})
        wraps = re.fullmatch(r"holders/([^/]+)/wraps", route)
        if wraps and method == "PUT":
            holder = next((h for h in self.holders if h["holderId"] == wraps.group(1) and h["ownerWorkspaceId"] == caller["workspaceId"]), None)
            if holder is None:
                return _refuse(404, "RECORD_HOLDER_NOT_FOUND")
            if body["pinnedId"] != holder["pinnedId"]:
                return _refuse(409, "RECORD_HOLDER_PIN_MISMATCH")
            if (body.get("wrap") or {}).get("v") != 2:
                return _refuse(400, "RECORD_WRAP_MALFORMED")
            v = body.get("version")
            holder["wraps"] = [*(w for w in holder["wraps"] if w["version"] != v), {"version": v, "wrap": body["wrap"], "rkid": body.get("rkid"), "state": "stored"}]
            return _ok({"holderId": holder["holderId"], "version": v, "state": "stored", "stored": True})
        if route == "holdings" and method == "GET":
            out = []
            for h in self.holders:
                if h["holderWorkspaceId"] != caller["workspaceId"] or h["removedAt"]:
                    continue
                owner = self.by_id(h["ownerWorkspaceId"])
                out.append(
                    {
                        **{k: v for k, v in h.items() if k not in ("wraps", "removedAt")},
                        "wraps": [
                            {
                                "version": w["version"],
                                "kid": None if w["version"] is None or owner is None else owner["versions"].get(w["version"]),
                                "rkid": w["rkid"] if w["version"] is None else None,
                                "wrap": w["wrap"],
                                "state": w["state"],
                            }
                            for w in h["wraps"]
                        ],
                    }
                )
            return _ok({"holdings": out})
        holding = re.fullmatch(r"holdings/([^/]+)/(confirm|refuse)", route)
        if holding and method == "POST":
            holder = next((h for h in self.holders if h["holderId"] == holding.group(1) and h["holderWorkspaceId"] == caller["workspaceId"]), None)
            w = next((x for x in (holder or {}).get("wraps", []) if x["version"] == body.get("version")), None)
            if holder is None or w is None:
                return _refuse(404, "RECORD_HOLDING_NOT_FOUND")
            w["state"] = "confirmed" if holding.group(2) == "confirm" else "refused"
            if holding.group(2) == "refuse":
                w["reason"] = body.get("reason")
            return _ok({"holderId": holder["holderId"], "version": body.get("version"), "state": w["state"]})
        return _refuse(404, "NOT_FOUND")
