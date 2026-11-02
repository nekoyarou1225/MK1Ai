"""WebAuthn credential parsing helpers."""

from __future__ import annotations

import base64
import json
from typing import Any

from webauthn.helpers.structs import (
    AuthenticationCredential,
    RegistrationCredential,
)


def _b64url_decode(val: str) -> bytes:
    padded = val + "=" * (-len(val) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def parse_registration_credential_json(val: str | dict[str, Any]) -> RegistrationCredential:
    data = json.loads(val) if isinstance(val, str) else dict(val)
    cred_id = str(data.get("id", ""))
    raw_id_str = str(data.get("rawId", cred_id))
    raw_id = _b64url_decode(raw_id_str) if raw_id_str else b""
    response = data.get("response", {})
    if not isinstance(response, dict):
        raise ValueError("Invalid registration credential response")
    return RegistrationCredential(id=cred_id, raw_id=raw_id, response=response)


def parse_authentication_credential_json(val: str | dict[str, Any]) -> AuthenticationCredential:
    data = json.loads(val) if isinstance(val, str) else dict(val)
    cred_id = str(data.get("id", ""))
    raw_id_str = str(data.get("rawId", cred_id))
    raw_id = _b64url_decode(raw_id_str) if raw_id_str else b""
    response = data.get("response", {})
    if not isinstance(response, dict):
        raise ValueError("Invalid authentication credential response")
    return AuthenticationCredential(id=cred_id, raw_id=raw_id, response=response)
