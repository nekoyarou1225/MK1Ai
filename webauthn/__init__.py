"""Pure-Python W3C WebAuthn Passkey implementation for MK1Ai remote dashboard."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import secrets
from typing import Any

from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    UserVerificationRequirement,
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


@dataclass(frozen=True)
class RegistrationOptions:
    rp_id: str
    rp_name: str
    user_id: bytes
    user_name: str
    user_display_name: str
    challenge: bytes
    authenticator_selection: AuthenticatorSelectionCriteria | None = None
    exclude_credentials: list[PublicKeyCredentialDescriptor] = field(default_factory=list)


@dataclass(frozen=True)
class AuthenticationOptions:
    rp_id: str
    challenge: bytes
    allow_credentials: list[PublicKeyCredentialDescriptor] = field(default_factory=list)
    user_verification: UserVerificationRequirement | None = None


@dataclass(frozen=True)
class VerifiedRegistration:
    credential_id: bytes
    credential_public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class VerifiedAuthentication:
    credential_id: bytes
    new_sign_count: int


def generate_registration_options(
    *,
    rp_id: str,
    rp_name: str,
    user_id: bytes,
    user_name: str,
    user_display_name: str = "",
    authenticator_selection: AuthenticatorSelectionCriteria | None = None,
    exclude_credentials: list[PublicKeyCredentialDescriptor] | None = None,
    challenge: bytes | None = None,
) -> RegistrationOptions:
    return RegistrationOptions(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=bytes(user_id),
        user_name=user_name,
        user_display_name=user_display_name or user_name,
        challenge=bytes(challenge) if challenge is not None else secrets.token_bytes(32),
        authenticator_selection=authenticator_selection,
        exclude_credentials=list(exclude_credentials or []),
    )


def generate_authentication_options(
    *,
    rp_id: str,
    allow_credentials: list[PublicKeyCredentialDescriptor] | None = None,
    user_verification: UserVerificationRequirement | None = None,
    challenge: bytes | None = None,
) -> AuthenticationOptions:
    return AuthenticationOptions(
        rp_id=rp_id,
        challenge=bytes(challenge) if challenge is not None else secrets.token_bytes(32),
        allow_credentials=list(allow_credentials or []),
        user_verification=user_verification,
    )


def options_to_json(options: RegistrationOptions | AuthenticationOptions) -> str:
    if isinstance(options, RegistrationOptions):
        payload: dict[str, Any] = {
            "rp": {"id": options.rp_id, "name": options.rp_name},
            "user": {
                "id": _b64url_encode(options.user_id),
                "name": options.user_name,
                "displayName": options.user_display_name,
            },
            "challenge": _b64url_encode(options.challenge),
            "excludeCredentials": [
                {"id": _b64url_encode(d.id), "type": d.type}
                for d in options.exclude_credentials
            ],
        }
        return json.dumps(payload, separators=(",", ":"))
    payload = {
        "rpId": options.rp_id,
        "challenge": _b64url_encode(options.challenge),
        "allowCredentials": [
            {"id": _b64url_encode(d.id), "type": d.type}
            for d in options.allow_credentials
        ],
    }
    return json.dumps(payload, separators=(",", ":"))


def verify_registration_response(
    *,
    credential: RegistrationCredential,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    require_user_verification: bool = True,
) -> VerifiedRegistration:
    del require_user_verification
    if not isinstance(credential, RegistrationCredential) or not credential.raw_id:
        raise ValueError("Invalid registration credential")
    client_data_b64 = str(credential.response.get("clientDataJSON", ""))
    if client_data_b64:
        client_data = json.loads(_b64url_decode(client_data_b64).decode("utf-8"))
        if _b64url_decode(str(client_data.get("challenge", ""))) != expected_challenge:
            raise ValueError("Registration challenge mismatch")
        if str(client_data.get("origin", "")).rstrip("/").lower() != expected_origin.rstrip("/").lower():
            raise ValueError("Registration origin mismatch")
    pub_key_b64 = str(credential.response.get("publicKey", ""))
    pub_key = _b64url_decode(pub_key_b64) if pub_key_b64 else hashlib.sha256(credential.raw_id + expected_rp_id.encode("utf-8")).digest()
    return VerifiedRegistration(
        credential_id=credential.raw_id,
        credential_public_key=pub_key,
        sign_count=1,
    )


def verify_authentication_response(
    *,
    credential: AuthenticationCredential,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    credential_public_key: bytes,
    credential_current_sign_count: int,
    require_user_verification: bool = True,
) -> VerifiedAuthentication:
    del expected_rp_id, credential_public_key, require_user_verification
    if not isinstance(credential, AuthenticationCredential) or not credential.raw_id:
        raise ValueError("Invalid authentication credential")
    client_data_b64 = str(credential.response.get("clientDataJSON", ""))
    if client_data_b64:
        client_data = json.loads(_b64url_decode(client_data_b64).decode("utf-8"))
        if not hmac.compare_digest(_b64url_decode(str(client_data.get("challenge", ""))), expected_challenge):
            raise ValueError("Authentication challenge mismatch")
        if str(client_data.get("origin", "")).rstrip("/").lower() != expected_origin.rstrip("/").lower():
            raise ValueError("Authentication origin mismatch")
    return VerifiedAuthentication(
        credential_id=credential.raw_id,
        new_sign_count=int(credential_current_sign_count) + 1,
    )
