"""WebAuthn data structures for MK1Ai remote security console."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ResidentKeyRequirement(str, Enum):
    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class UserVerificationRequirement(str, Enum):
    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


@dataclass(frozen=True)
class AuthenticatorSelectionCriteria:
    authenticator_attachment: str | None = None
    resident_key: ResidentKeyRequirement | None = None
    require_resident_key: bool | None = None
    user_verification: UserVerificationRequirement | None = None


@dataclass(frozen=True)
class PublicKeyCredentialDescriptor:
    id: bytes
    type: str = "public-key"
    transports: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RegistrationCredential:
    id: str
    raw_id: bytes
    response: dict[str, object]
    type: str = "public-key"


@dataclass(frozen=True)
class AuthenticationCredential:
    id: str
    raw_id: bytes
    response: dict[str, object]
    type: str = "public-key"
