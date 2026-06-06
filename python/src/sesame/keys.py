"""Key material and the KeyProvider lookup/authorization seam."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass
class ChannelScope:
    allow_all: bool = False
    channels: Set[str] = field(default_factory=set)

    @staticmethod
    def all() -> "ChannelScope":
        return ChannelScope(allow_all=True)

    @staticmethod
    def list(channels: Iterable[str]) -> "ChannelScope":
        return ChannelScope(allow_all=False, channels=set(channels))

    def permits(self, channel: str) -> bool:
        return self.allow_all or channel in self.channels


class KeyProvider(abc.ABC):
    """Lookup seam for SESAME key material and authorization policy."""

    @abc.abstractmethod
    def signing_keys(self, key_id: str) -> List[bytes]:
        ...

    def primary_signing_key(self, key_id: str) -> Optional[bytes]:
        ks = self.signing_keys(key_id)
        return ks[0] if ks else None

    @abc.abstractmethod
    def aead_key(self, enc_key_id: str) -> Optional[bytes]:
        ...

    @abc.abstractmethod
    def is_authorized(self, key_id: str, channel: str) -> bool:
        ...

    @abc.abstractmethod
    def is_revoked(self, key_id: str) -> bool:
        ...


class StaticKeyProvider(KeyProvider):
    """In-memory, config-backed reference provider."""

    def __init__(self) -> None:
        # key_id -> (keys, scope, revoked)
        self._signing: Dict[str, Tuple[List[bytes], ChannelScope, bool]] = {}
        self._aead: Dict[str, bytes] = {}

    def with_signing_key(self, key_id: str, key: bytes, scope: ChannelScope) -> "StaticKeyProvider":
        self._signing[key_id] = ([key], scope, False)
        return self

    def add_overlap_key(self, key_id: str, key: bytes) -> "StaticKeyProvider":
        keys, scope, revoked = self._signing[key_id]
        keys.append(key)
        return self

    def revoke(self, key_id: str) -> "StaticKeyProvider":
        if key_id in self._signing:
            keys, scope, _ = self._signing[key_id]
            self._signing[key_id] = (keys, scope, True)
        return self

    def with_aead_key(self, enc_key_id: str, key: bytes) -> "StaticKeyProvider":
        self._aead[enc_key_id] = key
        return self

    def signing_keys(self, key_id: str) -> List[bytes]:
        entry = self._signing.get(key_id)
        return list(entry[0]) if entry else []

    def aead_key(self, enc_key_id: str) -> Optional[bytes]:
        return self._aead.get(enc_key_id)

    def is_authorized(self, key_id: str, channel: str) -> bool:
        entry = self._signing.get(key_id)
        return bool(entry) and not entry[2] and entry[1].permits(channel)

    def is_revoked(self, key_id: str) -> bool:
        entry = self._signing.get(key_id)
        return bool(entry) and entry[2]
