"""Release identity: authenticated manifests and controlled key injection.

Keys are *only* supplied through the :class:`KeyRing` constructor.  No method
of this module ever persists raw key material or a mapping from token to raw
value: audit storage keeps the non-secret ``key_id`` label and keyed digests.
"""
import hashlib
import hmac
import json
import re

from .policy import canonical

# Bumped whenever the deterministic transform semantics change.  It is part of
# every release identity, so a new implementation can never silently reuse an
# identity prepared under an older one.
TRANSFORM_VERSION = "transform-v2"

REQUEST_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,127}")
KEY_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}")

MANIFEST_FORMAT = "redacta.authenticated-manifest.v2"
LEGACY_MANIFEST_FORMAT = "redacta.unsigned-manifest.v1"


class PublicationError(ValueError):
    """Base class for every protocol-level rejection."""


class IdentityConflict(PublicationError):
    """Same request id presented with a different frozen identity."""


class ReleaseStateError(PublicationError):
    """An operation is illegal in the release's current state."""


class ManifestIntegrityError(PublicationError):
    """An authenticated manifest failed verification."""


class UnknownKeyError(PublicationError):
    """A manifest references a key id not present in the injected ring."""


class KeyRing:
    """Holds key material in memory only.

    ``secrets`` maps a caller-managed ``key_id`` to at least 32 bytes of key
    material.  ``active_key_id`` selects the key used to sign new releases;
    the other entries let already-prepared releases keep their identity when
    the active key is rotated.  Nothing here is ever written to disk or to the
    audit database.
    """

    def __init__(self, secrets, active_key_id):
        if not isinstance(secrets, dict) or not secrets:
            raise PublicationError("a non-empty key ring is required")
        for key_id, material in secrets.items():
            if not isinstance(key_id, str) or not KEY_ID_RE.fullmatch(key_id):
                raise PublicationError("invalid key id")
            if not isinstance(material, bytes) or len(material) < 32:
                raise PublicationError("each key needs at least 32 bytes")
        if active_key_id not in secrets:
            raise PublicationError("active key id must be present in the ring")
        self._secrets = dict(secrets)
        self.active_key_id = active_key_id

    @classmethod
    def single(cls, key_id, material):
        return cls({key_id: material}, key_id)

    @property
    def active(self):
        return self.active_key_id, self._secrets[self.active_key_id]

    def material(self, key_id):
        try:
            return self._secrets[key_id]
        except KeyError:
            raise UnknownKeyError(f"unknown key id: {key_id}") from None

    def has(self, key_id):
        return key_id in self._secrets

    def sign(self, key_id, payload):
        return hmac.new(self.material(key_id), payload, hashlib.sha256).hexdigest()


def input_fingerprint(tables):
    """Frozen fingerprint of the raw caller input (canonical, sorted)."""
    return hashlib.sha256(canonical(tables).encode("utf-8")).hexdigest()


def collect_namespaces(policy_document):
    """Namespaces participating in the identity, sorted and deduplicated."""
    namespaces = set()
    for spec in policy_document["tables"].values():
        for rule in spec["fields"].values():
            if rule.get("op") == "token" and rule.get("namespace"):
                namespaces.add(rule["namespace"])
            if rule.get("op") == "date_shift":
                namespaces.add(rule.get("namespace", "subject"))
    return sorted(namespaces)


def identity_tuple(*, request_id, input_fp, policy_digest, transform_version,
                   key_id, namespaces):
    """The frozen identity of one publish request (all fields are bound)."""
    return {
        "request_id": request_id,
        "input_fingerprint": input_fp,
        "policy_digest": policy_digest,
        "transform_version": transform_version,
        "key_id": key_id,
        "namespaces": list(namespaces),
    }


def identity_fingerprint(identity):
    """Single digest used to detect *any* identity mismatch on retry."""
    return hashlib.sha256(canonical(identity).encode("utf-8")).hexdigest()


def canonical_manifest(manifest):
    """Stable byte encoding of the manifest without its envelope signature."""
    return canonical(manifest).encode("utf-8")


def sign_manifest(key_ring, key_id, manifest):
    """Wrap a manifest in an authenticated envelope (never unsigned)."""
    payload = canonical_manifest(manifest)
    return {
        "format": MANIFEST_FORMAT,
        "key_id": key_id,
        "algorithm": "HMAC-SHA256",
        "manifest": manifest,
        "signature": key_ring.sign(key_id, payload),
    }


def verify_envelope(key_ring, envelope, *, allow_legacy=False):
    """Verify an envelope and return its embedded manifest.

    A plain checksum, an unknown key id, or an unsigned legacy document
    (unless ``allow_legacy`` is explicitly set) all fail closed.
    """
    if not isinstance(envelope, dict):
        raise ManifestIntegrityError("manifest envelope is not an object")
    if envelope.get("format") == LEGACY_MANIFEST_FORMAT:
        if not allow_legacy:
            raise ManifestIntegrityError(
                "legacy unsigned manifests require an explicit compatibility policy")
        legacy = envelope.get("manifest")
        if not isinstance(legacy, dict) or "tables" not in legacy:
            raise ManifestIntegrityError("malformed legacy manifest")
        return legacy
    if envelope.get("format") != MANIFEST_FORMAT:
        raise ManifestIntegrityError("unknown manifest format")
    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or not key_ring.has(key_id):
        raise UnknownKeyError(f"unknown key id: {key_id}")
    manifest = envelope.get("manifest")
    if not isinstance(manifest, dict) or "identity" not in manifest:
        raise ManifestIntegrityError("malformed authenticated manifest")
    expected = key_ring.sign(key_id, canonical_manifest(manifest))
    if not hmac.compare_digest(expected, str(envelope.get("signature", ""))):
        raise ManifestIntegrityError("manifest signature mismatch")
    return manifest


def dumps_envelope(envelope):
    return canonical(envelope)


def loads_envelope(raw):
    try:
        envelope = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ManifestIntegrityError(f"manifest is not valid JSON: {exc}") from None
    if not isinstance(envelope, dict):
        raise ManifestIntegrityError("manifest envelope is not an object")
    return envelope
