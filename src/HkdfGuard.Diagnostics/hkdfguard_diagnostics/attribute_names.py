"""Attribute/tag keys shared across every component's spans, events, and metrics - lowercase,
dot-separated (OpenTelemetry semantic-convention style), so the same keys translate identically
into a Java/Node/.NET/Go port's own OTel SDK.
"""


class AttributeNames:
    NAME = "hkdfguard.name"
    PLAINTEXT_LENGTH = "hkdfguard.plaintext_length"
    CIPHERTEXT_LENGTH = "hkdfguard.ciphertext_length"
    ENCRYPTED_LENGTH = "hkdfguard.encrypted_length"
    AAD_LENGTH = "hkdfguard.aad_length"
    VALUE_LENGTH = "hkdfguard.value_length"
    KEY_VERSION = "hkdfguard.key_version"
    KEY_RING_BECAME_CURRENT = "hkdfguard.key_ring.became_current"
    OPERATION_NAME = "hkdfguard.operation.name"
    RESULT = "hkdfguard.result"
