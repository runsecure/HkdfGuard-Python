"""Span/operation names, one nested class per component - lowercase, dot-separated
(OpenTelemetry semantic-convention style: ``hkdfguard.<component>.<operation>``),
so the same names translate identically into a Java/Node/.NET/Go port's own OTel SDK.
"""


class ActivityNames:
    class Cache:
        ADD = "hkdfguard.cache.add"
        ADD_OR_UPDATE = "hkdfguard.cache.add_or_update"
        DECRYPT = "hkdfguard.cache.decrypt"

    class DataProtection:
        PROTECTOR_ENCRYPT = "hkdfguard.data_protection.protector.encrypt"
        PROTECTOR_DECRYPT = "hkdfguard.data_protection.protector.decrypt"
        KEY_WRAPPED_KEY_ENCRYPT = "hkdfguard.data_protection.key_wrapped_key.encrypt"
        KEY_WRAPPED_KEY_DECRYPT = "hkdfguard.data_protection.key_wrapped_key.decrypt"
        EPHEMERAL_KEY_INITIALIZE = "hkdfguard.data_protection.ephemeral_key.initialize"
        PIPELINE_KEY_INITIALIZE = "hkdfguard.data_protection.pipeline_key.initialize"
        KEY_RING_ADD = "hkdfguard.data_protection.key_ring.add"
        KEY_RING_GET = "hkdfguard.data_protection.key_ring.get"
        KEY_RING_GET_CURRENT = "hkdfguard.data_protection.key_ring.get_current"
        FORMAT_PROVIDER_FORMAT = "hkdfguard.data_protection.format.format"
        FORMAT_PROVIDER_PARSE = "hkdfguard.data_protection.format.parse"
        FORMAT_PROVIDER_GET_MAX_DECRYPTED_LENGTH = "hkdfguard.data_protection.format.get_max_decrypted_length"

    class CryptoSessionAesGcm256:
        ENCRYPT = "hkdfguard.crypto_session_aes_gcm256.encrypt"
        DECRYPT = "hkdfguard.crypto_session_aes_gcm256.decrypt"
        BACKGROUND_REFRESH = "hkdfguard.crypto_session_aes_gcm256.background_refresh"

    class EncryptedConfiguration:
        DECRYPT = "hkdfguard.encrypted_configuration.decrypt"
