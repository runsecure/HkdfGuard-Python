# HkdfGuard-Python

A Python port of HkdfGuard (originally a C# library) for protecting data-at-rest encryption keys
using native, platform-backed key management (TPM2 on Linux, Secure Enclave on macOS, the
Platform Crypto Provider/TPM on Windows - see `hkdfguard_keywrapping_v1`) combined with AES-256-GCM
for the actual data encryption. Application code works against a `KeyRing` to encrypt/decrypt
strings and binary data, with key-version tracking and purpose-scoped Additional Authenticated
Data (AAD).

## Key concepts

- **No plaintext key ever touches disk or this process's memory for longer than a single
  operation.** Wrapping/unwrapping a data encryption key (DEK) is delegated entirely to the native
  KMS library for the current OS (`NativeHkdfKeyWrapperV1`) - the KEK never leaves that native
  library, and this library only ever sees the wrapped payload plus the momentarily-revealed DEK.
- **Identified by service name, not a shared master key.** A key is identified to the native KMS
  library by a service name - not by any secret this library holds itself. `KeyRingBuilder`
  carries this, along with a cache-expiry/rotation policy, fluently.
- **One `IKeyWrapper` per KEK, not per wrapped payload.** `IKeyWrapper.decrypt` takes the wrapped
  payload as an explicit argument, so a single wrapper instance (bound only to a KEK - e.g. a
  `NativeHkdfKeyWrapperV1` for one service name) can reveal any number of different wrapped DEKs
  sharing that KEK, one per registered key file.
- **Cached, expiring, proactively-refreshed cipher sessions via `ICryptoProvider`.** A revealed
  DEK is bound into an internal cipher session once, not re-derived on every encrypt/decrypt - the
  configured expiry (1-300 seconds) marks when it should be refreshed instead of reused.
  `ICryptoProvider` owns that refresh itself, and does it ahead of time: a background daemon
  `threading.Thread`, waking every `expiry_seconds` (via `threading.Event.wait`, the interruptible-
  sleep equivalent of a cancellable timer), reveals and builds the next session before the current
  one expires, then swaps it in (behind a `threading.Lock`) and closes the outgoing one (zeroing
  its key) - so an encrypt/decrypt call almost never pays the unwrap cost itself. The concrete
  session type (`AesGcmCryptoSession`) is a private implementation detail, not exported from its
  package - callers only ever see it through the public `ICryptoProvider` they were given (e.g.
  `AesGcmCryptoProvider`), which exposes encrypt/decrypt directly. `ICryptoProviderFactory` is the
  single seam every consumer (`KeyRingBuilder`, `PipelineKeyFactory`) mints providers through, for
  each of the three ways a DEK is revealed: `create` (wrapped-on-disk), `create_ephemeral`
  (generated fresh via `IKeyWrapper.generate_and_wrap`), and `create_for_pipeline` (an already-
  plaintext DEK, used as-is).
- **Versioned, rotatable keys via `KeyRing`.** A `KeyRing` tracks any number of independently
  wrapped keys by an integer version. The highest version added automatically becomes the ring's
  `current_version` - no separate "mark as current" step, so it can never drift out of sync with
  what's actually registered.
- **Purpose-scoped protectors.** `IDataProtector` binds a `name` (purpose) to every operation as
  AAD, so a value protected for one purpose can never be decrypted under another - even using the
  same underlying key.
- **`bytearray`/`bytes`-based API; `aad` collapses to a default parameter, not an overload.**
  Python has no method overloading: where the C#/Java originals overload Encrypt/Decrypt with and
  without an `aad` parameter, Python's version always takes `aad: bytes = b""`, so a caller with
  none just omits it. Buffers that get zeroed after use (plaintext, revealed keys) are `bytearray`
  (mutable); read-only inputs are `bytes`. Secrets are zeroed via `array_utility.zero_memory` and
  never surface as interned strings.
- **"I"-prefixed interfaces, unlike this workspace's Java/Go/Node ports.** Every abstract base
  class keeps its C# `I` prefix (`ICryptoProvider`, `IKeyWrapper`, `IDataEncryptionKey`, ...),
  matching .NET 1:1; concrete classes use plain descriptive names with no `Impl` suffix, since
  there's no naming collision to resolve once the "I" prefix is never stripped.
- **Built-in telemetry.** Every package emits OpenTelemetry (`opentelemetry-api`) spans/metrics via
  `HkdfGuardTelemetry`/`ComponentTelemetry`, with exceptions recorded on failure, and an opt-in
  sensitive-logging mode that emits operation metadata (never raw key/plaintext/ciphertext bytes).

## Architecture overview

```
                      +------------------------------------------+
                      | Hardware Security Module (TPM2 / Enclave) |
                      +------------------------------------------+
                                           |
                                  (Wraps / Unwraps)
                                           v
+---------------------+       +---------------------------------------+
| Native KMS Library  | <---> |   IKeyWrapper (NativeHkdfKeyWrapperV1, |
+---------------------+       |   resolved once per process by        |
                               |   get_library)                        |
                               +---------------------------------------+
                                           |
                                  (Reveals DEK)
                                           v
                              +---------------------------+
                              |       ICryptoProvider      |  <-- background thread refreshes
                              |    (AesGcmCryptoProvider)  |      + zeroes the outgoing session
                              +---------------------------+
                                           |
                                   (AEAD encrypt/decrypt)
                                           v
                              +---------------------------+
                              |     IDataEncryptionKey     |
                              |  (KeyWrapped / Pipeline,   |
                              |  via EncryptionKeyBase)    |
                              +---------------------------+
                                           |
                               (Version Management / AAD)
                                           v
               +-------------------------------------------------------+
               |                       KeyRing                         |
               +-------------------------------------------------------+
                                /                            \
                               v                              v
                +------------------------+     +--------------------------+
                |     IDataProtector      |     |  IProtectedCache /       |
                | (strings)               |     |  IProtectedReadOnlyCache |
                +------------------------+     +--------------------------+
```

Same shape as every other port in this workspace (the .NET repo drives the design, so
Java/Go/Node/Python mirror this layering, adding their own consumer branches as they catch up):

1. **KEK (Key Encryption Key)** - a hardware-backed key managed by the OS/TPM/Enclave, referenced
   only by a service name. The plaintext KEK never enters this process's memory.
2. **DEK (Data Encryption Key)** - a 256-bit symmetric key wrapped by the KEK. Can be persisted to
   disk or generated ephemerally in memory - both are a `KeyWrappedDataEncryptionKey` around an
   `ICryptoProvider` minted via `ICryptoProviderFactory.create`/`create_ephemeral` respectively -
   or used unwrapped before a KEK exists yet (`PipelineDataEncryptionKey`, via
   `create_for_pipeline`).
3. **`ICryptoProvider`** - the active AEAD (AES-256-GCM) cipher session holding the unwrapped DEK.
   Automatically rotates and zeroes expired sessions on a configured schedule (1-300 seconds).
4. **`KeyRing`** - manages multiple versioned keys. Adding a new key version doesn't break
   decryption of data already protected under older versions.
5. **Formatted encrypted value** - the standardized `enc::v{version}::{base64}` string, handled by
   `IEncryptedFormatProvider`/`DefaultFormatProvider`.

## Package layout

`uv` workspace (`pyproject.toml` → `tool.uv.workspace.members = ["src/*", "test/*"]`); each
`src/HkdfGuard.<Module>/` is its own workspace member exposing a `hkdfguard_<module>` import
package.

| Package | Purpose |
|---|---|
| `hkdfguard_diagnostics` | Every package's telemetry, centralized: `HkdfGuardTelemetry` (one `ComponentTelemetry` per component - `.tracer`, `.meter`, `.enable_sensitive_logging`, `ComponentTelemetry.record_exception`, `.log_sensitive_operation`), `ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames` (OpenTelemetry semantic-convention-style names, e.g. `hkdfguard.cache.add`), `CacheMetrics`, and `sensitive_operation_logged`/`operation_failed` (stdlib-`logging`-based helpers). No dependency on any other package in this workspace - the lowest layer, its naming/shape kept identical across every HkdfGuard port. |
| `hkdfguard_abstractions` | Interfaces and pure data types only (`IKeyWrapper`, `ICryptoProvider`, `ICryptoProviderFactory`, `IDataEncryptionKey`, `IDataProtector`, `IProtectedCache`/`IProtectedReadOnlyCache`, `IEncryptedFormatProvider`, `KeyTrackingValue`, `ProtectedCacheBase`, `array_utility.is_null_or_empty`/`zero_memory`). Depends only on `hkdfguard_diagnostics`. |
| `hkdfguard_cryptosession_aesgcm256` | `AesGcmCryptoSession` (private, key-bound at construction, built on `cryptography.hazmat.primitives.ciphers.aead.AESGCM`) wrapped directly by the public `AesGcmCryptoProvider` (an `ICryptoProvider` that reveals/refreshes it from an `IKeyWrapper` + wrapped bytes via a background daemon thread, and is the sole place the 1-300 second expiry range is validated - it only ever holds one active session at a time; also exposes `get_encrypted_allocation_length`/`get_decrypted_allocation_length`, and a pipeline-only construction path with no background thread), minted via `AesGcmCryptoProviderFactory` (an `ICryptoProviderFactory`). Depends on `hkdfguard_abstractions`/`hkdfguard_diagnostics`; its `HkdfGuardTelemetry.CRYPTO_SESSION_AES_GCM256` component keeps its own independent sensitive-logging flag rather than sharing `ROOT`'s. |
| `hkdfguard_keywrapping_v1` | `NativeHkdfKeyWrapperV1` (an `IKeyWrapper`) and `get_library`, which resolve and bind the current OS's native KMS library (Linux/`.so`, macOS/`.dylib`, Windows/`.dll`) to wrap and unwrap a 32-byte DEK under a service-identified KEK held entirely outside this process. |
| `hkdfguard_dataencryptionkey` | The application-facing API: `KeyRing`/`KeyRingBuilder`, `IDataProtector` (unexported concrete `DataProtector`, built only via `KeyRing.create_protector`), `EncryptionKeyBase` (shared allocation-sizing/telemetry logic) and its two concrete keys `KeyWrappedDataEncryptionKey`/`PipelineDataEncryptionKey`, `PipelineKeyFactory` (mints a fresh-DEK `PipelineDataEncryptionKey` via an `ICryptoProviderFactory`, through the inert, unexported `DummyKeyWrapper`), and `DefaultFormatProvider` (the default `enc::v{version}::{base64}` wire format). Depends on `hkdfguard_abstractions`/`hkdfguard_diagnostics`. |
| `hkdfguard_cache` | `ProtectedCache` (an `IProtectedCache` backed by one `IDataEncryptionKey` - encrypts on `add`/`add_or_update`, reveals on `decrypt`, nothing held as plaintext beyond a single call) and `ProtectedCacheCollection` (aggregates multiple `IProtectedReadOnlyCache` sources behind one read-only surface, checked in registration order). |

Requires **Python 3.11+**. `uv sync --all-packages` resolves every workspace member (plain
`uv sync` alone only resolves the root project, whose own `dependencies` list is empty).

## Getting started

### 1. Wrap or reveal a DEK

`NativeHkdfKeyWrapperV1` is an `IKeyWrapper` bound to whichever native KMS library matches the
current OS (resolved once per process by `get_library`), identified only by a service name. Since
`decrypt` takes the wrapped payload as an explicit argument rather than one bound at construction,
a single instance freely handles both directions, and any number of different wrapped payloads
sharing that service name:

```python
wrapper = NativeHkdfKeyWrapperV1("my-service")

# Protect a fresh 32-byte DEK under the KEK identified by "my-service":
wrapped = bytearray(512)  # native library's own payload format/size
written = wrapper.encrypt(fresh_dek, wrapped)

# Later, reveal a DEK from a previously-wrapped payload for the same service:
dek = bytearray(32)
wrapper.decrypt(bytes(wrapped[:written]), dek)
```

The native ABI has no concept of Additional Authenticated Data - `IKeyWrapper` itself does not
expose an AAD-taking method.

### 2. Build a `KeyRing`

`KeyRingBuilder` fluently collects a service name/cache-expiry/rotation policy, a shared
`IKeyWrapper` and an `ICryptoProviderFactory`, and any number of wrapped-DEK files - one per
version - then reads each file, mints its own `ICryptoProvider` (via
`ICryptoProviderFactory.create`), and wires it into a `KeyWrappedDataEncryptionKey`.
`with_ephemeral_key` registers a version whose own key is instead generated fresh in memory on
first use (via `ICryptoProviderFactory.create_ephemeral`) - it shares the same
`IKeyWrapper`/`ICryptoProviderFactory`, so no extra configuration is needed for it. `build`
validates everything at once - including that `with_cached_key_expiry` was actually called;
there's no default:

```python
ring = (
    KeyRingBuilder()
    .with_service_name("my-service")
    .with_cached_key_expiry(60)   # seconds, 0-300 - required before build
    .with_key_rotation_days(90)   # 1-180
    .with_key_wrapper(wrapper)
    .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
    .with_key_file(1, "/path/to/wrapped-dek-v1.bin")
    .with_ephemeral_key(2)
    .build()
)
```

Registering additional key files at higher version numbers (e.g. during a rotation) is all that's
needed to advance `ring.current_version` - existing ciphertext tagged with older versions
continues to decrypt correctly as long as those files stay registered.

### 3. Encrypt and decrypt

```python
protector = ring.create_protector("cookie-auth")  # "cookie-auth" becomes this protector's AAD

encrypted = protector.encrypt("secret value")
# e.g. "enc::v1::AbCdEf..."

decrypted = protector.decrypt(encrypted)
```

A value encrypted by one protector name can never be decrypted by a protector created with a
different name, even from the same `KeyRing` - the name is bound in as AAD on every operation.

### Ephemeral, in-memory-only keys

For scenarios that don't need a durable, file-backed key at all,
`ICryptoProviderFactory.create_ephemeral` generates and wraps a fresh DEK once via
`IKeyWrapper.generate_and_wrap` - the plaintext DEK never crosses that call's return value, and
nothing here is ever written to or read from a file. Wrap the resulting `ICryptoProvider` in a
`KeyWrappedDataEncryptionKey`, exactly as for a file-backed key (or just call
`KeyRingBuilder.with_ephemeral_key` - see above, which does exactly this):

```python
factory = AesGcmCryptoProviderFactory()
provider = factory.create_ephemeral(wrapper, expiry_seconds=60)
ephemeral_key = KeyWrappedDataEncryptionKey(provider)
```

### Pipeline keys - encrypt now, wrap later

`PipelineDataEncryptionKey` is for the moment before a durable KEK even exists yet - e.g. a
provisioning pipeline that needs to encrypt secrets in-flight, then hand the same plaintext DEK to
the platform's native "initialize" CLI utility at the end of the chain, which independently
wraps/registers it against a real KEK. Unlike every other `IDataEncryptionKey` here, its DEK is
never wrapped or unwrapped - it's used exactly as given via a trivial, unexported identity
`IKeyWrapper` (`DummyKeyWrapper`). `PipelineKeyFactory` generates a fresh, random 32-byte DEK and
builds one around it via `ICryptoProviderFactory.create_for_pipeline` - unlike the C#/Java
originals' `Create`, which also accepts a format-provider argument and an optional key version
that its own implementation never reads, Python's `create` drops both rather than carrying two
parameters that do nothing:

```python
with PipelineKeyFactory().create(AesGcmCryptoProviderFactory()) as pipeline_key:
    encrypted = pipeline_key.encrypt(bytearray(b"secret value"))

    # At the end of the pipeline, hand the plaintext DEK off to be wrapped for real:
    dek = pipeline_key.as_bytearray()
    initialize_with_native_cli(dek)
# __exit__ calls close(), which zeroes the DEK.
```

## Diagnostics

All telemetry lives in `hkdfguard_diagnostics`. `HkdfGuardTelemetry` exposes one
`ComponentTelemetry` per component (`ROOT`, `CACHE`, `DATA_PROTECTION`,
`ENCRYPTED_CONFIGURATION`, `CRYPTO_SESSION_AES_GCM256`, `KEY_WRAPPING`), each with its own
`.tracer`/`.meter` and an `enable_sensitive_logging` flag - `ROOT`/`CACHE`/`DATA_PROTECTION`/
`ENCRYPTED_CONFIGURATION` share one flag (set any of them, all four read the new value);
`CRYPTO_SESSION_AES_GCM256` and `KEY_WRAPPING` each keep their own, independent flag. When
enabled, operations emit a fixed-name `hkdfguard.sensitive_operation` debug event carrying only
non-sensitive metadata (lengths, versions, identifiers) as attributes - raw key, plaintext, and
ciphertext bytes are never logged, regardless of this setting.

Span, event, attribute, and metric names all follow OpenTelemetry semantic-convention style -
lowercase, dot-separated (e.g. `hkdfguard.cache.add`, attribute `hkdfguard.plaintext_length`) - see
`ActivityNames`/`AttributeNames`/`EventNames`/`MetricNames`. This naming is the part of the design
meant to translate identically into every HkdfGuard port's own OpenTelemetry SDK usage, regardless
of implementation language.

`ProtectedCache` accepts an optional `logging.Logger` (`None` is a silent no-op) alongside its
existing tracing, and records every add/add_or_update via `CacheMetrics` (a counter on
`HkdfGuardTelemetry.CACHE`'s meter).

## Testing

```bash
uv sync --all-packages
uv run pytest test/HkdfGuard.Cache.Test              # per-module - see note below
uv run pytest test/HkdfGuard.Cache.Test/test_protected_cache.py::test_name  # single test
uv run ruff check .    # tool.ruff config: target-version py311, line-length 120
```

Run each `test/HkdfGuard.<Module>.Test/` directory as its own `pytest` invocation rather than one
root-level run: several test directories each define their own `test_helpers` package under the
same top-level name, and Python's `sys.modules` only keeps one `test_helpers` module loaded for
the whole process, so a single combined run can fail to collect tests whose `test_helpers`
submodules got shadowed by an unrelated directory's package of the same name.
