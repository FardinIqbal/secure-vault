# Architectural Decision Records

Each entry documents a non-obvious engineering choice, its alternatives, and why I picked what I picked.

---

## ADR 1: AES-128 in GCM mode for authenticated encryption

**Status:** accepted

**Context:**
Encrypting the vault requires both confidentiality (unreadable without key) and authenticity (modifications detected). Three options:

1. **AES-CBC + HMAC-SHA256**: encrypt-then-MAC. Two primitives, two keys.
2. **AES-GCM** (this design): single primitive provides both confidentiality and authenticity.
3. **ChaCha20-Poly1305**: modern alternative to AES-GCM, similar security properties.

**Decision:**
AES-GCM.

**Consequences:**

- Pro: single primitive, single key. Simpler implementation.
- Pro: hardware-accelerated on modern CPUs (AES-NI instructions).
- Pro: standard, widely audited. NIST-approved (SP 800-38D).
- Pro: integrated authentication tag (16 bytes) appended to ciphertext.
- Con: catastrophically broken if (key, nonce) is ever reused. Requires careful nonce management.
- Con: 12-byte nonce limits to ~2^32 messages per key before nonce reuse becomes likely. For a password vault encrypting maybe once per session, no concern.

ChaCha20-Poly1305 would also work; the choice between them is largely a matter of platform preference. AES-GCM has hardware acceleration on every modern CPU; ChaCha20 is faster on platforms without AES instructions.

---

## ADR 2: scrypt for key derivation

**Status:** accepted

**Context:**
The master password must be transformed into a 128-bit AES key. Three options:

1. **PBKDF2-SHA256**: industry standard, fast, but cheap on GPUs.
2. **scrypt** (this design): memory-hard, GPU-resistant.
3. **Argon2**: newer (2015 winner of the Password Hashing Competition), even more memory-hard.

**Decision:**
scrypt.

**Consequences:**

- Pro: memory-hard. GPU brute force needs lots of memory per attempt, which slows it down dramatically.
- Pro: tunable cost (N parameter). Can be raised over time as hardware improves.
- Pro: well-understood, audited, in use for ~15 years.
- Con: Argon2 is the modern best practice (PHC winner). scrypt is one generation behind.
- Con: scrypt parameters are confusing (N, r, p) compared to Argon2's clearer time-memory-parallelism knobs.

For a study project, scrypt is fine. The `cryptography` library has good scrypt support; Argon2 requires `argon2-cffi` as a separate install. Future versions could migrate to Argon2 with a vault-format version bump.

---

## ADR 3: Store KDF parameters in the vault file

**Status:** accepted

**Context:**
The KDF parameters (N, r, p for scrypt) must match between encryption and decryption. Two options:

1. **Hardcode**: parameters are constants in the source.
2. **Store in vault** (this design): N, r, p saved alongside ciphertext.

**Decision:**
Store.

**Consequences:**

- Pro: forward compatibility. Future versions can increase N without breaking old vaults.
- Pro: per-vault tunability. Different vaults can use different costs.
- Pro: explicit. The vault is self-describing.
- Con: 6 bytes of overhead per vault. Negligible.

This is the pattern used by every modern password hashing library (bcrypt, Argon2, PBKDF2 in `passlib`). The hash output includes the parameters used to generate it, so the verifier knows how to reproduce the derivation.

---

## ADR 4: Generic error message on decryption failure

**Status:** accepted

**Context:**
GCM tag verification can fail for two reasons: wrong password or tampered ciphertext. Two options:

1. **Distinguish in the error**: tell the user "wrong password" or "vault tampered."
2. **Generic message** (this design): "Incorrect password or corrupted vault."

**Decision:**
Generic.

**Consequences:**

- Pro: information-theoretically secure. An attacker cannot use the error message to distinguish these cases.
- Pro: simpler error path. No need to check the failure mode.
- Con: confusing for the user. They cannot tell whether they typed the password wrong or whether their vault was modified.

For a security tool, the generic message is the right call. Telling an attacker which case they triggered would let them gradually narrow in on the password.

---

## ADR 5: Fresh salt and nonce on every encryption

**Status:** accepted

**Context:**
Each encryption operation needs a salt (for KDF) and a nonce (for AES-GCM). Two options:

1. **Reuse**: derive once, reuse the salt and nonce across encryptions.
2. **Fresh** (this design): generate new salt and nonce every time.

**Decision:**
Fresh.

**Consequences:**

- Pro: AES-GCM nonce reuse is catastrophic. Fresh nonce per encryption guarantees safety.
- Pro: fresh salt means same plaintext encrypts to different ciphertext, preventing pattern analysis.
- Pro: simpler invariants. Every encryption is independent.
- Con: re-derives the key on every encryption. ~100ms per scrypt run.

The cost is acceptable for a vault that is typically encrypted once per session. For a high-frequency encryption workload, deriving once and tracking nonces would be the optimization.

---

## ADR 6: Output to a single file

**Status:** accepted

**Context:**
The vault data could be split across files (one per entry, or metadata file plus blob file). Two options:

1. **Multiple files**: header file plus blob file plus metadata.
2. **Single file** (this design): salt, nonce, ciphertext, KDF params all in one file.

**Decision:**
Single.

**Consequences:**

- Pro: simpler. Copy one file to back up the vault.
- Pro: atomic. The file either has all the parts or none.
- Pro: harder to corrupt by partial-file mishandling.
- Con: cannot deduplicate entries across vaults. (But that is not a goal.)

A vault is a black box. Single-file representation is the right primitive.

---

## ADR 7: Disable verification logging in test vault

**Status:** accepted

**Context:**
During testing, the vault library's debug logging would expose the master password. Two options:

1. **Leave logging on**: simpler, but may leak.
2. **Disable in tests** (this design): silence logging during sensitive operations.

**Decision:**
Disable.

**Consequences:**

- Pro: no master password leakage in test logs (which might be checked into CI artifacts).
- Pro: production code follows the same pattern.
- Con: harder to debug failed test cases. Mitigation: enable logging only when investigating.

Sensitive data should not be in logs by default. Period.
