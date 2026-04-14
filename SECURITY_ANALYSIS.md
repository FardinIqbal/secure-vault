# Secure Vault: Security Analysis
**Fardin Iqbal** | April 2026

---

## Problem 1. Two Desirable Security Properties

**Confidentiality.** Only the user who knows the correct master password should be able to learn the contents of the vault. Following the definition from class that only those who are authorized to know can know, an adversary who obtains the encrypted vault file should gain zero information about the stored passwords without the master key. Our implementation achieves this through AES-128 in GCM mode, where the encryption key is derived from the master password via scrypt. Since the vault is never stored in plaintext on disk, the confidentiality property reduces to the strength of the AES cipher and the unpredictability of the derived key.

**Integrity.** No party should be able to modify the vault's contents without the modification being detected. As defined in lecture, integrity means data is only modified by authorized parties and in permitted ways. If an attacker tampers with even a single byte of the encrypted vault file, whether flipping bits in the ciphertext, injecting entries, or rearranging data, the vault must catch this and refuse to decrypt. AES-GCM provides this as an authenticated encryption scheme. It produces an authentication tag during encryption that is verified during decryption, so any tampering causes the `decrypt_and_verify` operation to fail.

---

## Problem 2. Two Potential Threat Models

**Offline Attacker with File Access.** An adversary gains access to the local file system where the encrypted vault lives. This could happen through a stolen laptop, malware exfiltrating files, or a shared computer. The attacker possesses a copy of the encrypted vault and can run brute force or dictionary attacks against it offline, with no rate limiting on attempts. This maps to the ciphertext only adversary model from class. The attacker has the ciphertext but not the key, and can spend unlimited computational resources trying to recover it. As we discussed in Lecture 7, this is the exact scenario that makes offline dictionary attacks such a real threat, especially with modern GPU and ASIC based cracking tools like Hashcat capable of hundreds of millions of hashes per second.

**Compromised Endpoint.** An adversary has runtime access to the machine while the user is actively operating the vault. This could be a keylogger capturing the master password as it is typed, or malware reading decrypted vault contents directly from process memory. Unlike the offline attacker, this adversary bypasses the cryptographic protections entirely because they intercept data before encryption or after decryption. This is the single point of failure risk inherent to password managers as discussed in class. All passwords are protected by one master password, and if that master password is captured, everything is compromised.

---

## Problem 3. Analyzing Both Properties Under the Offline Attacker

**Confidentiality analysis.** The vault is encrypted with AES-128 GCM, and the encryption key is derived from the master password using scrypt with parameters N=2^14, r=8, p=1. scrypt is specifically designed to be memory hard, meaning it resists the GPU and ASIC based attacks that have made traditional hash functions like SHA-256 vulnerable to brute force at scale. Where a standard hash might allow an attacker to test hundreds of millions of guesses per second, scrypt forces each guess to consume significant memory, drastically reducing throughput.

The confidentiality property holds as long as the master password has sufficient entropy. Using NIST entropy estimation, an 8 character human selected password has roughly 18 bits of entropy. That is far too low to resist a determined attacker even with scrypt's slowdown. A strong, randomly generated master password is essential. There is also a subtlety in our implementation. The salt used for key derivation is constant rather than per user random. This means two users who choose the same master password will derive identical encryption keys. In a real deployment you would want a random salt stored alongside the vault, similar to how modern Unix systems store the salt and hashed password pair in /etc/shadow but this implementation opts for simplicity.

**Integrity analysis.** AES-GCM is an authenticated encryption scheme, meaning it provides both confidentiality and integrity in a single pass. During encryption, GCM computes an authentication tag over the ciphertext. During decryption, this tag is verified before any plaintext is returned. If the offline attacker modifies the vault file in any way, whether bit flipping, appending data, truncating, or rearranging blocks, the tag verification will fail and the program raises an error rather than returning corrupted data.

This is a meaningful guarantee. The attacker cannot silently inject a phishing password for a banking domain or subtly alter existing entries without detection. What the attacker *can* do is delete the vault file outright or corrupt it beyond recovery, but that constitutes a denial of service, an availability violation, not a silent integrity breach. The magic string prepended to vault contents acts as an additional decryption verification layer. If the first line after decryption is not the expected magic string, we know something went wrong, providing a secondary check on top of GCM's built in tag authentication.
