"""Comprehensive test suite for Secure Vault password manager."""
import hashlib
import json
import os
import sys
from password_manager import (
    computerMasterKey, encryptFile, decryptFile,
    generatePassword, EncryptVaultAndSave, decryptAndReconstructVault
)

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        print(f"  PASS  {name}")
        passed += 1
    else:
        print(f"  FAIL  {name} --- {detail}")
        failed += 1

def cleanup(hashedusername):
    if os.path.exists(hashedusername):
        os.remove(hashedusername)

# ============================================================
print("\n[1] KEY DERIVATION - computerMasterKey")
# ============================================================
key = computerMasterKey("testpassword")
test("Key is 16 bytes (128-bit)", len(key) == 16, f"got {len(key)}")
test("Key is bytes type", isinstance(key, bytes), f"got {type(key)}")

# Same password always produces same key (deterministic with constant salt)
key2 = computerMasterKey("testpassword")
test("Deterministic: same password -> same key", key == key2)

# Different passwords produce different keys
key3 = computerMasterKey("differentpassword")
test("Different password -> different key", key != key3)

# Empty-ish edge case
key4 = computerMasterKey("a")
test("Single-char password produces valid 16-byte key", len(key4) == 16)

key5 = computerMasterKey("a" * 1000)
test("Very long password produces valid 16-byte key", len(key5) == 16)


# ============================================================
print("\n[2] ENCRYPTION / DECRYPTION - encryptFile + decryptFile")
# ============================================================
plaintext = b"hello world this is a test"
encrypted = encryptFile(plaintext, key)

# Verify output is valid JSON with expected fields
parsed = json.loads(encrypted)
test("Encrypted output is valid JSON", True)
for field in ['nonce', 'header', 'ciphertext', 'tag']:
    test(f"JSON contains '{field}' field", field in parsed, f"missing {field}")

# Round-trip
decrypted = decryptFile(encrypted, key)
test("Decrypt recovers original plaintext", decrypted == plaintext)

# Empty data
enc_empty = encryptFile(b"", key)
dec_empty = decryptFile(enc_empty, key)
test("Empty data round-trips correctly", dec_empty == b"")

# Large data
big_data = b"x" * 100000
enc_big = encryptFile(big_data, key)
dec_big = decryptFile(enc_big, key)
test("100KB data round-trips correctly", dec_big == big_data)

# Unicode in data
unicode_data = "Hello unicode cafe\u0301".encode('utf-8')
enc_uni = encryptFile(unicode_data, key)
dec_uni = decryptFile(enc_uni, key)
test("Unicode data round-trips correctly", dec_uni == unicode_data)

# Two encryptions of same data produce different ciphertexts (random nonce)
enc_a = encryptFile(plaintext, key)
enc_b = encryptFile(plaintext, key)
test("Same plaintext -> different ciphertext (nonce randomness)", enc_a != enc_b)

# Wrong key fails
wrong_key = computerMasterKey("wrongpassword")
try:
    decryptFile(encrypted, wrong_key)
    test("Wrong key rejected during decryption", False, "decryption should have failed")
except (ValueError, Exception):
    test("Wrong key rejected during decryption", True)

# Tampered ciphertext fails
tampered = json.loads(encrypted)
# Flip a character in the ciphertext
ct = tampered['ciphertext']
tampered['ciphertext'] = ct[:-2] + ('A' if ct[-2] != 'A' else 'B') + ct[-1]
try:
    decryptFile(json.dumps(tampered), key)
    test("Tampered ciphertext rejected", False, "should have failed")
except (ValueError, Exception):
    test("Tampered ciphertext rejected", True)


# ============================================================
print("\n[3] PASSWORD GENERATION - generatePassword")
# ============================================================
passwords = set()
for i in range(100):
    pw = generatePassword()
    passwords.add(pw)
    if i == 0:
        test("Password length is 16", len(pw) == 16, f"got {len(pw)}")
        test("Password is alphanumeric only", pw.isalnum(), f"got '{pw}'")
        # Check it contains only valid chars (A-Z, a-z, 0-9)
        import string
        valid = set(string.ascii_uppercase + string.ascii_lowercase + string.digits)
        test("All chars from valid set", all(c in valid for c in pw))

test("100 generated passwords are mostly unique", len(passwords) >= 95,
     f"only {len(passwords)} unique out of 100")


# ============================================================
print("\n[4] FULL VAULT ROUND-TRIP")
# ============================================================
username = "vaulttest"
password = "masterkey123"
hashed = hashlib.sha256(username.encode('utf-8')).hexdigest()
cleanup(hashed)

# Single entry
vault1 = ["alice:mypass:google.com"]
EncryptVaultAndSave(vault1, password, hashed)
test("Vault file created on disk", os.path.exists(hashed))
recovered1 = decryptAndReconstructVault(hashed, password)
test("Single entry recovered correctly", recovered1 == vault1,
     f"expected {vault1}, got {recovered1}")
cleanup(hashed)

# Multiple entries
vault2 = [
    "alice:pass1:google.com",
    "bob:pass2:github.com",
    "charlie:pass3:stackoverflow.com",
    "diana:pass4:reddit.com",
    "eve:pass5:twitter.com"
]
EncryptVaultAndSave(vault2, password, hashed)
recovered2 = decryptAndReconstructVault(hashed, password)
test("5 entries recovered correctly", recovered2 == vault2)
test("Entry order preserved", recovered2 == vault2)
cleanup(hashed)

# Empty vault
vault_empty = []
EncryptVaultAndSave(vault_empty, password, hashed)
recovered_empty = decryptAndReconstructVault(hashed, password)
test("Empty vault round-trips correctly", recovered_empty == [])
cleanup(hashed)

# Vault with special characters (no colons, per spec)
vault_special = ["user1:p@ss!w0rd#$%:example.com"]
EncryptVaultAndSave(vault_special, password, hashed)
recovered_special = decryptAndReconstructVault(hashed, password)
test("Special chars in password preserved", recovered_special == vault_special)
cleanup(hashed)

# Long entries
long_user = "a" * 200
long_pass = "b" * 200
long_domain = "c" * 200
vault_long = [f"{long_user}:{long_pass}:{long_domain}"]
EncryptVaultAndSave(vault_long, password, hashed)
recovered_long = decryptAndReconstructVault(hashed, password)
test("Long entries preserved", recovered_long == vault_long)
cleanup(hashed)


# ============================================================
print("\n[5] WRONG PASSWORD DETECTION")
# ============================================================
vault = ["alice:secret:google.com"]
EncryptVaultAndSave(vault, password, hashed)

try:
    decryptAndReconstructVault(hashed, "totallyWrongPassword")
    test("Wrong master password rejected", False, "should have raised error")
except (SystemExit, ValueError, Exception) as e:
    test("Wrong master password rejected", True)
cleanup(hashed)


# ============================================================
print("\n[6] HASHED USERNAME")
# ============================================================
h1 = hashlib.sha256("alice".encode('utf-8')).hexdigest()
h2 = hashlib.sha256("alice".encode('utf-8')).hexdigest()
h3 = hashlib.sha256("bob".encode('utf-8')).hexdigest()
test("Same username -> same hash", h1 == h2)
test("Different username -> different hash", h1 != h3)
test("Hash is 64 hex chars (SHA-256)", len(h1) == 64 and all(c in '0123456789abcdef' for c in h1))


# ============================================================
print("\n[7] VAULT OVERWRITE (save twice, second version persists)")
# ============================================================
hashed = hashlib.sha256("overwritetest".encode('utf-8')).hexdigest()
cleanup(hashed)

vault_v1 = ["old:oldpass:old.com"]
vault_v2 = ["new:newpass:new.com", "extra:extrapass:extra.com"]

EncryptVaultAndSave(vault_v1, password, hashed)
EncryptVaultAndSave(vault_v2, password, hashed)
recovered = decryptAndReconstructVault(hashed, password)
test("Second save overwrites first", recovered == vault_v2)
cleanup(hashed)


# ============================================================
print("\n[8] MULTIPLE USERS (different usernames = different vault files)")
# ============================================================
hash_a = hashlib.sha256("userA".encode('utf-8')).hexdigest()
hash_b = hashlib.sha256("userB".encode('utf-8')).hexdigest()
cleanup(hash_a)
cleanup(hash_b)

vault_a = ["alice:passA:siteA.com"]
vault_b = ["bob:passB:siteB.com"]

EncryptVaultAndSave(vault_a, "passwordA", hash_a)
EncryptVaultAndSave(vault_b, "passwordB", hash_b)

recovered_a = decryptAndReconstructVault(hash_a, "passwordA")
recovered_b = decryptAndReconstructVault(hash_b, "passwordB")

test("User A vault intact", recovered_a == vault_a)
test("User B vault intact", recovered_b == vault_b)
test("Different vault files", hash_a != hash_b)

# Cross-user access fails
try:
    decryptAndReconstructVault(hash_a, "passwordB")
    test("User B can't decrypt User A's vault", False)
except (SystemExit, ValueError, Exception):
    test("User B can't decrypt User A's vault", True)

cleanup(hash_a)
cleanup(hash_b)


# ============================================================
# SUMMARY
# ============================================================
total = passed + failed
print(f"\n{'='*50}")
print(f"RESULTS: {passed}/{total} passed, {failed} failed")
if failed == 0:
    print("ALL TESTS PASSED")
else:
    print(f"FAILURES DETECTED")
    sys.exit(1)
