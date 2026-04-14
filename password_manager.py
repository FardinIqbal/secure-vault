# -*- coding: utf-8 -*-
"""Secure Vault -- Authenticated encryption password manager with AES-128 GCM."""

import os
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from base64 import b64decode
import json
from base64 import b64encode
import os.path
import hashlib
import random
import string
import sys

#PasswordVault is a List of String
# Each string in a password value is of the form: ``username:password:domain''

def encryptFile(plaintextData, key):
    # Empty header per AES-GCM spec --- we don't need authenticated associated data
    header = b""
    # GCM generates a random nonce internally (16 bytes by default)
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(header)
    # encrypt_and_digest returns (ciphertext, authentication tag) in one pass
    ciphertext, tag = cipher.encrypt_and_digest(plaintextData)
    # Bundle nonce + header + ciphertext + tag as base64 JSON for safe file storage
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    json_v = [b64encode(x).decode('utf-8') for x in [cipher.nonce, header, ciphertext, tag]]
    encryptionResults = json.dumps(dict(zip(json_k, json_v)))
    return encryptionResults


def decryptFile(encryptedJson, key):
    # Parse the JSON and decode each base64 field back to raw bytes
    b64 = json.loads(encryptedJson)
    json_k = ['nonce', 'header', 'ciphertext', 'tag']
    jv = {k: b64decode(b64[k]) for k in json_k}
    # Reconstruct cipher with the same nonce used during encryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])
    cipher.update(jv['header'])
    # decrypt_and_verify both decrypts AND checks the authentication tag ---
    # raises ValueError if even a single bit was tampered with
    decryptionResults = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])
    return decryptionResults

# computerMasterKey : String -> String of bytes
# Calculates the encryption key from the user password
def computerMasterKey(password):
    # Constant salt for simplicity
    # In production, this would be a unique random salt per user stored alongside the vault
    salt = b"<\n<~\x0e\xeetGR\xfe;\xec \xfc)8"
    # scrypt is memory-hard: N=2^14 sets the CPU/memory cost, r=8 block size, p=1 parallelism
    # Output is a 16-byte (128-bit) key suitable for AES-128
    key = scrypt(password, salt, 16, N=2**14, r=8, p=1)
    return key


def decryptAndReconstructVault(hashedusername, password):
    key = computerMasterKey(password)
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'

    with open(hashedusername, "r") as file:
        fileread = file.read()
    file.close()
    decryptedresults = decryptFile(fileread, key)
    decodedContent = decryptedresults.decode('utf-8')
    # The magic string acts as a decryption canary: if it's not at the front,
    # either the password is wrong or this vault belongs to a different user
    # who happens to share the same hashed username
    if not decodedContent.startswith(magicString):
        print("Error: Decryption failed. Wrong master password or corrupt vault.")
        sys.exit(1)
    # Strip the magic string --- the rest is pure vault data
    decodedContent = decodedContent[len(magicString):]
    passwordvault = []
    for line in decodedContent.splitlines():
        if line.strip():
            passwordvault.append(line)
    return passwordvault

def checkVaultExistenceOrCreate():
    passwordvault = []
    while True:
        username = input('enter vault username: ')
        password = input('enter vault password: ')

        if username and password:
            break

    # SHA-256 of the username becomes the vault filename ---
    # this avoids storing usernames in plaintext on disk
    hashedusername = hashlib.sha256(username.encode('utf-8')).hexdigest()
    if (os.path.exists(hashedusername)):
        passwordvault = decryptAndReconstructVault(hashedusername, password)

    else:
        print("Password vault not found, creating a new one")
        pass

    return username, password, hashedusername, passwordvault

def generatePassword():
    # 16-character password drawn from uppercase, lowercase, and digits (62 possible chars)
    # Gives ~95 bits of entropy (log2(62^16) ≈ 95.27)
    characters = string.ascii_uppercase + string.ascii_lowercase + string.digits
    result = ''.join(random.choice(characters) for _ in range(16))
    return result


def AddPassword(passwordvault):
    username = input('Enter username: ')
    password = input('Enter password: ')
    domain = input('Enter domain: ')
    entry = username + ':' + password + ':' + domain
    passwordvault.append(entry)
    print('Record Entry added')

def CreatePassword(passwordvault):
    username = input('Enter username: ')
    domain = input('Enter domain: ')
    password = generatePassword()
    print('Generated password: ' + password)
    entry = username + ':' + password + ':' + domain
    passwordvault.append(entry)
    print('Record Entry added')

def UpdatePassword(passwordvault):
    domain = input('Enter domain to update: ')
    for i in range(len(passwordvault)):
        parts = passwordvault[i].split(':')
        if parts[2] == domain:
            newpassword = generatePassword()
            print('New generated password: ' + newpassword)
            passwordvault[i] = parts[0] + ':' + newpassword + ':' + parts[2]
            print('Record Entry Updated')
            return
    print('Domain not found')

def LookupPassword(passwordvault):
    domain = input('Enter domain to lookup: ')
    for entry in passwordvault:
        parts = entry.split(':')
        if parts[2] == domain:
            print('Username: ' + parts[0])
            print('Password: ' + parts[1])
            print('Domain: ' + parts[2])
            return
    print('Domain not found')

def DeletePassword(passwordvault):
    domain = input('Enter domain to delete: ')
    for i in range(len(passwordvault)):
        parts = passwordvault[i].split(':')
        if parts[2] == domain:
            passwordvault.pop(i)
            print('Record Entry Deleted')
            return
    print('Domain not found')

def displayVault(passwordvault):
    print(passwordvault)

def EncryptVaultAndSave(passwordvault, password, hashedusername):
    writeString = ''
    magicString = '101010101010101010102020202020202020202030303030303030303030\n'
    # writeString + magicString
    key = computerMasterKey(password)
    finalString = ''
    finalString = finalString + magicString

    for i in passwordvault:
        record = i + '\n'
        finalString = finalString + record

    finaldbBytes = bytes(finalString, 'utf-8')
    finaldbBytesEncrypted = encryptFile(finaldbBytes, key)

    with open(hashedusername, "w") as file:
        file.write(finaldbBytesEncrypted)
    file.close()
    print("Password Vault encrypted and saved to file")


def main():
    username, password, hashedusername, passwordvault = checkVaultExistenceOrCreate()
    while(True):

        print('Password Management')
        print('-----------------------')
        print('-----------------------')
        print('1 - Add password')
        print('2 - Create password')
        print('3 - Update password')
        print('4 - Lookup password')
        print('5 - Delete password')
        print('6 - Display Vault')
        print('7 - Save Vault and Quit')
        choice = input('')


        if choice == ('1'):
            AddPassword(passwordvault)

        elif choice == ('2'):
            CreatePassword(passwordvault)

        elif choice == ('3'):
            UpdatePassword(passwordvault)

        elif choice == ('4'):
            LookupPassword(passwordvault)

        elif choice == ('5'):
            DeletePassword(passwordvault)
        elif choice == ('6'):
            displayVault(passwordvault)

        elif choice == ('7'):
            EncryptVaultAndSave(passwordvault, password, hashedusername)
            quit()
        else:
            print('Invalid choice please try again')

if __name__ == "__main__":
    main()
