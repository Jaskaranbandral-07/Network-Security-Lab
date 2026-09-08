# ---------------------------------------------
# Caesar Cipher  &  Vigenère Cipher
# Encrypt and decrypt the single character "J"
# Shift = 7 letters
# ---------------------------------------------

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# 1. CAESAR CIPHER

def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char in ALPHABET:
            idx = ALPHABET.index(char)
            new_idx = (idx + shift) % 26
            result += ALPHABET[new_idx]
        else:
            result += char
    return result


def caesar_decrypt(text, shift):
    result = ""
    for char in text:
        if char in ALPHABET:
            idx = ALPHABET.index(char)
            new_idx = (idx - shift) % 26
            result += ALPHABET[new_idx]
        else:
            result += char
    return result


# 2. VIGENÈRE CIPHER

def vigenere_encrypt(text, key):
    result = ""
    key_idx = 0
    for char in text:
        if char in ALPHABET:
            char_idx = ALPHABET.index(char)
            key_char = key[key_idx % len(key)]
            key_shift = ALPHABET.index(key_char)
            new_idx = (char_idx + key_shift) % 26
            result += ALPHABET[new_idx]
            key_idx += 1
        else:
            result += char
    return result


def vigenere_decrypt(text, key):
    result = ""
    key_idx = 0
    for char in text:
        if char in ALPHABET:
            char_idx = ALPHABET.index(char)
            key_char = key[key_idx % len(key)]
            key_shift = ALPHABET.index(key_char)
            new_idx = (char_idx - key_shift) % 26
            result += ALPHABET[new_idx]
            key_idx += 1
        else:
            result += char
    return result


# =============================================
# MAIN : user enters the plain text, shift &
# key, and both ciphers encrypt/decrypt it
# =============================================
if __name__ == "__main__":
    # ---- User inputs ----
    original = input("Enter the plain text (letters only): ").upper()
    shift = int(input("Enter the Caesar shift amount (e.g. 7): "))
    key = input("Enter the Vigenere key (e.g. MONKEY): ").upper()

    print()

    # ---- Caesar Cipher ----
    print("=" * 50)
    print(f" CAESAR CIPHER (shift = {shift})")
    print("=" * 50)
    caesar_cipher = caesar_encrypt(original, shift)
    caesar_plain = caesar_decrypt(caesar_cipher, shift)
    print(f" Original   : {original}")
    print(f" Encrypted  : {caesar_cipher}")
    print(f" Decrypted  : {caesar_plain}")
    print(f" Match?     : {caesar_plain == original}")
    print()

    # ---- Vigenère Cipher ----
    print("=" * 50)
    print(f" VIGENÈRE CIPHER (key = '{key}')")
    print("=" * 50)
    vigenere_cipher = vigenere_encrypt(original, key)
    vigenere_plain = vigenere_decrypt(vigenere_cipher, key)
    print(f" Original   : {original}")
    print(f" Encrypted  : {vigenere_cipher}")
    print(f" Decrypted  : {vigenere_plain}")
    print(f" Match?     : {vigenere_plain == original}")
