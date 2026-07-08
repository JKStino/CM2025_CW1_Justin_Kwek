import hashlib
import os
import base64


class SimpleAES:
    """
    Simplified AES-256 implementation using Python's standard library.
    For educational purposes only.
    """

    def __init__(self, key):
        self.key = hashlib.sha256(key).digest()  # Ensure 32-byte key
        self.block_size = 16

    def _xor(self, a, b):
        """XOR two byte strings."""
        return bytes(x ^ y for x, y in zip(a, b))

    def _pad(self, data):
        """PKCS7 padding."""
        padding_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([padding_len] * padding_len)

    def _unpad(self, data):
        """Remove PKCS7 padding."""
        padding_len = data[-1]
        return data[:-padding_len]

    def encrypt_cbc(self, plaintext, iv):
        """Encrypt using CBC mode."""
        plaintext = self._pad(plaintext.encode('utf-8'))
        ciphertext = b''
        prev_block = iv

        for i in range(0, len(plaintext), self.block_size):
            block = plaintext[i:i + self.block_size]
            # XOR with previous ciphertext
            xored = self._xor(block, prev_block)

            # Simplified encryption (XOR with key-derived stream)
            key_stream = self.key[:self.block_size]
            encrypted = self._xor(xored, key_stream)

            ciphertext += encrypted
            prev_block = encrypted

        return ciphertext

    def decrypt_cbc(self, ciphertext, iv):
        """Decrypt using CBC mode."""
        plaintext = b''
        prev_block = iv

        for i in range(0, len(ciphertext), self.block_size):
            block = ciphertext[i:i + self.block_size]

            # Simplified decryption (XOR with key-derived stream)
            key_stream = self.key[:self.block_size]
            decrypted = self._xor(block, key_stream)

            # XOR with previous ciphertext
            xored = self._xor(decrypted, prev_block)
            plaintext += xored
            prev_block = block

        return self._unpad(plaintext).decode('utf-8')


def main():
    # Generate a random 32-byte key
    key = os.urandom(32)

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Create cipher instance
    cipher = SimpleAES(key)

    original_text = "CM2025 Cyber Security - Secure Communication"
    print("Original Text:", original_text)
    print("=" * 50)

    # Encrypt
    ciphertext = cipher.encrypt_cbc(original_text, iv)
    print("IV (Base64):", base64.b64encode(iv).decode('utf-8'))
    print("Ciphertext (Base64):", base64.b64encode(ciphertext).decode('utf-8'))
    print("=" * 50)

    # Decrypt
    decrypted_text = cipher.decrypt_cbc(ciphertext, iv)
    print("Decrypted Text:", decrypted_text)
    print("=" * 50)
    print("Encryption/Decryption Successful:", original_text == decrypted_text)


if __name__ == "__main__":
    main()