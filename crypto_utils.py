import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def aes_encrypt(file_path):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = aesgcm.encrypt(nonce, data, None)

    out_path = file_path + ".aes"
    with open(out_path, "wb") as f:
        f.write(nonce + encrypted)

    with open(out_path + ".key", "w") as kf:
        kf.write(aes_key.hex())

    return out_path, out_path + ".key"

def aes_decrypt(file_path):
    key_file = file_path + ".key"
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Missing key file: {key_file}")

    with open(key_file, "r") as kf:
        aes_key = bytes.fromhex(kf.read())

    with open(file_path, "rb") as f:
        nonce = f.read(12)
        ciphertext = f.read()

    aesgcm = AESGCM(aes_key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted

def des_encrypt(file_path):
    des_key = os.urandom(8)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        data = f.read()

    # Padding to multiple of 8 bytes
    padding_len = 8 - len(data) % 8
    data += bytes([padding_len] * padding_len)

    encrypted = encryptor.update(data) + encryptor.finalize()

    out_path = file_path + ".des"
    with open(out_path, "wb") as f:
        f.write(iv + encrypted)

    with open(out_path + ".key", "w") as kf:
        kf.write(des_key.hex())

    return out_path, out_path + ".key"

def des_decrypt(file_path):
    key_file = file_path + ".key"
    if not os.path.exists(key_file):
        raise FileNotFoundError(f"Missing key file: {key_file}")

    with open(key_file, "r") as kf:
        des_key = bytes.fromhex(kf.read())

    with open(file_path, "rb") as f:
        iv = f.read(8)
        encrypted = f.read()

    cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    padding_len = decrypted[-1]
    decrypted = decrypted[:-padding_len]
    return decrypted

def rsa_encrypt(file_path, public_key_path="rsa_public.pem"):
    if not os.path.exists(public_key_path):
        raise FileNotFoundError(f"Public key not found at: {public_key_path}")

    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) > 190:
        raise ValueError("File too large for RSA encryption. Must be < 190 bytes.")

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    out_path = file_path + ".rsa"
    with open(out_path, "wb") as f:
        f.write(encrypted)

    return out_path

def rsa_decrypt(file_path, private_key_path="rsa_private.pem"):
    if not os.path.exists(private_key_path):
        raise FileNotFoundError(f"Private key not found at: {private_key_path}")

    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(file_path, "rb") as f:
        encrypted = f.read()

    decrypted = private_key.decrypt(
        encrypted,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted
