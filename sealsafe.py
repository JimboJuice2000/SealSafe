#!/usr/bin/env python3

import argparse
import os
import sys
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

logo = f"""{Fore.CYAN}
███████╗███████╗ █████╗ ██╗     ███████╗ █████╗ ███████╗███████╗
██╔════╝██╔════╝██╔══██╗██║     ██╔════╝██╔══██╗██╔════╝██╔════╝
███████╗█████╗  ███████║██║     ███████╗███████║█████╗  █████╗  
╚════██║██╔══╝  ██╔══██║██║     ╚════██║██╔══██║██╔══╝  ██╔══╝  
███████║███████╗██║  ██║███████╗███████║██║  ██║██║     ███████╗
╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝
{Style.RESET_ALL}"""

def main():
    parser = argparse.ArgumentParser(description="SealSafe - File Security CLI Tool", add_help=False)
    parser.add_argument("-e", "--encrypt", nargs=2, metavar=("MODE", "FILE"), help="Encrypt a file using aes, des, or rsa")
    parser.add_argument("-d", "--decrypt", nargs=2, metavar=("MODE", "FILE"), help="Decrypt a file using aes, des, or rsa")
    parser.add_argument("--rsa-genkeys", help="Generate RSA key pair", action="store_true")
    parser.add_argument("--ecdsa-genkeys", help="Generate ECDSA key pair", action="store_true")
    parser.add_argument("--sign", nargs=2, metavar=("ALGORITHM", "FILE"), help="Sign a file using rsa or ecdsa")
    parser.add_argument("--verify", nargs=3, metavar=("ALGORITHM", "FILE", "SIGFILE"), 
                      help="Verify a file's signature using rsa or ecdsa")
    parser.add_argument("--shred", metavar="FILE", help="Securely delete a file by overwriting it")
    parser.add_argument("--integrity-check", metavar="FILE", help="Verify integrity of an encrypted file")
    parser.add_argument("-h", "--help", action="store_true", help="Show help message and exit")
    args = parser.parse_args()

    if args.help or not any(vars(args).values()):
        print(logo)
        parser.print_help()
        return

    if args.rsa_genkeys:
        generate_rsa_keys()
    elif args.ecdsa_genkeys:
        generate_ecdsa_keys()
    elif args.encrypt:
        mode, file = args.encrypt
        if mode == "aes":
            aes_encrypt(file)
        elif mode == "des":
            des_encrypt(file)
        elif mode == "rsa":
            rsa_encrypt(file)
        else:
            print(f"{Fore.RED}Unknown encryption mode: {mode}")
    elif args.decrypt:
        mode, file = args.decrypt
        if mode == "aes":
            aes_decrypt(file)
        elif mode == "des":
            des_decrypt(file)
        elif mode == "rsa":
            rsa_decrypt(file)
        else:
            print(f"{Fore.RED}Unknown decryption mode: {mode}")
    elif args.sign:
        algorithm, file = args.sign
        if algorithm == "rsa":
            rsa_sign_file(file)
        elif algorithm == "ecdsa":
            ecdsa_sign_file(file)
        else:
            print(f"{Fore.RED}Unknown signing algorithm: {algorithm}")
    elif args.verify:
        algorithm, file, sigfile = args.verify
        if algorithm == "rsa":
            rsa_verify_signature(file, sigfile)
        elif algorithm == "ecdsa":
            ecdsa_verify_signature(file, sigfile)
        else:
            print(f"{Fore.RED}Unknown verification algorithm: {algorithm}")
    elif args.shred:
        secure_delete(args.shred)
    elif args.integrity_check:
        verify_integrity(args.integrity_check)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    with open("rsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("rsa_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"{Fore.GREEN}RSA key pair generated: rsa_private.pem, rsa_public.pem")

def generate_ecdsa_keys():
    
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open("ecdsa_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("ecdsa_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print(f"{Fore.GREEN}ECDSA key pair generated: ecdsa_private.pem, ecdsa_public.pem")

def rsa_sign_file(file_path):
    if not os.path.exists("rsa_private.pem"):
        print(f"{Fore.RED}RSA private key not found. Generate RSA keys first.")
        return

    with open("rsa_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    sig_path = file_path + ".rsa.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"{Fore.GREEN}File signed with RSA successfully. Signature saved to: {sig_path}")

def rsa_verify_signature(file_path, sig_path):
    if not os.path.exists("rsa_public.pem"):
        print(f"{Fore.RED}RSA public key not found. Generate RSA keys first.")
        return

    with open("rsa_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(file_path, "rb") as f:
        data = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print(f"{Fore.GREEN}RSA signature is valid. The file has not been tampered with.")
    except InvalidSignature:
        print(f"{Fore.RED}RSA signature verification failed. The file may have been tampered with.")
    except Exception as e:
        print(f"{Fore.RED}Error during RSA verification: {e}")

def ecdsa_sign_file(file_path):
    if not os.path.exists("ecdsa_private.pem"):
        print(f"{Fore.RED}ECDSA private key not found. Generate ECDSA keys first.")
        return

    with open("ecdsa_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(file_path, "rb") as f:
        data = f.read()

    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    sig_path = file_path + ".ecdsa.sig"
    with open(sig_path, "wb") as f:
        f.write(signature)

    print(f"{Fore.GREEN}File signed with ECDSA successfully. Signature saved to: {sig_path}")

def ecdsa_verify_signature(file_path, sig_path):
    if not os.path.exists("ecdsa_public.pem"):
        print(f"{Fore.RED}ECDSA public key not found. Generate ECDSA keys first.")
        return

    with open("ecdsa_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(file_path, "rb") as f:
        data = f.read()

    with open(sig_path, "rb") as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        print(f"{Fore.GREEN}ECDSA signature is valid. The file has not been tampered with.")
    except InvalidSignature:
        print(f"{Fore.RED}ECDSA signature verification failed. The file may have been tampered with.")
    except Exception as e:
        print(f"{Fore.RED}Error during ECDSA verification: {e}")
        
def aes_encrypt(file_path):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = aesgcm.encrypt(nonce, data, None)

    
    hmac_key = os.urandom(32)  # 256-bit HMAC key
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(encrypted)
    hmac_tag = h.finalize()

    out_path = file_path + ".aes"
    with open(out_path, "wb") as f:
        f.write(nonce + hmac_tag + encrypted)

    with open(out_path + ".key", "w") as kf:
        kf.write(aes_key.hex() + "\n" + hmac_key.hex())

    print(f"{Fore.GREEN}File encrypted: {out_path}")
    print(f"{Fore.YELLOW}Keys saved to: {out_path}.key")

def aes_decrypt(file_path):
    key_file = file_path + ".key"
    if not os.path.exists(key_file):
        print(f"{Fore.RED}Missing key file: {key_file}")
        return

    with open(key_file, "r") as kf:
        keys = kf.read().splitlines()
        aes_key = bytes.fromhex(keys[0])
        hmac_key = bytes.fromhex(keys[1])

    with open(file_path, "rb") as f:
        nonce = f.read(12)
        hmac_tag = f.read(32)  # SHA256 produces 32-byte
        ciphertext = f.read()

    # Verify HMAC first
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(ciphertext)
    try:
        h.verify(hmac_tag)
    except InvalidTag:
        print(f"{Fore.RED}Integrity check failed! File may have been tampered with.")
        return

    # Then decrypt
    aesgcm = AESGCM(aes_key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        out_path = file_path.replace(".aes", ".decrypted")
        with open(out_path, "wb") as f:
            f.write(decrypted)
        print(f"{Fore.GREEN}File decrypted and integrity verified: {out_path}")
    except Exception as e:
        print(f"{Fore.RED}Decryption failed: {e}")

def des_encrypt(file_path):
    des_key = os.urandom(8)
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, "rb") as f:
        data = f.read()

    padding_len = 8 - len(data) % 8
    data += bytes([padding_len] * padding_len)

    encrypted = encryptor.update(data) + encryptor.finalize()

    # Generate HMAC
    hmac_key = os.urandom(32)
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(encrypted)
    hmac_tag = h.finalize()

    out_path = file_path + ".des"
    with open(out_path, "wb") as f:
        f.write(iv + hmac_tag + encrypted)

    with open(out_path + ".key", "w") as kf:
        kf.write(des_key.hex() + "\n" + hmac_key.hex())

    print(f"{Fore.GREEN}File encrypted (DES): {out_path}")
    print(f"{Fore.YELLOW}Keys saved to: {out_path}.key")

def des_decrypt(file_path):
    key_file = file_path + ".key"
    if not os.path.exists(key_file):
        print(f"{Fore.RED}Missing key file: {key_file}")
        return

    with open(key_file, "r") as kf:
        keys = kf.read().splitlines()
        des_key = bytes.fromhex(keys[0])
        hmac_key = bytes.fromhex(keys[1])

    with open(file_path, "rb") as f:
        iv = f.read(8)
        hmac_tag = f.read(32)
        encrypted = f.read()

    # Verify HMAC
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(encrypted)
    try:
        h.verify(hmac_tag)
    except InvalidTag:
        print(f"{Fore.RED}Integrity check failed! File may have been tampered with.")
        return

    cipher = Cipher(algorithms.TripleDES(des_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    padding_len = decrypted[-1]
    decrypted = decrypted[:-padding_len]

    out_path = file_path.replace(".des", ".decrypted")
    with open(out_path, "wb") as f:
        f.write(decrypted)

    print(f"{Fore.GREEN}DES decryption successful (integrity verified): {out_path}")

def verify_integrity(file_path):
    if file_path.endswith(".aes"):
        key_file = file_path + ".key"
        if not os.path.exists(key_file):
            print(f"{Fore.RED}Missing key file: {key_file}")
            return

        with open(key_file, "r") as kf:
            keys = kf.read().splitlines()
            hmac_key = bytes.fromhex(keys[1])

        with open(file_path, "rb") as f:
            nonce = f.read(12)
            hmac_tag = f.read(32)
            ciphertext = f.read()

        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(ciphertext)
        try:
            h.verify(hmac_tag)
            print(f"{Fore.GREEN}Integrity verified: {file_path} has not been tampered with.")
        except InvalidTag:
            print(f"{Fore.RED}Integrity check failed! File may have been tampered with.")

    elif file_path.endswith(".des"):
        key_file = file_path + ".key"
        if not os.path.exists(key_file):
            print(f"{Fore.RED}Missing key file: {key_file}")
            return

        with open(key_file, "r") as kf:
            keys = kf.read().splitlines()
            hmac_key = bytes.fromhex(keys[1])

        with open(file_path, "rb") as f:
            iv = f.read(8)
            hmac_tag = f.read(32)
            ciphertext = f.read()

        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(ciphertext)
        try:
            h.verify(hmac_tag)
            print(f"{Fore.GREEN}Integrity verified: {file_path} has not been tampered with.")
        except InvalidTag:
            print(f"{Fore.RED}Integrity check failed! File may have been tampered with.")
    else:
        print(f"{Fore.YELLOW}Integrity checking is only supported for AES and DES encrypted files.")

def rsa_encrypt(file_path):
    if not os.path.exists("rsa_public.pem"):
        print(f"{Fore.RED}Public key not found. Generate RSA keys first.")
        return

    with open("rsa_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open(file_path, "rb") as f:
        data = f.read()

    if len(data) > 190:
        print(f"{Fore.RED}File too large for RSA encryption. Must be < 190 bytes.")
        return

    encrypted = public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    out_path = file_path + ".rsa"
    with open(out_path, "wb") as f:
        f.write(encrypted)

    print(f"{Fore.GREEN}File encrypted with RSA: {out_path}")

def rsa_decrypt(file_path):
    if not os.path.exists("rsa_private.pem"):
        print(f"{Fore.RED}Private key not found. Generate RSA keys first.")
        return

    with open("rsa_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open(file_path, "rb") as f:
        encrypted = f.read()

    try:
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        out_path = file_path.replace(".rsa", ".decrypted")
        with open(out_path, "wb") as f:
            f.write(decrypted)
        print(f"{Fore.GREEN}RSA decryption successful: {out_path}")
    except Exception as e:
        print(f"{Fore.RED}RSA decryption failed: {e}")

def secure_delete(file_path: str, passes: int = 3):
    
    try:
        if not os.path.exists(file_path):
            print(f"{Fore.RED}File not found: {file_path}")
            return

        file_size = os.path.getsize(file_path)
        
        with open(file_path, "rb+") as f:
            for _ in range(passes):
                # Overwrite with random data
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        # Rename file to obscure original name
        temp_name = file_path + ".shred"
        os.rename(file_path, temp_name)
        
        # Finally delete the file
        os.remove(temp_name)
        print(f"{Fore.GREEN}File securely shredded: {file_path}")
        
    except PermissionError:
        print(f"{Fore.RED}Permission denied: Could not shred {file_path}")
    except Exception as e:
        print(f"{Fore.RED}Error during file shredding: {e}")

if __name__ == "__main__":
    main()