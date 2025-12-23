#!/usr/bin/env python3

#some AI generated SLOP

import sys
import os
import socket
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

# ---------------- CRC16 (CCITT-FALSE) ----------------

#def crc16_ccitt_false(data: bytes) -> int:
#    crc = 0xFFFF
#    for b in data:
#        crc ^= b << 8
#        for _ in range(8):
#            if crc & 0x8000:
#                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
#            else:
#                crc = (crc << 1) & 0xFFFF
#    return crc

def crc16_le(data: bytes) -> int:
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
        crc &= 0xFFFF
    return crc

# ---------------- AES-256-CTR ----------------

def aes_256_ctr_encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(16)  # 128-bit nonce for CTR
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + ciphertext  # prepend nonce for transport

# ---------------- Main ----------------

def main():
    # 1. Generate AES-256 key
    aes_key = os.urandom(32)

    # 2. Compute CRC16 of AES key
    aes_crc = crc16_le(aes_key)

    # 3. Print AES key + CRC16
    print("AT+PROV=" + f"{aes_crc:04x}" + "," +str(aes_key.hex()))

    # 6. ECDH P-256 key exchange
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    our_public_key = private_key.public_key()
    our_pub_bytes = our_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )


    device_iv = os.urandom(4)

    puk_crc = crc16_le(our_pub_bytes)
    # 8. Output encrypted public key
    print("AT+DHKE=" + f"{puk_crc:04x}" + "," + str(device_iv.hex()) + "," + str(our_pub_bytes.hex())[2::])

    # 4. Read stdin (CRC16 and ECDH public key)
    print("\nWaiting for input:")


    #print("Line 1: CRC16 of ECDH P-256 public key (hex)")
    print("Line 2: ECDH P-256 public key (hex)\n")
    print("Line 3: partial_iv (hex)\n")

    #recv_crc_hex = sys.stdin.readline().strip()
    recv_pub_hex = sys.stdin.readline().strip()
    recv_partial_iv_hex = sys.stdin.readline().strip()
    modem_iv = bytes.fromhex(recv_partial_iv_hex)

    iv = modem_iv + device_iv + modem_iv + device_iv

    if not recv_partial_iv_hex or not recv_pub_hex:
        print("Error: missing input", file=sys.stderr)
        sys.exit(1)

    #recv_crc = int(recv_crc_hex, 16)
    recv_pub_bytes = bytes.fromhex(recv_pub_hex)
    ba2 = bytes.fromhex(4)
    recv_pub_bytes = ba2 + recv_pub_bytes

    # 5. Verify CRC16
    #computed_crc = crc16_le(recv_pub_bytes)
    #if computed_crc != recv_crc:
    #    print("CRC16 verification FAILED", file=sys.stderr)
    #    sys.exit(1)

    #print("CRC16 verification OK")

    sha = hashlib.sha256(recv_pub_bytes).digest().hex()

    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        recv_pub_bytes
    )
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)


    # Encrypt
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CTR(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    print("sighex: " + str(ciphertext.hex()))


if __name__ == "__main__":
    main()

