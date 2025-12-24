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

#def crc16_le(data: bytes) -> int:
#    crc = 0x0000
#    for b in data:
#        crc ^= b
#        for _ in range(8):
#            if crc & 0x0001:
#                crc = (crc >> 1) ^ 0xA001
#            else:
#                crc >>= 1
#        crc &= 0xFFFF
#    return crc

crc16_le_table = [
    0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
    0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
    0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
    0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
    0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
    0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
    0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
    0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
    0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
    0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
    0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
    0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
    0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
    0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
    0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
    0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
    0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
    0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
    0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
    0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
    0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
    0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
    0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
    0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
    0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
    0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
    0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
    0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
    0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
    0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
    0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
    0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
]

def crc16_le(data: bytes) -> int:
    """
    Compute CRC16 little-endian compatible with esp_rom_crc16_le.
    
    Args:
        crc: Initial CRC value (usually 0).
        data: Bytes over which to compute the CRC.
    
    Returns:
        CRC16 as an integer.
    """
    crc = 0;
    crc = ~crc & 0xFFFF  # Invert initial CRC like in C code
    for b in data:
        crc = crc16_le_table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return ~crc & 0xFFFF  # Final inversion

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

    puk_crc = crc16_le(our_pub_bytes[1::])
    # 8. Output encrypted public key
    print("AT+DHKE=" + f"{puk_crc:04x}" + "," + str(device_iv.hex()) + "," + str(our_pub_bytes.hex())[2::])

    # 4. Read stdin (CRC16 and ECDH public key)
    print("\nWaiting for input:")


    print("Line 1: partial_iv (hex)\n")
    print("Line 2: ECDH P-256 public key (hex)\n")
    print("Line 3: sig (hex)")

    recv_partial_iv_hex = sys.stdin.readline().strip()
    recv_pub_hex = sys.stdin.readline().strip()
    recv_sig_hex = sys.stdin.readline().strip()
    modem_iv = bytes.fromhex(recv_partial_iv_hex)
    recv_sig = bytes.fromhex(recv_sig_hex)

    iv = modem_iv + device_iv + modem_iv + device_iv

    if not recv_partial_iv_hex or not recv_pub_hex or not recv_sig_hex:
        print("Error: missing input", file=sys.stderr)
        sys.exit(1)

    #recv_crc = int(recv_crc_hex, 16)
    recv_pub_bytes = bytes.fromhex(recv_pub_hex)
    sha = hashlib.sha256(recv_pub_bytes).digest()

    ba2 = bytes.fromhex("04")
    assert len(ba2) == 1
    recv_pub_bytes = ba2 + recv_pub_bytes

    # 5. Verify CRC16
    #computed_crc = crc16_le(recv_pub_bytes)
    #if computed_crc != recv_crc:
    #    print("CRC16 verification FAILED", file=sys.stderr)
    #    sys.exit(1)

    #print("CRC16 verification OK")


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
    ciphertext = encryptor.update(recv_sig) + encryptor.finalize()

    print("cipher len", len(ciphertext), "len sha", len(sha))
    assert len(ciphertext) == len(sha)
    print("ciper", ciphertext.hex())
    print("sha", sha.hex())
    for i in range(len(ciphertext)):
        print(i)
        assert(sha[i] == ciphertext[i])



if __name__ == "__main__":
    main()

