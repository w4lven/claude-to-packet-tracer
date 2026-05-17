"""
Cisco Packet Tracer .pkt / .pka file codec — pure Python port of pka2xml.

Pipeline (decrypt):
  1. Deobfuscate (reverse + xor with (length - i*length))
  2. Twofish-EAX decrypt   (key = 0x89 * 16, IV = 0x10 * 16)
  3. Deobfuscate (xor with (size - i))
  4. zlib decompress (first 4 bytes BE = uncompressed length)

Reference: https://github.com/mircodz/pka2xml/blob/master/include/pka2xml.hpp
"""
from __future__ import annotations

import struct
import zlib

from CryptoPlus.Cipher import python_Twofish as Twofish

# -----------------------------------------------------------------------------
# Constants for .pkt / .pka files
# -----------------------------------------------------------------------------
PKA_KEY = bytes([137] * 16)
PKA_IV = bytes([16] * 16)


class PktDecodeError(Exception):
    pass


# -----------------------------------------------------------------------------
# Twofish single-block primitive
# -----------------------------------------------------------------------------
def _tf_encrypt_block(key: bytes, block: bytes) -> bytes:
    c = Twofish.new(key, mode=Twofish.MODE_ECB)
    return c.encrypt(block)


# -----------------------------------------------------------------------------
# CMAC on top of Twofish (NIST SP 800-38B, polynomial 0x87 for 128-bit block)
# -----------------------------------------------------------------------------
def _gf128_double(b: bytes) -> bytes:
    n = int.from_bytes(b, "big")
    n <<= 1
    if n & (1 << 128):
        n ^= 0x87
    n &= (1 << 128) - 1
    return n.to_bytes(16, "big")


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _cmac(key: bytes, msg: bytes) -> bytes:
    L = _tf_encrypt_block(key, bytes(16))
    K1 = _gf128_double(L)
    K2 = _gf128_double(K1)

    if len(msg) == 0 or len(msg) % 16 != 0:
        # pad: append 0x80 then zeros
        pad_len = 16 - (len(msg) % 16)
        last = msg[-(len(msg) % 16):] if (len(msg) % 16) else b""
        last_padded = last + b"\x80" + bytes(pad_len - 1)
        prefix = msg[:len(msg) - len(last)]
        last_block = _xor_bytes(last_padded, K2)
    else:
        prefix = msg[:-16]
        last_block = _xor_bytes(msg[-16:], K1)

    # CBC-MAC: encrypt block-by-block, XOR-chained
    x = bytes(16)
    for i in range(0, len(prefix), 16):
        x = _tf_encrypt_block(key, _xor_bytes(x, prefix[i:i + 16]))
    x = _tf_encrypt_block(key, _xor_bytes(x, last_block))
    return x


# -----------------------------------------------------------------------------
# EAX mode (Bellare-Rogaway-Wagner) on top of Twofish + CMAC
# -----------------------------------------------------------------------------
def _omac(key: bytes, t: int, msg: bytes) -> bytes:
    """OMAC^t_K(M) = CMAC_K( (16-byte block ending in t) || M )"""
    prefix = bytes(15) + bytes([t])
    return _cmac(key, prefix + msg)


def _ctr_xor(key: bytes, counter_block: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = int.from_bytes(counter_block, "big")
    for i in range(0, len(data), 16):
        ks = _tf_encrypt_block(key, counter.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out.extend(_xor_bytes(chunk, ks[:len(chunk)]))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)


def eax_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes,
                assoc_data: bytes = b"") -> bytes:
    if len(ciphertext_with_tag) < 16:
        raise PktDecodeError("EAX: ciphertext too short to contain tag")
    body = ciphertext_with_tag[:-16]
    received_tag = ciphertext_with_tag[-16:]

    N_tag = _omac(key, 0, nonce)
    H_tag = _omac(key, 1, assoc_data)
    C_tag = _omac(key, 2, body)
    computed_tag = _xor_bytes(_xor_bytes(N_tag, H_tag), C_tag)

    if computed_tag != received_tag:
        raise PktDecodeError(
            f"EAX auth tag mismatch:\n"
            f"  computed: {computed_tag.hex()}\n"
            f"  received: {received_tag.hex()}"
        )

    return _ctr_xor(key, N_tag, body)


def eax_encrypt(key: bytes, nonce: bytes, plaintext: bytes,
                assoc_data: bytes = b"") -> bytes:
    N_tag = _omac(key, 0, nonce)
    H_tag = _omac(key, 1, assoc_data)
    body = _ctr_xor(key, N_tag, plaintext)
    C_tag = _omac(key, 2, body)
    tag = _xor_bytes(_xor_bytes(N_tag, H_tag), C_tag)
    return body + tag


# -----------------------------------------------------------------------------
# pka2xml obfuscation stages
# -----------------------------------------------------------------------------
def _stage1_deobf(data: bytes) -> bytes:
    """processed[i] = input[length - i - 1] XOR ((length - i*length) & 0xFF)"""
    length = len(data)
    out = bytearray(length)
    for i in range(length):
        out[i] = data[length - i - 1] ^ ((length - i * length) & 0xFF)
    return bytes(out)


def _stage1_obf(data: bytes) -> bytes:
    """Inverse of stage1: output[length - i - 1] = input[i] XOR ((length - i*length) & 0xFF)"""
    length = len(data)
    out = bytearray(length)
    for i in range(length):
        out[length - i - 1] = data[i] ^ ((length - i * length) & 0xFF)
    return bytes(out)


def _stage3(data: bytes) -> bytes:
    """output[i] = data[i] XOR ((size - i) & 0xFF). Self-inverse."""
    size = len(data)
    return bytes(data[i] ^ ((size - i) & 0xFF) for i in range(size))


# -----------------------------------------------------------------------------
# Public decode / encode
# -----------------------------------------------------------------------------
def decode_pkt(blob: bytes,
               key: bytes = PKA_KEY,
               iv: bytes = PKA_IV) -> bytes:
    """Decode a .pkt/.pka blob into XML bytes."""
    if len(blob) < 20:
        raise PktDecodeError("file too small")

    s1 = _stage1_deobf(blob)
    s2 = eax_decrypt(key, iv, s1)
    s3 = _stage3(s2)

    if len(s3) < 4:
        raise PktDecodeError("decompression input too short")
    uncompressed_len = struct.unpack(">I", s3[:4])[0]
    try:
        xml = zlib.decompress(s3[4:])
    except zlib.error as e:
        raise PktDecodeError(f"zlib decompress failed: {e}") from e

    if uncompressed_len and abs(len(xml) - uncompressed_len) > 16:
        # Soft check — some PT versions write a slightly off header
        pass

    return xml


def encode_pkt(xml: bytes,
               key: bytes = PKA_KEY,
               iv: bytes = PKA_IV) -> bytes:
    """Encode XML bytes back into a .pkt blob."""
    compressed = zlib.compress(xml, level=9)
    header = struct.pack(">I", len(xml))
    s3_input = header + compressed
    s2_input = _stage3(s3_input)
    s1_input = eax_encrypt(key, iv, s2_input)
    return _stage1_obf(s1_input)
