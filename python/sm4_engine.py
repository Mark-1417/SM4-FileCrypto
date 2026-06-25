# -*- coding: utf-8 -*-
from typing import List, Tuple
import struct
import os
import time

# ============================================================
# SM4 固定参数
# ============================================================

FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

CK = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
]

SBOX = [
    [0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05],
    [0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99],
    [0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62],
    [0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6],
    [0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8],
    [0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35],
    [0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87],
    [0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e],
    [0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1],
    [0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3],
    [0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f],
    [0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51],
    [0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8],
    [0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0],
    [0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84],
    [0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48],
]

MASK32 = 0xFFFFFFFF


def _rotate_left(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32

def _L1(x: int) -> int:
    return x ^ _rotate_left(x, 2) ^ _rotate_left(x, 10) ^ _rotate_left(x, 18) ^ _rotate_left(x, 24)

def _L2(x: int) -> int:
    return x ^ _rotate_left(x, 13) ^ _rotate_left(x, 23)

def _sbox(x: int) -> int:
    b0 = (x >> 24) & 0xFF
    b1 = (x >> 16) & 0xFF
    b2 = (x >> 8) & 0xFF
    b3 = x & 0xFF
    return (SBOX[b0 >> 4][b0 & 0x0F] << 24) | \
           (SBOX[b1 >> 4][b1 & 0x0F] << 16) | \
           (SBOX[b2 >> 4][b2 & 0x0F] << 8) | \
           SBOX[b3 >> 4][b3 & 0x0F]

def _tau(x: int) -> int:
    return _sbox(x)

def _T(x: int) -> int:
    return _L1(_tau(x))

def _T_prime(x: int) -> int:
    return _L2(_tau(x))

def key_expansion(key_bytes: bytes) -> list:
    assert len(key_bytes) == 16, "密钥必须 16 字节"
    K = list(struct.unpack('>4I', key_bytes))
    K[0] ^= FK[0]
    K[1] ^= FK[1]
    K[2] ^= FK[2]
    K[3] ^= FK[3]

    rk = []
    for i in range(32):
        tmp = K[1] ^ K[2] ^ K[3] ^ CK[i]
        new_k = K[0] ^ _T_prime(tmp)
        rk.append(new_k)
        K = [K[1], K[2], K[3], new_k]
    return rk

def sm4_encrypt_block(block_bytes: bytes, rk: list) -> bytes:
    assert len(block_bytes) == 16
    X = list(struct.unpack('>4I', block_bytes))
    for i in range(32):
        tmp = X[1] ^ X[2] ^ X[3] ^ rk[i]
        new_x = X[0] ^ _T(tmp)
        X = [X[1], X[2], X[3], new_x]
    # 反序输出
    return struct.pack('>4I', X[3], X[2], X[1], X[0])

def sm4_decrypt_block(block_bytes: bytes, rk: list) -> bytes:
    assert len(block_bytes) == 16
    X = list(struct.unpack('>4I', block_bytes))
    for i in range(32):
        tmp = X[1] ^ X[2] ^ X[3] ^ rk[31 - i]
        new_x = X[0] ^ _T(tmp)
        X = [X[1], X[2], X[3], new_x]
    return struct.pack('>4I', X[3], X[2], X[1], X[0])

def _bytes_xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def sm4_cbc_cts_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    rk = key_expansion(key)
    n = len(plaintext)
    block_size = 16
    full_blocks = n // block_size
    remainder = n % block_size

    if remainder == 0:
        ciphertext = bytearray()
        prev = iv
        for i in range(full_blocks):
            block = plaintext[i * block_size:(i + 1) * block_size]
            enc = sm4_encrypt_block(_bytes_xor(block, prev), rk)
            ciphertext.extend(enc)
            prev = enc
        return bytes(ciphertext)

    if full_blocks == 0:
        padded = plaintext + b'\x00' * (block_size - remainder)
        return sm4_encrypt_block(_bytes_xor(padded, iv), rk)

    ciphertext = bytearray()
    prev = iv
    for i in range(full_blocks - 1):
        block = plaintext[i * block_size:(i + 1) * block_size]
        enc = sm4_encrypt_block(_bytes_xor(block, prev), rk)
        ciphertext.extend(enc)
        prev = enc

    second_last = plaintext[(full_blocks - 1) * block_size:full_blocks * block_size]
    C_prev = sm4_encrypt_block(_bytes_xor(second_last, prev), rk)

    tail_raw = plaintext[full_blocks * block_size:] 
    padded_last = tail_raw + C_prev[remainder:]
    C_last = sm4_encrypt_block(_bytes_xor(padded_last, prev), rk)

    ciphertext.extend(C_last)
    ciphertext.extend(C_prev[:remainder])

    return bytes(ciphertext)


def sm4_cbc_cts_decrypt(ciphertext: bytes, key: bytes, iv: bytes,
                          plaintext_len: int) -> bytes:
    rk = key_expansion(key)
    block_size = 16
    n = plaintext_len
    full_blocks = n // block_size
    remainder = n % block_size
    if remainder == 0:
        plaintext = bytearray()
        prev = iv
        for i in range(len(ciphertext) // block_size):
            block = ciphertext[i * block_size:(i + 1) * block_size]
            dec = _bytes_xor(sm4_decrypt_block(block, rk), prev)
            plaintext.extend(dec)
            prev = block
        return bytes(plaintext)[:n]

    if full_blocks == 0:
        dec = sm4_decrypt_block(ciphertext[:block_size], rk)
        return _bytes_xor(dec, iv)[:n]

    plaintext = bytearray()
    prev = iv

    for i in range(full_blocks - 1):
        block = ciphertext[i * block_size:(i + 1) * block_size]
        dec = _bytes_xor(sm4_decrypt_block(block, rk), prev)
        plaintext.extend(dec)
        prev = block

    C_last_block = ciphertext[(full_blocks - 1) * block_size:full_blocks * block_size]
    C_prev_tail = ciphertext[full_blocks * block_size:
                               full_blocks * block_size + remainder]
    M_n_decrypted = sm4_decrypt_block(C_last_block, rk)
    M_n = _bytes_xor(M_n_decrypted, prev)
    P_n = M_n[:remainder]
    C_prev_full = C_prev_tail + M_n[remainder:]
    P_prev = _bytes_xor(sm4_decrypt_block(C_prev_full, rk), prev)

    plaintext.extend(P_prev)
    plaintext.extend(P_n)

    return bytes(plaintext)