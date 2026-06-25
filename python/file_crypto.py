# -*- coding: utf-8 -*-
"""
文件级加解密 (Python 版)
对应 C 代码中的 file_crypto.c
"""

import os
import time
from sm4_engine import sm4_cbc_cts_encrypt, sm4_cbc_cts_decrypt

MAGIC = b'SM4C'   # 文件头标识
HEADER_SIZE = len(MAGIC) + 4 + 16   # MAGIC(4) + 原始长度(4) + IV(16) = 24 字节


def _generate_iv() -> bytes:
    """生成 16 字节随机 IV"""
    return os.urandom(16)


def _bytes_to_human(n: int) -> str:
    """把字节数转成人类可读格式"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.2f} {unit}" if unit != 'B' else f"{n} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def encrypt_file(in_path: str, out_path: str, key: bytes,
                  progress_callback=None) -> dict:
    """
    加密文件. 输出文件格式: [MAGIC | 原始长度(uint32 BE) | IV | 密文]
    返回统计信息 dict.
    """
    t0 = time.perf_counter()

    with open(in_path, 'rb') as f:
        data = f.read()

    file_size = len(data)
    iv = _generate_iv()

    ciphertext = sm4_cbc_cts_encrypt(data, key, iv)

    header = MAGIC + file_size.to_bytes(4, 'big') + iv

    with open(out_path, 'wb') as f:
        f.write(header)
        f.write(ciphertext)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    speed_mbps = (file_size / (1024 * 1024)) / (elapsed_ms / 1000) if elapsed_ms > 0 else 0

    stats = {
        'input_path': in_path,
        'output_path': out_path,
        'plaintext_size': file_size,
        'ciphertext_size': len(ciphertext),
        'elapsed_ms': elapsed_ms,
        'speed_mbps': speed_mbps,
        'iv': iv,
    }

    if progress_callback:
        progress_callback(stats)

    return stats


def decrypt_file(in_path: str, out_path: str, key: bytes,
                  progress_callback=None) -> dict:
    """解密文件"""
    t0 = time.perf_counter()

    with open(in_path, 'rb') as f:
        header = f.read(HEADER_SIZE)
        ciphertext = f.read()

    if len(header) < HEADER_SIZE or header[:len(MAGIC)] != MAGIC:
        raise ValueError("文件不是有效的 SM4 加密文件 (缺少 MAGIC 标识)")

    plaintext_len = int.from_bytes(header[len(MAGIC):len(MAGIC) + 4], 'big')
    iv = header[len(MAGIC) + 4:len(MAGIC) + 4 + 16]

    plaintext = sm4_cbc_cts_decrypt(ciphertext, key, iv, plaintext_len)

    with open(out_path, 'wb') as f:
        f.write(plaintext)

    elapsed_ms = (time.perf_counter() - t0) * 1000
    speed_mbps = (plaintext_len / (1024 * 1024)) / (elapsed_ms / 1000) if elapsed_ms > 0 else 0

    stats = {
        'input_path': in_path,
        'output_path': out_path,
        'plaintext_size': plaintext_len,
        'ciphertext_size': len(ciphertext),
        'elapsed_ms': elapsed_ms,
        'speed_mbps': speed_mbps,
        'iv': iv,
    }

    if progress_callback:
        progress_callback(stats)

    return stats