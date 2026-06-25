# -*- coding: utf-8 -*-
import sys
import os

# 默认密钥: 与 C 版一致 (01234567 89abcdef fedcba98 76543210)
DEFAULT_KEY = bytes.fromhex("0123456789abcdeffedcba9876543210")


def _print_stats(title: str, stats: dict):
    print(f"\n{'=' * 50}")
    print(f"  {title}")
    print(f"{'=' * 50}")
    print(f"  输入文件: {stats['input_path']}")
    print(f"  输出文件: {stats['output_path']}")
    print(f"  明文大小: {stats['plaintext_size']:,} 字节")
    print(f"  密文大小: {stats['ciphertext_size']:,} 字节")
    print(f"  IV:        {stats['iv'].hex()}")
    print(f"  用时:      {stats['elapsed_ms']:.2f} ms")
    print(f"  速度:      {stats['speed_mbps']:.3f} MB/s")
    print(f"{'=' * 50}\n")


def _run_self_test():
    from sm4_engine import sm4_encrypt_block, sm4_decrypt_block, \
                              sm4_cbc_cts_encrypt, sm4_cbc_cts_decrypt, \
                              key_expansion

    print("=== SM4 算法自测 ===\n")

    test_key = DEFAULT_KEY
    test_plain = bytes.fromhex("0123456789abcdeffedcba9876543210")
    rk = key_expansion(test_key)

    # 测试 1: 单块加解密回环
    cipher = sm4_encrypt_block(test_plain, rk)
    decrypted = sm4_decrypt_block(cipher, rk)
    ok1 = decrypted == test_plain
    print(f"  [{'OK' if ok1 else 'FAIL'}] 单块加解密回环")
    print(f"       明文: {test_plain.hex()}")
    print(f"       密文: {cipher.hex()}")
    print(f"       解密: {decrypted.hex()}")

    # 测试 2: CBC-CTS 不同长度
    iv = b'\x00' * 16
    all_ok = True
    for test_len in [16, 32, 100, 1, 15, 17, 200, 1024]:
        data = bytes([(i * 7 + 3) & 0xFF for i in range(test_len)])
        ct = sm4_cbc_cts_encrypt(data, test_key, iv)
        pt = sm4_cbc_cts_decrypt(ct, test_key, iv, len(data))
        ok = pt == data
        all_ok = all_ok and ok
        status = "OK  " if ok else "FAIL"
        print(f"  [{status}] CBC-CTS  len={test_len:>5d}  cipher_len={len(ct):>5d}")

    print()
    print("  自测通过!" if (ok1 and all_ok) else "  自测失败!")
    return ok1 and all_ok


def main():
    args = sys.argv[1:]

    if len(args) == 0 or args[0] == 'gui':
        # 启动 GUI
        try:
            from crypto_app import run_gui
            run_gui()
        except ImportError as e:
            print(f"[错误] 无法启动 GUI: {e}")
            print("请先安装依赖: pip install customtkinter")
        return

    mode = args[0].lower()

    if mode == 'test':
        ok = _run_self_test()
        sys.exit(0 if ok else 1)

    if mode in ('enc', 'dec') and len(args) >= 2:
        from file_crypto import encrypt_file, decrypt_file

        in_file = args[1]
        key = bytes.fromhex(args[2]) if len(args) >= 3 else DEFAULT_KEY

        if not os.path.isfile(in_file):
            print(f"[错误] 文件不存在: {in_file}")
            sys.exit(1)

        if mode == 'enc':
            out_file = in_file + '.sm4'
            stats = encrypt_file(in_file, out_file, key)
            _print_stats("加密完成 ✓", stats)
        else:
            base = in_file
            if base.lower().endswith('.sm4'):
                original_path = base[:-4]
                name, ext = os.path.splitext(original_path)
                out_file = name + "_已解密" + ext
            else:
                out_file = base + ".decrypted"
            stats = decrypt_file(in_file, out_file, key)
            _print_stats("解密完成 ✓", stats)
        return

    # 帮助信息
    print(__doc__)


if __name__ == '__main__':
    main()