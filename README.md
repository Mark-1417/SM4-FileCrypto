# SM4 文件加解密系统

基于国密 **SM4** 算法的文件加密/解密工具，采用 **CBC-CTS** 分组模式，支持任意长度文件的无填充加密。

---

## 目录结构

```
大作业/
├── python/                          # Python 实现（核心）
│   ├── sm4_engine.py                # SM4 核心算法（密钥扩展 / 分组加解密 / CBC-CTS）
│   ├── file_crypto.py               # 文件级加解密（文件头格式 / 读写 / 速度统计）
│   ├── main.py                      # 命令行入口 + 算法自测
│   ├── crypto_app.py                # GUI 界面
│   └── requirements.txt             # 依赖声明
├── SM4FileCrypto.exe                # 打包好的可执行程序
└── README.md
```

---

## 1. sm4_engine.py —— SM4 密码算法核心

这是整个系统的**算法核心**，完全按照 **GB/T 32907-2016**（SM4 国密标准）实现。包含以下部分：

### 1.1 固定参数（SM4 标准定义）

| 参数 | 说明 |
|---|---|
| `FK[4]` | 密钥扩展使用的系统参数 |
| `CK[32]` | 密钥扩展使用的固定参数（每轮一个） |
| `SBOX[16×16]` | 非线性置换 S 盒，按字节查表 |

### 1.2 基础运算函数

| 函数 | 作用 |
|---|---|
| `_rotate_left(x, n)` | 32 位整数**循环左移** n 位 |
| `_sbox(x)` | 32 位整数拆成 4 个字节，分别查 S 盒后再拼回 |
| `_L1(x)` / `_L2(x)` | 线性置换 L（分别用于**轮函数**和**密钥扩展**） |
| `_T(x)` / `_T_prime(x)` | 合成置换 T = L ∘ τ（τ 即 S 盒置换） |

### 1.3 密钥扩展 —— `key_expansion(key_bytes)`

- 输入：**16 字节**密钥（128 位）
- 输出：**32 个轮密钥** `rk[0]..rk[31]`
- 流程：
  1. 将 16 字节密钥拆成 4 个 32 位整数 `K0..K3`
  2. 分别与 FK 参数异或作为初始状态
  3. 循环 32 轮，每轮用 `T'` 置换生成新的轮密钥 `rk[i]`

### 1.4 单块加密 —— `sm4_encrypt_block(block_bytes, rk)`

- 输入：16 字节明文块 + 32 个轮密钥
- 输出：16 字节密文块
- **Feistel 结构**：32 轮迭代，每轮 `X[0] ← X[0] XOR T(X[1] XOR X[2] XOR X[3] XOR rk[i])`
- 最后**反序输出** `(X3, X2, X1, X0)`

### 1.5 单块解密 —— `sm4_decrypt_block(block_bytes, rk)`

与加密完全相同，**唯一区别**是轮密钥**逆序使用**：`rk[31], rk[30], ..., rk[0]`

### 1.6 CBC-CTS 模式 —— `sm4_cbc_cts_encrypt` / `_decrypt`

> **为什么用 CTS？** 普通 CBC 需要把最后不足 16 字节的块补齐（Padding），会让密文比明文大。**CTS（Ciphertext Stealing）** 通过"偷"倒数第二块的末尾字节来填充最后一块，让**密文长度 = 明文长度**，无冗余。

**加密流程：**

```
明文:  P1  P2  ...  Pn-1  Pn    (Pn 长度 < 16)

步骤:
  1) C1 = SM4(P1 XOR IV)
  2) C2 = SM4(P2 XOR C1)
     ...
  *) Cn-1 = SM4(Pn-1 XOR Cn-2)   ← 正常加密倒数第二块
  *) Padded = Pn || Cn-1[len(Pn):] ← 用 Cn-1 的尾部把 Pn 补齐到 16 字节
  *) Cn = SM4(Padded XOR Cn-2)    ← 加密补齐后的"最后一块"
  *) 最终密文: C1, C2, ..., Cn-2, Cn, Cn-1[:len(Pn)]
                                   ↑ 最后两块交换，且 Cn-1 只保留前 len(Pn) 字节
```

**解密**做反向操作：从倒数第二块中还原出原始 Cn-1，再正常解密。

> **关键细节**：解密时必须知道**原始明文长度** `plaintext_len`（存储在文件头中），否则无法正确切割 CTS 的最后两块。

---

## 2. file_crypto.py —— 文件级加解密

在 SM4 算法之上，定义**加密文件格式**和文件读写逻辑。

### 2.1 加密文件格式

```
文件头 (HEADER_SIZE = 24 字节) + 密文数据

┌─────────┬──────────┬──────────┬────────────────────┐
│ MAGIC   │ 明文长度 │ IV       │  CBC-CTS 密文 ...   │
│ (4 字节)│ (4 字节) │ (16 字节)│  (可变长)           │
│ "SM4C"  │ big-endian│ 随机    │  长度 = 明文长度   │
└─────────┴──────────┴──────────┴────────────────────┘

总计: 24 字节文件头 + N 字节密文
```

| 字段 | 作用 |
|---|---|
| `MAGIC = b'SM4C'` | 标识文件类型，解密时先校验，防止误操作 |
| 明文长度 (4 字节 BE) | **关键**：CTS 解密时必须知道原始明文长度 |
| IV (16 字节) | 每次加密随机生成 `os.urandom(16)`，不需要保密但必须唯一 |
| 密文数据 | `sm4_cbc_cts_encrypt()` 的输出 |

### 2.2 `encrypt_file(in_path, out_path, key)`

加密流程：
1. 读取整个明文文件到内存
2. 用 `os.urandom(16)` 生成随机 IV
3. 调用 `sm4_cbc_cts_encrypt()` 加密
4. 写入文件头 `MAGIC + 明文长度 + IV`
5. 写入密文数据
6. 记录**耗时**和**速度**（MB/s），返回 `stats` 字典

### 2.3 `decrypt_file(in_path, out_path, key)`

解密流程：
1. 读取前 24 字节文件头
2. **校验 MAGIC**，如果不是 `SM4C` 则抛出 `ValueError`
3. 从文件头取出明文长度和 IV
4. 调用 `sm4_cbc_cts_decrypt()` 解密
5. 写入解密后的明文
6. 同样返回 `stats` 字典（时间/速度统计）

### 2.4 返回值 `stats` 字典

两个函数都返回统一的统计信息，方便日志/GUI 展示：

```python
{
    'input_path':       '...',     # 输入文件路径
    'output_path':      '...',     # 输出文件路径
    'plaintext_size':   12345,     # 明文字节数
    'ciphertext_size':  12345,     # 密文字节数
    'elapsed_ms':       42.17,     # 总耗时（毫秒）
    'speed_mbps':       23.714,    # 处理速度（MB/秒）
    'iv':               b'...',    # 使用的 IV
}
```

---

## 3. main.py —— 命令行入口与自测

这是项目的**入口文件**，提供三种运行方式。

### 3.1 方式一：启动 GUI（默认）

```bash
python main.py          # 等价于 python main.py gui
python crypto_app.py    # 也可以直接启动 GUI 脚本
```

### 3.2 方式二：算法自测

```bash
python main.py test
```

**自测内容**：
1. **单块回环测试**：加密标准明文 `0123456789abcdeffedcba9876543210`，解密后应与明文一致
2. **CBC-CTS 多长度测试**：分别加密 1、15、16、17、32、100、200、1024 字节的数据，解密后逐一比对

这一步是**验证算法正确性的关键**——确保算法实现与国密标准一致。
<img width="1020" height="592" alt="image" src="https://github.com/user-attachments/assets/fa62b1c0-d503-41fd-93cc-ada45316fd43" />

### 3.3 方式三：命令行加解密

```bash
# 使用默认密钥加密
python main.py enc  test.txt              # 输出 test.txt.sm4

# 使用自定义密钥加密（32 位 hex = 16 字节）
python main.py enc  test.txt  aabbccdd11223344aabbccdd11223344

# 解密
python main.py dec  test.txt.sm4          # 输出 test_已解密.txt
```

**默认密钥**（用于演示，实际使用请传入自定义密钥）：

```
0123456789abcdeffedcba9876543210
```

---

## 4. crypto_app.py —— GUI 界面

基于 `customtkinter` 的图形界面。包含两个 Tab：

| Tab | 功能 |
|---|---|
| 加密 | 选择文件 → 输入密钥 → 点击加密 → 输出 `.sm4` 文件 |
| 解密 | 选择 `.sm4` 文件 → 输入密钥 → 点击解密 → 还原原始文件 |

GUI 会在操作完成后显示**文件大小、耗时、处理速度**等统计信息。

---

## 5. 密钥说明

- **密钥长度**：SM4 要求 **128 位 = 16 字节**
- **输入方式**：在 GUI 或 CLI 中输入 32 个 hex 字符（例如 `0123456789abcdeffedcba9876543210`）
- **IV**：每次加密自动随机生成，随文件头保存，不需要用户提供

---

## 6. 运行环境与依赖

| 项目 | 要求 |
|---|---|
| Python | 3.8 或更高 |
| 依赖 | `customtkinter >= 5.2.0`（仅 GUI 需要） |
| 安装依赖 | `pip install -r requirements.txt` |

**无 GUI 也可以运行**：`sm4_engine.py` 和 `file_crypto.py` 只依赖 Python 标准库，完全可以在服务器/嵌入式环境下独立使用。

---

## 7. 核心设计要点一览

| 设计决策 | 理由 |
|---|---|
| **CBC-CTS 分组模式** | 密文长度 = 明文长度，无需 padding，文件大小零膨胀 |
| **每个文件随机 IV** | 相同内容 + 相同密钥 = 不同密文，防止明文频率分析 |
| **文件头含明文长度** | CTS 解密必须知道原始长度，否则无法正确切割最后两块 |
| **MAGIC 标识 `SM4C`** | 防止解密非加密文件导致错误输出 |
| **算法纯 Python 实现** | 无第三方加密库依赖，可直接验证算法正确性 |
| **单块 Feistel 结构** | 32 轮迭代 + 反序输出，严格遵循 SM4 标准 |

---

## 8. 打包为独立 EXE

```bash
cd python
pip install customtkinter pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name SM4FileCrypto --hidden-import customtkinter crypto_app.py
```

产物：`dist/SM4FileCrypto.exe`

---

## 9.测试
加密页面
<img width="2002" height="1806" alt="image" src="https://github.com/user-attachments/assets/682c1518-3f70-42c6-9f38-895bea61d5b2" />
解密页面
<img width="2002" height="1806" alt="image" src="https://github.com/user-attachments/assets/885f2b96-7201-4fbf-adb7-f612306daf2f" />

txt测试：
<img width="2280" height="920" alt="image" src="https://github.com/user-attachments/assets/d5357f15-bc2e-4b79-b524-aedf121cf4f0" />

word测试：
（左侧原来，中间sm4，右侧已解密）
<img width="3072" height="1920" alt="image" src="https://github.com/user-attachments/assets/3ad53d0c-b897-47f1-b8d8-943388606c7e" />

pdf测试：
<img width="3072" height="1920" alt="image" src="https://github.com/user-attachments/assets/0314f028-607a-49c3-a9fa-193ea9f7df06" />





