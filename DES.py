import base64
from hashlib import pbkdf2_hmac

from table import *


# PKCS7 填充
def pkcs7_padding(data, block_size=64):
    pad_len = block_size - (len(data) % block_size)
    return data + chr(pad_len) * pad_len


# PKCS7 去除填充
def pkcs7_unpadding(data):
    pad_len = ord(data[-1])
    return data[:-pad_len]


# 将字符串转换为二进制（使用 Base64 编码避免中文字符截断）
def str2bin(s):
    base64_bytes = base64.b64encode(s.encode('utf-8'))  # 将字符串转换为 Base64 编码后的字节
    return ''.join(format(byte, '08b') for byte in base64_bytes)  # 将每个字节转换为二进制字符串


# 将二进制转换为字符串（使用 Base64 解码）
def bin2str(b):
    bytes_list = [b[i:i + 8] for i in range(0, len(b), 8)]  # 将二进制字符串按每 8 位分组，得到字节列表
    bytes_obj = bytes([int(byte, 2) for byte in bytes_list])  # 字节列表会得到所有的字节
    try:
        # 进行 Base64 解码并转换回字符串
        return base64.b64decode(bytes_obj).decode('utf-8')
    except (UnicodeDecodeError, base64.binascii.Error) as e:
        print(f"解码失败: {e}")  # 可选的打印错误信息以便调试
        return


def bin2hex(bin_str):
    return "".join(
        hex(int(bin_str[i : i + 4], 2))[2:] for i in range(0, len(bin_str), 4)
    )


def hex2bin(hex_str):
    return "".join(format(int(char, 16), "04b") for char in hex_str)

def byte2bin(byte_str):
    return "".join(format(byte, '08b') for byte in byte_str)


"""
这是关于得到所有密钥的方法
"""


# 得到56位的密钥
def process_key(k):
    k_hex = pbkdf2_hmac(
        'sha256',
        k.encode('utf-8'),
        b'salt',
        10000,
        dklen=8
    )
    k_str = byte2bin(k_hex)
    key_bin56 = ""
    for i in PC1_TABLE:
        key_bin56 += k_str[i - 1]
    # 得到56bit的密钥
    return key_bin56


# 循环左移的操作
def left_turn(my_str, num):
    return my_str[num:] + my_str[:num]


# 得到所有的子密钥
def generate_keys(k):
    keys = []
    key_bin56 = process_key(k)
    c = key_bin56[0:28]
    d = key_bin56[28:]
    for i in MOVE_TABLE:
        c = left_turn(c, i)
        d = left_turn(d, i)
        total_k = c + d
        sub_key = ""
        for j in PC2_TABLE:
            sub_key += total_k[j - 1]
        keys.append(sub_key)
    return keys


"""
这是关于生成密文的过程
"""


def divide(bin_str):
    # 判断是否可以成功切割，否则补0
    length = len(bin_str)
    if length % 64 != 0:
        bin_str += "0" * (64 - (length % 64))
    # 切割成多个64bit.i的总数是str的总长度，每次取64位
    result = [bin_str[i: i + 64] for i in range(0, len(bin_str), 64)]
    return result


# 置换操作 IP_TABLE IP2_TABLE E_TABLE P_TABLE
def trans(str_bit, table):
    result = ""
    for i in table:
        result += str_bit[i - 1]
    return result


# 异或操作
def xor(str1, str2):
    result = ""
    # 对于每一位按顺序进行异或判断
    for c1, c2 in zip(str1, str2):
        result += str(int(c1) ^ int(c2))
    return result


# 单个S盒
def single_s(str_bit, i):
    row = int(str_bit[0] + str_bit[5], 2)
    col = int(str_bit[1:5], 2)
    num = S_BOX[i][row][col]
    return bin(num)[2:].zfill(4)


# 整体的S操作
def s_box(str_bit):
    result = ""
    for i in range(8):
        result += single_s(str_bit[i * 6: i * 6 + 6], i)
    return result


# 整体的F操作
def F(str_bit, k):
    # 拓展E
    str_bit = trans(str_bit, E_TABLE)
    # 使用子密钥进行异或
    str_bit = xor(str_bit, k)
    # S盒操作
    str_bit = s_box(str_bit)
    # 使用P盒进行置换
    str_bit = trans(str_bit, P_TABLE)
    return str_bit


# 加密过程
def encrypt(origin_str, k):
    # 计算原始密钥的哈希值
    # 防止长度问题导致密钥后半部分无法使用
    # key_hash = hashlib.sha256(k.encode()).hexdigest()
    keys = generate_keys(k)
    # origin_str = pkcs7_padding(origin_str)
    bin_str = str2bin(origin_str)
    str_list = divide(bin_str)
    result = ""
    for i in str_list:
        # 初始置换
        i = trans(i, IP_TABLE)
        # 得到L0和R0
        L, R = i[0:32], i[32:]
        # 16轮迭代
        for j in range(16):
            L, R = R, xor(L, F(R, keys[j]))
        # 逆初始置换
        i = trans(R + L, IP2_TABLE)
        result += i
    # 这里可以把哈希密钥以任何形式插入密文中，只要解密的时候可以提取出来就行
    return result


# 解密过程
def decrypt(origin_str, k):
    # 提取密文和密钥哈希
    # ciphertext = origin_str[:-256]
    # key_hash = origin_str[-256:]
    # # 验证密钥
    # if hashlib.sha256(k.encode()).hexdigest() != bin2hex(key_hash):
    #     return
    keys = generate_keys(k)
    str_list = divide(origin_str)
    result = ""
    for i in str_list:
        # 初始置换
        i = trans(i, IP_TABLE)
        # 得到L0和R0
        L, R = i[0:32], i[32:]
        # 16轮迭代
        for j in range(16):
            L, R = R, xor(L, F(R, keys[15 - j]))
        # 逆初始置换
        i = trans(R + L, IP2_TABLE)
        result += i
    # 去除填充
    result = result.rstrip('0')
    return bin2str(result)


# VALIDATION_STRING = "VALID_KEY"
# def encrypt(origin_str, k):
#     # 在明文前添加验证字符串
#     origin_str = VALIDATION_STRING + origin_str
#     keys = generate_keys(k)
#     bin_str = str2bin(origin_str)
#     str_list = divide(bin_str)
#     result = ""
#     for i in str_list:
#         i = trans(i, IP_TABLE)
#         L, R = i[0:32], i[32:]
#         for j in range(16):
#             L, R = R, xor(L, F(R, keys[j]))
#         i = trans(R + L, IP2_TABLE)
#         result += i
#     return result


# def decrypt(origin_str, k):
#     keys = generate_keys(k)
#     str_list = divide(origin_str)
#     result = ""
#     for i in str_list:
#         i = trans(i, IP_TABLE)
#         L, R = i[0:32], i[32:]
#         for j in range(16):
#             L, R = R, xor(L, F(R, keys[15 - j]))
#         i = trans(R + L, IP2_TABLE)
#         result += i
#     result = result.rstrip("0")
#     plaintext = bin2str(result)
#     # 检查解密后的文本是否以验证字符串开头
#     if plaintext.startswith(VALIDATION_STRING):
#         return plaintext[len(VALIDATION_STRING):]
#     else:
#         return
