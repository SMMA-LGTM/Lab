import os
import random
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor

# SM2曲线参数
p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 椭圆曲线点类
class Point:
    def __init__(self, x, y, is_infinity=False):
        self.x = x
        self.y = y
        self.is_infinity = is_infinity  # 无穷远点标志
    
    def __eq__(self, other):
        if self.is_infinity and other.is_infinity:
            return True
        if self.is_infinity or other.is_infinity:
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self):
        if self.is_infinity:
            return "Point(infinity)"
        return f"Point(0x{self.x:x}, 0x{self.y:x})"


# -------------------------- 基础运算优化 --------------------------
def extended_gcd(a, b):
    # 扩展欧几里得算法：用于高效计算模逆
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a, mod):
    g, x, y = extended_gcd(a, mod)
    if g != 1:
        raise ValueError("模逆不存在")
    return x % mod

def point_add(p1, p2):
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    if p1.x == p2.x and p1.y != p2.y:
        return Point(0, 0, True)  # 无穷远点
    # 计算斜率
    if p1 != p2:
        dx = (p2.x - p1.x) % p
        dy = (p2.y - p1.y) % p
        inv_dx = mod_inverse(dx, p)
        k = (dy * inv_dx) % p
    else:
        k_num = (3 * p1.x * p1.x + a) % p
        k_den = (2 * p1.y) % p
        inv_den = mod_inverse(k_den, p)
        k = (k_num * inv_den) % p
    # 计算结果点
    x3 = (k * k - p1.x - p2.x) % p
    y3 = (k * (p1.x - x3) - p1.y) % p
    return Point(x3, y3)

def point_mul_optimized(point, scalar):
    # 标量乘法
    # 确保标量在有效范围内
    scalar = scalar % n
    if scalar == 0:
        return Point(0, 0, True)
    
    result = Point(0, 0, True)  # 初始为无穷远点
    current = point
    
    # 二进制双加算法
    while scalar > 0:
        if scalar % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)  # 点加倍
        scalar = scalar // 2
    
    return result


# -------------------------- 密钥优化（公钥压缩） --------------------------
def compress_public_key(point):
    # 压缩公钥为33字节（x坐标+奇偶标志）
    prefix = b'\x02' if (point.y % 2 == 0) else b'\x03'
    x_bytes = int_to_bytes(point.x).rjust(32, b'\x00')
    return prefix + x_bytes

def decompress_public_key(compressed_bytes):
    # 从压缩公钥恢复完整点坐标
    prefix = compressed_bytes[0]
    x = bytes_to_int(compressed_bytes[1:]) % p
    
    # 计算y² = x³ + a x + b (mod p)
    y_squared = (pow(x, 3, p) + a * x + b) % p
    y = pow(y_squared, (p + 1) // 4, p)  # SM2的p ≡ 3 mod 4，快速开方
    
    # 根据前缀调整y的奇偶性
    if (prefix == 0x02 and y % 2 != 0) or (prefix == 0x03 and y % 2 == 0):
        y = (p - y) % p
    return Point(x, y)


# -------------------------- 签名验证优化 --------------------------
def verify_single(public_key, message, signature, user_id):
    # 单个签名验证
    r, s = signature
    x, y = public_key
    P = Point(x, y)
    G = Point(Gx, Gy)
    
    # 基础验证
    if r < 1 or r >= n or s < 1 or s >= n:
        return False
    
    # 计算ZA和e
    entl = len(user_id) * 8
    za = calculate_za(user_id, entl, a, b, Gx, Gy, x, y)
    e_bytes = sha256(za + message.encode('utf-8')).digest()
    e = bytes_to_int(e_bytes)
    
    t = (r + s) % n
    if t == 0:
        return False
    
    # 计算验证点
    sG = point_mul_optimized(G, s)
    tP = point_mul_optimized(P, t)
    P1 = point_add(sG, tP)
    
    if P1.is_infinity:
        return False
    
    # 验证结果
    return (e + P1.x) % n == r

def batch_verify(public_keys, messages, signatures, user_id=b"1234567812345678"):
    # 并行批量验证多个签名
    if len(public_keys) != len(messages) or len(messages) != len(signatures):
        raise ValueError("输入长度不匹配")
    
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(verify_single, pk, msg, sig, user_id)
            for pk, msg, sig in zip(public_keys, messages, signatures)
        ]
        return all(future.result() for future in futures)


def int_to_bytes(x):
    # 整数转字节串
    if x == 0:
        return b'\x00'
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bytes_to_int(b):
    # 字节串转整数
    return int.from_bytes(b, byteorder='big')

def kdf(z, klen):
    # 密钥派生函数
    hlen = 32
    n = (klen + hlen - 1) // hlen
    t = b''
    for i in range(1, n+1):
        ct = int_to_bytes(i).rjust(4, b'\x00')
        t += sha256(z + ct).digest()
    return t[:klen]

def is_on_curve(point):
    # 验证点是否在曲线上
    if point.is_infinity:
        return True
    left = (point.y * point.y) % p
    right = (pow(point.x, 3, p) + a * point.x + b) % p
    return left == right

def calculate_za(user_id, entl, a, b, gx, gy, px, py):
    # 计算ZA值
    data = b''
    data += int_to_bytes(entl).rjust(2, b'\x00')  # entl占2字节
    data += user_id  # 用户ID
    data += int_to_bytes(a).rjust(32, b'\x00')   # a参数
    data += int_to_bytes(b).rjust(32, b'\x00')   # b参数
    data += int_to_bytes(gx).rjust(32, b'\x00')  # Gx
    data += int_to_bytes(gy).rjust(32, b'\x00')  # Gy
    data += int_to_bytes(px).rjust(32, b'\x00')  # 公钥x
    data += int_to_bytes(py).rjust(32, b'\x00')  # 公钥y
    return sha256(data).digest()


# -------------------------- 密钥生成/加解密/签名 --------------------------

# 密钥生成
def generate_key_pair():
    d = random.randint(1, n-2)
    G = Point(Gx, Gy)
    P = point_mul_optimized(G, d)
    return d, (P.x, P.y)

# 加密
def encrypt(public_key, message):
    x, y = public_key
    P = Point(x, y)
    G = Point(Gx, Gy)
    
    k = random.randint(1, n-2)
    C1 = point_mul_optimized(G, k)
    S = point_mul_optimized(P, k)
    
    message_bytes = message.encode('utf-8')
    t = kdf(int_to_bytes(S.x) + int_to_bytes(S.y), len(message_bytes))
    C2 = bytes([m ^ t[i] for i, m in enumerate(message_bytes)])
    hash_input = int_to_bytes(S.x) + message_bytes + int_to_bytes(S.y)
    C3 = sha256(hash_input).digest()
    
    c1_compressed = compress_public_key(C1)
    return c1_compressed + C3 + C2

# 解密
def decrypt(private_key, ciphertext):
    d = private_key
    c1_len = 33
    c3_len = 32
    C1_compressed = ciphertext[:c1_len]
    C3 = ciphertext[c1_len:c1_len+c3_len]
    C2 = ciphertext[c1_len+c3_len:]
    
    C1 = decompress_public_key(C1_compressed)
    if not is_on_curve(C1):
        raise ValueError("C1不在椭圆曲线上")
    
    S = point_mul_optimized(C1, d)
    t = kdf(int_to_bytes(S.x) + int_to_bytes(S.y), len(C2))
    message_bytes = bytes([c ^ t[i] for i, c in enumerate(C2)])
    
    hash_input = int_to_bytes(S.x) + message_bytes + int_to_bytes(S.y)
    if sha256(hash_input).digest() != C3:
        raise ValueError("解密验证失败")
    return message_bytes.decode('utf-8')

def sign(private_key, message, user_id=b"1234567812345678"):
    d = private_key
    G = Point(Gx, Gy)
    P = point_mul_optimized(G, d)  # 计算公钥点
    
    # 计算ZA
    entl = len(user_id) * 8
    za = calculate_za(user_id, entl, a, b, Gx, Gy, P.x, P.y)
    
    # 计算e
    e_hash = sha256(za + message.encode('utf-8'))
    e = bytes_to_int(e_hash.digest())
    
    # 生成签名
    while True:
        k = random.randint(1, n-1)
        kG = point_mul_optimized(G, k)
        r = (e + kG.x) % n
        
        # 检查r是否有效
        if r == 0 or r + k == n:
            continue
        
        # 计算s
        inv_1_plus_d = mod_inverse((1 + d) % n, n)
        s = (inv_1_plus_d * (k - r * d)) % n
        
        # 确保s为正数且有效
        if s < 0:
            s += n
        if s != 0:
            break
    
    return (r, s)

# 单签名验证
def verify(public_key, message, signature, user_id=b"1234567812345678"):
    return verify_single(public_key, message, signature, user_id)



# 测试代码
if __name__ == "__main__":
    # 生成密钥对
    private_key, public_key = generate_key_pair()
    print(f"私钥: 0x{private_key:x}")
    print(f"公钥: (0x{public_key[0]:x}, 0x{public_key[1]:x})")
    
    # 测试公钥压缩
    P = Point(public_key[0], public_key[1])
    compressed_pk = compress_public_key(P)
    print(f"压缩公钥: {compressed_pk.hex()}")
    decompressed_pk = decompress_public_key(compressed_pk)
    assert decompressed_pk == P, "公钥压缩/解压缩失败"
    
    # 测试加解密
    message = "SM2优化算法测试"
    print(f"\n原始消息: {message}")
    
    ciphertext = encrypt(public_key, message)
    print(f"加密结果 (长度{len(ciphertext)}字节): {ciphertext.hex()}")
    
    decrypted_message = decrypt(private_key, ciphertext)
    print(f"解密结果: {decrypted_message}")
    assert decrypted_message == message, "解密失败"
    
    # 测试签名与验证
    signature = sign(private_key, message)
    print(f"\n签名结果: (0x{signature[0]:x}, 0x{signature[1]:x})")
    
    # 验证前先检查签名参数范围
    r, s = signature
    print(f"签名参数检查: r={r >= 1 and r < n}, s={s >= 1 and s < n}")

    verified = verify(public_key, message, signature)
    print(f"单签名验证: {'成功' if verified else '失败'}")
    assert verified, "单签名验证失败"
    
    # 测试批量验证
    messages = [f"批量消息{i}" for i in range(5)]
    signatures = [sign(private_key, msg) for msg in messages]
    public_keys = [public_key] * 5
    
    batch_result = batch_verify(public_keys, messages, signatures)
    print(f"批量验证(5条): {'成功' if batch_result else '失败'}")
    assert batch_result, "批量验证失败"
    
