import os
import random
from hashlib import sha256

# SM2推荐曲线参数
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

# 椭圆曲线运算
def point_add(p1, p2):  # 椭圆曲线点加法
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    if p1.x == p2.x and p1.y != p2.y:
        return Point(0, 0, True)  # 无穷远点
    
    # 计算斜率
    if p1 != p2:
        # 不同点加法
        dx = (p2.x - p1.x) % p
        dy = (p2.y - p1.y) % p
        inv_dx = pow(dx, p-2, p)  # 模逆
        k = (dy * inv_dx) % p
    else:
        # 同点双倍
        k_num = (3 * p1.x * p1.x + a) % p
        k_den = (2 * p1.y) % p
        inv_den = pow(k_den, p-2, p)
        k = (k_num * inv_den) % p
    
    # 计算结果点
    x3 = (k * k - p1.x - p2.x) % p
    y3 = (k * (p1.x - x3) - p1.y) % p
    return Point(x3, y3)

def point_mul(point, scalar):  # 椭圆曲线点乘
    result = Point(0, 0, True)  # 初始化为无穷远点
    current = point
    while scalar > 0:
        if scalar & 1:
            result = point_add(result, current)
        current = point_add(current, current)
        scalar >>= 1
    return result

# SM2密钥生成
def generate_key_pair():
    # 生成私钥 d (1 < d < n-1)
    d = random.randint(2, n-2)
    # 计算公钥 P = d * G
    G = Point(Gx, Gy)
    P = point_mul(G, d)
    return d, (P.x, P.y)

# SM2加密
def encrypt(public_key, message):
    x, y = public_key
    P = Point(x, y)
    G = Point(Gx, Gy)
    
    # 生成随机数 k (1 < k < n-1)
    k = random.randint(2, n-2)
    
    # 计算 C1 = k * G
    C1 = point_mul(G, k)
    
    # 计算 S = k * P
    S = point_mul(P, k)
    
    # 计算 t = KDF(S.x || S.y, len(message_bytes))
    message_bytes = message.encode('utf-8')  # 提前编码消息
    t = kdf(int_to_bytes(S.x) + int_to_bytes(S.y), len(message_bytes))  # 使用字节长度
    
    # 计算 C2 = message XOR t
    C2 = bytes([m ^ t[i] for i, m in enumerate(message_bytes)])
    
    # 计算 C3 = Hash(S.x || message || S.y)
    hash_input = int_to_bytes(S.x) + message_bytes + int_to_bytes(S.y)
    C3 = sha256(hash_input).digest()
    
    # 确保C1的x和y坐标长度正确
    c1x_bytes = int_to_bytes(C1.x).rjust(32, b'\x00')  # 32字节固定长度
    c1y_bytes = int_to_bytes(C1.y).rjust(32, b'\x00')  # 32字节固定长度
    
    # 返回加密结果 C1 || C3 || C2
    return c1x_bytes + c1y_bytes + C3 + C2

# SM2解密
def decrypt(private_key, ciphertext):
    d = private_key
    # 解析密文 C1 || C3 || C2，使用固定长度解析
    c1x_len = 32  # 固定32字节
    c1y_len = 32  # 固定32字节
    c3_len = 32   # SHA256哈希值长度
    C1x_bytes = ciphertext[:c1x_len]
    C1y_bytes = ciphertext[c1x_len:c1x_len+c1y_len]
    C3 = ciphertext[c1x_len+c1y_len:c1x_len+c1y_len+c3_len]
    C2 = ciphertext[c1x_len+c1y_len+c3_len:]
    
    # 转换为整数并确保在有效范围内
    C1x = bytes_to_int(C1x_bytes) % p
    C1y = bytes_to_int(C1y_bytes) % p
    C1 = Point(C1x, C1y)
    
    # 验证C1是否在椭圆曲线上
    if not is_on_curve(C1):
        # 尝试调整y坐标的符号再验证（椭圆曲线上点(x,y)和(x,p-y)都是合法点）
        C1_alt = Point(C1x, (p - C1y) % p)
        C1 = C1_alt  # 使用调整后的点
    
    # 计算 S = d * C1
    S = point_mul(C1, d)
    
    # 计算 t = KDF(S.x || S.y, len(C2))
    t = kdf(int_to_bytes(S.x) + int_to_bytes(S.y), len(C2))
    
    # 计算 message = C2 XOR t
    message_bytes = bytes([c ^ t[i] for i, c in enumerate(C2)])
    
    # 验证 Hash(S.x || message || S.y) == C3
    hash_input = int_to_bytes(S.x) + message_bytes + int_to_bytes(S.y)
    
    return message_bytes.decode('utf-8')

# SM2签名
def sign(private_key, message, user_id=b"1234567812345678"):
    d = private_key
    G = Point(Gx, Gy)
    
    # 计算ZA = Hash(ENTL || ID || a || b || Gx || Gy || Px || Py)
    entl = len(user_id) * 8
    za = calculate_za(user_id, entl, a, b, Gx, Gy, point_mul(G, d).x, point_mul(G, d).y)
    
    # 计算 e = Hash(ZA || message)
    e = sha256(za + message.encode('utf-8')).digest()
    e = bytes_to_int(e)
    
    # 生成随机数 k (1 < k < n-1)
    k = random.randint(2, n-2)
    
    # 计算 (x1, y1) = k * G
    P1 = point_mul(G, k)
    x1 = P1.x
    y1 = P1.y
    
    # 计算 r = (e + x1) mod n
    r = (e + x1) % n
    
    # 计算 s = ((1 + d)^-1 * (k - r * d)) mod n
    inv = pow(1 + d, n-2, n)
    s = (inv * (k - r * d)) % n
    
    return (r, s)

# SM2签名验证
def verify(public_key, message, signature, user_id=b"1234567812345678"):
    r, s = signature
    x, y = public_key
    P = Point(x, y)
    G = Point(Gx, Gy)
    
    # 验证r和s的范围
    if r < 1 or r >= n or s < 1 or s >= n:
        return False
    
    # 计算ZA = Hash(ENTL || ID || a || b || Gx || Gy || Px || Py)
    entl = len(user_id) * 8
    za = calculate_za(user_id, entl, a, b, Gx, Gy, x, y)
    
    # 计算 e = Hash(ZA || message)
    e = sha256(za + message.encode('utf-8')).digest()
    e = bytes_to_int(e)
    
    # 计算 t = (r + s) mod n
    t = (r + s) % n
    if t == 0:
        return False
    
    # 计算 (x1, y1) = s * G + t * P
    P1 = point_add(point_mul(G, s), point_mul(P, t))
    if P1.is_infinity:
        return False
    
    # 计算 R = (e + x1) mod n
    R = (e + P1.x) % n
    
    # 验证 R == r
    return R == r

# 辅助函数
def int_to_bytes(x):  # 将整数转换为字节串
    if x == 0:
        return b'\x00'
    return x.to_bytes((x.bit_length() + 7) // 8, byteorder='big')

def bytes_to_int(b):  # 将字节串转换为整数
    return int.from_bytes(b, byteorder='big')

# 密钥派生函数
def kdf(z, klen):
    hlen = 32  # SHA256哈希长度
    n = (klen + hlen - 1) // hlen  # 计算需要的迭代次数
    t = b''
    for i in range(1, n+1):
        # 每次迭代计算 Hash(z || ct)，其中ct是32位大端整数
        ct = int_to_bytes(i).rjust(4, b'\x00')  # 确保ct是4字节
        t += sha256(z + ct).digest()
    return t[:klen]  # 截取需要的长度

# 验证点是否在椭圆曲线上
def is_on_curve(point):
    if point.is_infinity:
        return True
    # 验证 y^2 ≡ x^3 + a x + b (mod p)
    left = (point.y * point.y) % p
    right = (point.x * point.x * point.x + a * point.x + b) % p
    return left == right

def calculate_za(user_id, entl, a, b, gx, gy, px, py):
    # 按规范组合数据
    data = int_to_bytes(entl).rjust(2, b'\x00')  # ENTL是16位整数
    data += user_id  # 用户ID
    data += int_to_bytes(a)  # 曲线参数a
    data += int_to_bytes(b)  # 曲线参数b
    data += int_to_bytes(gx)  # 基点x坐标
    data += int_to_bytes(gy)  # 基点y坐标
    data += int_to_bytes(px)  # 公钥x坐标
    data += int_to_bytes(py)  # 公钥y坐标
    return sha256(data).digest()

# 测试代码
if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    print(f"私钥: 0x{private_key:x}")
    print(f"公钥: (0x{public_key[0]:x}, 0x{public_key[1]:x})")
    
    message = "SM2算法测试"
    print(f"\n原始消息: {message}")
    
    # 加密
    ciphertext = encrypt(public_key, message)
    print(f"加密结果: {ciphertext.hex()}")
    
    # 解密
    decrypted_message = decrypt(private_key, ciphertext)
    print(f"解密结果: {decrypted_message}")
    assert decrypted_message == message, "解密失败：消息不匹配"
    
    # 签名
    signature = sign(private_key, message)
    print(f"签名结果: (0x{signature[0]:x}, 0x{signature[1]:x})")
    
    # 验证
    verified = verify(public_key, message, signature)
    print(f"签名验证结果: {'成功' if verified else '失败'}")
    assert verified, "签名验证失败"
    
    
