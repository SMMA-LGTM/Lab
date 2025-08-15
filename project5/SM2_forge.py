from SM2 import *
import random

# 实际中若无私钥，此方法无法生成有效签名
def forge_signature(public_key, message, user_id=b"1234567812345678"):
    x, y = public_key
    P = Point(x, y)
    G = Point(Gx, Gy)
    
    # 计算ZA
    entl = len(user_id) * 8
    za = calculate_za(user_id, entl, a, b, Gx, Gy, x, y)
    # 计算e值
    e = sha256(za + message.encode('utf-8')).digest()
    e = bytes_to_int(e)
    
    # 随机选择r和s'（伪造的核心：暴力尝试或特殊构造）
    while True:
        r = random.randint(1, n-1)
        s_prime = random.randint(1, n-1)
        
        # 计算t = (r + s_prime) mod n
        t = (r + s_prime) % n
        if t == 0:
            continue
            
        # 计算P1 = s'*G + t*P
        P1 = point_add(point_mul(G, s_prime), point_mul(P, t))
        if P1.is_infinity:
            continue
            
        # 计算R = (e + x1) mod n
        R = (e + P1.x) % n
        
        # 如果R等于r，则找到一个"有效"签名
        if R == r:
            return (r, s_prime)

# 演示
if __name__ == "__main__":
    # 生成合法密钥对
    private_key, public_key = generate_key_pair()
    print(f"公钥: (0x{public_key[0]:x}, 0x{public_key[1]:x})")
    
    message = "中本聪"
    print(f"消息: {message}")
    
    # 生成合法签名
    valid_signature = sign(private_key, message)
    print(f"合法签名: (0x{valid_signature[0]:x}, 0x{valid_signature[1]:x})")
    print(f"合法签名验证: {'成功' if verify(public_key, message, valid_signature) else '失败'}")
    
    # 尝试伪造签名
    print("\n尝试伪造签名...（可能需要较长时间）")
    forged_signature = forge_signature(public_key, message)
    print(f"伪造的签名: (0x{forged_signature[0]:x}, 0x{forged_signature[1]:x})")
    print(f"伪造签名验证: {'成功' if verify(public_key, message, forged_signature) else '失败'}")
    
