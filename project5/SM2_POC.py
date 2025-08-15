from SM2 import *
import random

def test_trap1_k_disclosure():
    # 缺陷1: 泄露k导致私钥d泄露
    print(" ---测试缺陷1: 泄露k导致d泄露--- ")
    # 生成合法密钥对
    d, pub_key = generate_key_pair()
    message = "测试消息1"
    
    # 正常签名过程，但此处故意泄露随机数k
    k = random.randint(2, n-2)  # 本应保密的随机数
    G = Point(Gx, Gy)
    P1 = point_mul(G, k)
    x1 = P1.x
    za = calculate_za(b"1234567812345678", 128, a, b, Gx, Gy, pub_key[0], pub_key[1])
    e = bytes_to_int(sha256(za + message.encode('utf-8')).digest())
    r = (e + x1) % n
    s = (pow(1 + d, n-2, n) * (k - r * d)) % n
    signature = (r, s)
    
    # 攻击者已知k、r、s、e，求解d
    numerator = (k - s) % n
    denominator = (s + r) % n
    if denominator == 0:
        print("计算错误: 分母为0")
        return
    d_recover = (numerator * pow(denominator, n-2, n)) % n
    
    print(f"原始私钥: 0x{d:x}")
    print(f"恢复私钥: 0x{d_recover:x}")
    print(f"验证结果: {'成功' if d_recover == d else '失败'}\n")

def test_trap2_reuse_k_same_user():
    # 缺陷2: 同一用户重用k签名不同消息
    print("---测试缺陷2: 同一用户重用k签名不同消息---")
    d, pub_key = generate_key_pair()
    k = random.randint(2, n-2)  # 重复使用的k
    msg1 = "测试消息A"
    msg2 = "测试消息B"
    
    # 用相同k对不同消息签名
    def sign_with_k(d, msg, k):
        G = Point(Gx, Gy)
        P1 = point_mul(G, k)
        x1 = P1.x
        za = calculate_za(b"1234567812345678", 128, a, b, Gx, Gy, pub_key[0], pub_key[1])
        e = bytes_to_int(sha256(za + msg.encode('utf-8')).digest())
        r = (e + x1) % n
        s = (pow(1 + d, n-2, n) * (k - r * d)) % n
        return (r, s, e, x1)  # 返回x1用于验证
    
    r1, s1, e1, x1_1 = sign_with_k(d, msg1, k)
    r2, s2, e2, x1_2 = sign_with_k(d, msg2, k)
    
    # 验证k是否真的相同（x1应该相同）
    if x1_1 != x1_2:
        print("错误: 相同k应生成相同x1")
        return
    x1 = x1_1
    numerator = (s2 - s1) % n
    denominator = ((s1 - s2) + (r1 - r2)) % n
    
    if denominator == 0:
        print("计算错误: 分母为0")
        return
    
    d_recover = (numerator * pow(denominator, n-2, n)) % n
    
    print(f"原始私钥: 0x{d:x}")
    print(f"恢复私钥: 0x{d_recover:x}")
    print(f"验证结果: {'成功' if d_recover == d else '失败'}\n")

def test_trap3_reuse_k_different_users():
    # 缺陷3: 不同用户重用k
    print("---测试缺陷3: 不同用户重用k---")
    # 两个不同用户
    d1, pub1 = generate_key_pair()
    d2, pub2 = generate_key_pair()
    k = random.randint(2, n-2)  # 共同使用的k
    msg1 = "用户1的消息"
    msg2 = "用户2的消息"
    
    # 生成签名
    def sign_with_k(d, pub, msg, k):
        G = Point(Gx, Gy)
        P1 = point_mul(G, k)
        x1 = P1.x
        za = calculate_za(b"1234567812345678", 128, a, b, Gx, Gy, pub[0], pub[1])
        e = bytes_to_int(sha256(za + msg.encode('utf-8')).digest())
        r = (e + x1) % n
        s = (pow(1 + d, n-2, n) * (k - r * d)) % n
        return (r, s, e, x1)
    
    r1, s1, e1, x1_1 = sign_with_k(d1, pub1, msg1, k)
    r2, s2, e2, x1_2 = sign_with_k(d2, pub2, msg2, k)
    
    # 验证k是否真的相同（x1应该相同）
    if x1_1 != x1_2:
        print("错误: 相同k应生成相同x1")
        return
    x1 = x1_1
    k_val = (s1 * (1 + d1) + r1 * d1) % n
    
    # 使用k值计算d2
    numerator = (k_val - s2) % n
    denominator = (s2 + r2) % n
    
    if denominator == 0:
        print("计算错误: 分母为0")
        return
    
    d2_recover = (numerator * pow(denominator, n-2, n)) % n
    
    print(f"原始私钥d2: 0x{d2:x}")
    print(f"恢复私钥d2: 0x{d2_recover:x}")
    print(f"验证结果: {'成功' if d2_recover == d2 else '失败'}\n")

def test_trap4_same_dk_ecdsa_sm2():
    # 缺陷4: 同一d和k用于ECDSA和SM2
    print("---测试缺陷4: 同一d和k用于ECDSA和SM2---")
    d, pub_sm2 = generate_key_pair()
    k = random.randint(2, n-2)
    msg = "共享消息"
    
    # SM2签名
    G = Point(Gx, Gy)
    P1 = point_mul(G, k)
    x1 = P1.x
    za = calculate_za(b"1234567812345678", 128, a, b, Gx, Gy, pub_sm2[0], pub_sm2[1])
    e_sm2 = bytes_to_int(sha256(za + msg.encode('utf-8')).digest())
    r_sm2 = (e_sm2 + x1) % n
    s_sm2 = (pow(1 + d, n-2, n) * (k - r_sm2 * d)) % n
    
    # ECDSA签名
    e_ecdsa = bytes_to_int(sha256(msg.encode('utf-8')).digest())
    r_ecdsa = x1 % n  # ECDSA中r是kG的x坐标
    s_ecdsa = (pow(k, n-2, n) * (e_ecdsa + r_ecdsa * d)) % n
    
    # 从ECDSA签名恢复k
    k_recover = (e_ecdsa + r_ecdsa * d) * pow(s_ecdsa, n-2, n) % n
    
    if k_recover != k:
        print("警告: 从ECDSA恢复的k不正确")
    
    # 代入SM2公式求解d
    # 从s_sm2的公式推导
    numerator = (k - s_sm2) % n
    denominator = (s_sm2 + r_sm2) % n
    
    if denominator == 0:
        print("计算错误: 分母为0")
        return
    
    d_recover = (numerator * pow(denominator, n-2, n)) % n
    
    print(f"原始私钥: 0x{d:x}")
    print(f"恢复私钥: 0x{d_recover:x}")
    print(f"验证结果: {'成功' if d_recover == d else '失败'}\n")

if __name__ == "__main__":
    test_trap1_k_disclosure()
    test_trap2_reuse_k_same_user()
    test_trap3_reuse_k_different_users()
    test_trap4_same_dk_ecdsa_sm2()
    
