#include <iostream>
#include <cstdint>
#include <iomanip>
#include <cassert>  // 用于输入校验

//S盒
const uint8_t S_BOX[256] = {
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
        0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
        0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
        0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
        0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
        0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
        0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
        0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
        0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
        0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
        0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
        0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
        0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
        0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

/**
 * 系统参数FK（用于密钥扩展初始化）
 */
const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };

/**
 * 轮常量CK（32个，用于子密钥生成）
 */
const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aef5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/**
 * 32位循环左移
 * @param x 输入32位数据
 * @param n 左移位数（0~31）
 * @return 循环左移后的结果
 */
#define ROTL32(x, n) ((x) << (n) | ((x) >> (32 - (n))))

 /**
  * S盒替换（修正后）
  */
uint8_t sbox(uint8_t byte) {
    return S_BOX[byte];  // 标准S盒查表
}

/**
 * 线性变换L（基于循环左移的扩散）
 */
uint32_t L(uint32_t x) {
    return x ^ ROTL32(x, 2) ^ ROTL32(x, 10) ^ ROTL32(x, 18) ^ ROTL32(x, 24);
}

/**
 * 非线性变换tau（S盒替换+线性变换L）
 */
uint32_t nonlinearTransform(uint32_t x) {
    // 拆分32位为4个字节
    uint8_t b0 = (x >> 24) & 0xFF;
    uint8_t b1 = (x >> 16) & 0xFF;
    uint8_t b2 = (x >> 8) & 0xFF;
    uint8_t b3 = x & 0xFF;

    // 字节替换
    b0 = sbox(b0);
    b1 = sbox(b1);
    b2 = sbox(b2);
    b3 = sbox(b3);

    // 重组并执行线性变换
    uint32_t y = (static_cast<uint32_t>(b0) << 24) | (static_cast<uint32_t>(b1) << 16)
        | (static_cast<uint32_t>(b2) << 8) | b3;
    return L(y);
}

// -------------------------- 密钥扩展与加解密 --------------------------
/**
 * 生成32个子密钥
 * @param key 128位主密钥（4个32位字）
 * @param rk 输出32个子密钥（K0~K31）
 */
void keyExpansion(const uint32_t key[4], uint32_t rk[32]) {
    assert(key != nullptr && rk != nullptr);  // 校验输入指针有效性
    uint32_t K[4];  // 密钥寄存器
    K[0] = key[0] ^ FK[0];
    K[1] = key[1] ^ FK[1];
    K[2] = key[2] ^ FK[2];
    K[3] = key[3] ^ FK[3];
    // 迭代生成子密钥（SM4密钥扩展公式：K[i+4] = K[i] ^ nonlinearTransform(K[i+1]^K[i+2]^K[i+3]^CK[i])）
    for (int i = 0; i < 32; ++i) {
        rk[i] = K[i % 4] ^ nonlinearTransform(K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i]);
        K[i % 4] = rk[i];  // 更新寄存器
    }
}

/**
 * SM4加密
 * @param plaintext 128位明文（4个32位字）
 * @param key 128位密钥（4个32位字）
 * @param ciphertext 输出128位密文（4个32位字）
 */
void sm4Encrypt(const uint32_t plaintext[4], const uint32_t key[4], uint32_t ciphertext[4]) {
    assert(plaintext != nullptr && key != nullptr && ciphertext != nullptr);

    uint32_t rk[32];
    keyExpansion(key, rk);  // 生成子密钥

    uint32_t X[4] = { plaintext[0], plaintext[1], plaintext[2], plaintext[3] };

    // 32轮迭代：X[i+4] = X[i] ^ nonlinearTransform(X[i+1]^X[i+2]^X[i+3]^rk[i])
    for (int i = 0; i < 32; ++i) {
        uint32_t temp = X[0] ^ nonlinearTransform(X[1] ^ X[2] ^ X[3] ^ rk[i]);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp;
    }

    // 反序变换（加密最终输出：X3, X2, X1, X0）
    ciphertext[0] = X[3];
    ciphertext[1] = X[2];
    ciphertext[2] = X[1];
    ciphertext[3] = X[0];
}

/**
 * SM4解密（子密钥逆序使用）
 * @param ciphertext 128位密文（4个32位字）
 * @param key 128位密钥（4个32位字）
 * @param plaintext 输出128位明文（4个32位字）
 */
void sm4Decrypt(const uint32_t ciphertext[4], const uint32_t key[4], uint32_t plaintext[4]) {
    assert(ciphertext != nullptr && key != nullptr && plaintext != nullptr);

    uint32_t rk[32];
    keyExpansion(key, rk);  // 生成子密钥（与加密相同）

    uint32_t X[4] = { ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3] };

    // 32轮迭代（子密钥逆序：rk[31] ~ rk[0]）
    for (int i = 0; i < 32; ++i) {
        uint32_t temp = X[0] ^ nonlinearTransform(X[1] ^ X[2] ^ X[3] ^ rk[31 - i]);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp;
    }

    // 反序变换（解密最终输出）
    plaintext[0] = X[3];
    plaintext[1] = X[2];
    plaintext[2] = X[1];
    plaintext[3] = X[0];
}

/**
 * 16字节数组转4个32位字
 */
void bytesToWords(const uint8_t bytes[16], uint32_t words[4]) {
    assert(bytes != nullptr && words != nullptr);  // 校验输入

    for (int i = 0; i < 4; ++i) {
        words[i] = (static_cast<uint32_t>(bytes[4 * i]) << 24)
            | (static_cast<uint32_t>(bytes[4 * i + 1]) << 16)
            | (static_cast<uint32_t>(bytes[4 * i + 2]) << 8)
            | bytes[4 * i + 3];
    }
}

/**
 * 4个32位字转16字节数组
 */
void wordsToBytes(const uint32_t words[4], uint8_t bytes[16]) {
    assert(words != nullptr && bytes != nullptr);

    for (int i = 0; i < 4; ++i) {
        bytes[4 * i] = (words[i] >> 24) & 0xFF;
        bytes[4 * i + 1] = (words[i] >> 16) & 0xFF;
        bytes[4 * i + 2] = (words[i] >> 8) & 0xFF;
        bytes[4 * i + 3] = words[i] & 0xFF;
    }
}

// -------------------------- 测试代码 --------------------------
int main() {
    // 明文：01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    uint8_t plaintextBytes[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // 密钥：01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    uint8_t keyBytes[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // 转换为32位字
    uint32_t plaintextWords[4], keyWords[4], ciphertextWords[4], decryptedWords[4];
    bytesToWords(plaintextBytes, plaintextWords);
    bytesToWords(keyBytes, keyWords);

    // 加密
    sm4Encrypt(plaintextWords, keyWords, ciphertextWords);

    // 解密
    sm4Decrypt(ciphertextWords, keyWords, decryptedWords);

    // 转换为字节数组
    uint8_t ciphertextBytes[16], decryptedBytes[16];
    wordsToBytes(ciphertextWords, ciphertextBytes);
    wordsToBytes(decryptedWords, decryptedBytes);

    // 输出结果
    std::cout << "明文:  ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::uppercase
            << static_cast<int>(plaintextBytes[i]) << " ";
    }
    std::cout << std::endl;

    std::cout << "密钥:  ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::uppercase
            << static_cast<int>(keyBytes[i]) << " ";
    }
    std::cout << std::endl;

    std::cout << "密文:  ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::uppercase
            << static_cast<int>(ciphertextBytes[i]) << " ";
    }
    std::cout << std::endl;

    std::cout << "解密后: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << std::uppercase
            << static_cast<int>(decryptedBytes[i]) << " ";
    }
    std::cout << std::endl;

    return 0;
}
