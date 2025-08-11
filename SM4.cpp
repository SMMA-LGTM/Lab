#include <iostream>
#include <cstdint>  // 用于固定宽度整数类型（uint32_t）
#include <iomanip>  // 用于格式化输出

using namespace std;


//SM4算法的S盒（非线性替换表）
const uint8_t S_BOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x8f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x3f, 0xa6,
    0x0e, 0x45, 0x9b, 0x33, 0x4d, 0x4e, 0x09, 0xcb, 0x2d, 0x5b, 0x51, 0x84, 0x8b, 0x58, 0x29, 0x00,
    0x86, 0x60, 0x87, 0x6e, 0x01, 0x66, 0x3b, 0x55, 0x21, 0x0c, 0x7c, 0xad, 0xf0, 0x3e, 0xf7, 0xc1,
    0x7b, 0xca, 0x83, 0x59, 0x96, 0x80, 0x81, 0x6f, 0xd3, 0x02, 0xa1, 0x1d, 0x2e, 0xcb, 0x73, 0x97,
    0x0f, 0x5d, 0x93, 0x27, 0x5c, 0xa0, 0x15, 0x46, 0x57, 0xa7, 0x82, 0x9d, 0x38, 0xf5, 0xca, 0x31,
    0x03, 0x41, 0x07, 0x02, 0x18, 0xc5, 0x8c, 0xe3, 0x8e, 0x8e, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc,
    0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0x2c, 0x5b, 0x51, 0x84, 0x8b, 0x58, 0x29,
    0x00, 0x86, 0x60, 0x87, 0x6e, 0x01, 0x66, 0x3b, 0x55, 0x21, 0x0c, 0x7c, 0xad, 0xf0, 0x3e, 0xf7,
    0xc1, 0x7b, 0xca, 0x83, 0x59, 0x96, 0x80, 0x81, 0x6f, 0xd3, 0x02, 0xa1, 0x1d, 0x2e, 0xcb, 0x73,
    0x97, 0x0f, 0x5d, 0x93, 0x27, 0x5c, 0xa0, 0x15, 0x46, 0x57, 0xa7, 0x82, 0x9d, 0x38, 0xf5, 0xca,
    0x31, 0x03, 0x41, 0x07, 0x02, 0x18, 0xc5, 0x8c, 0xe3, 0x8e, 0x8e, 0x53, 0xd1, 0x00, 0xed, 0x20,
    0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0x2c, 0x1e, 0x72, 0xca, 0xa5, 0x64,
    0x12, 0x08, 0x7a, 0xc4, 0xa2, 0x24, 0x10, 0x19, 0x79, 0x48, 0x32, 0x6d, 0x2b, 0x11, 0x98, 0x12
};

/**
 * 系统参数FK（用于密钥扩展）
 * 固定值，由算法标准定义
 */
const uint32_t FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

/**
 * 固定参数CK（用于密钥扩展，共32个，对应32轮迭代）
 * 每一轮的轮常量，用于增强子密钥的差异性
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
 * S盒替换
 * @param byte 输入8位字节
 * @return 替换后的8位字节
 */
uint8_t sbox(uint8_t byte) {
    return S_BOX[byte];  // 直接查表实现替换
}

/**
 * 线性变换L（用于轮函数和密钥扩展）
 * 作用：对32位输入进行线性扩散，增强算法的雪崩效应
 * 计算方式：L(x) = x ^ (x << 2) ^ (x << 10) ^ (x << 18) ^ (x << 24)
 */
uint32_t L(uint32_t x) {
    // 左移操作后与原数据异或，实现线性扩散
    return x ^ ((x << 2) | (x >> 30))  // (x << 2) 若溢出，用右移30位补回
           ^ ((x << 10) | (x >> 22))   // 循环左移10位
           ^ ((x << 18) | (x >> 14))   // 循环左移18位
           ^ ((x << 24) | (x >> 8));   // 循环左移24位
}

/**
 * 轮函数中的非线性变换τ（由S盒和L变换组成）
 * 作用：对32位输入进行非线性混淆和线性扩散的组合变换
 * 将32位输入拆分为4个字节，每个字节经S盒替换，重组为32位，经L变换输出
 */
uint32_t tau(uint32_t x) {
    // 拆分32位为4个字节
    uint8_t b0 = (x >> 24) & 0xFF;
    uint8_t b1 = (x >> 16) & 0xFF;
    uint8_t b2 = (x >> 8) & 0xFF;
    uint8_t b3 = x & 0xFF;

    // 每个字节进行S盒替换
    b0 = sbox(b0);
    b1 = sbox(b1);
    b2 = sbox(b2);
    b3 = sbox(b3);

    // 重组为32位并进行L变换
    uint32_t y = (static_cast<uint32_t>(b0) << 24) | (static_cast<uint32_t>(b1) << 16) 
               | (static_cast<uint32_t>(b2) << 8) | b3;
    return L(y);
}

/**
 * 密钥扩展函数（生成32个子密钥）
 * 作用：根据128位主密钥生成32轮迭代所需的子密钥
 * 基于主密钥和系统参数FK、轮常量CK，通过迭代计算生成子密钥
 * @param key 128位主密钥（4个32位字）
 * @param rk 输出32个子密钥（K0~K31）
 */
void keyExpansion(const uint32_t key[4], uint32_t rk[32]) {
    // 初始化密钥寄存器：将主密钥与系统参数FK异或
    uint32_t K[4];
    K[0] = key[0] ^ FK[0];
    K[1] = key[1] ^ FK[1];
    K[2] = key[2] ^ FK[2];
    K[3] = key[3] ^ FK[3];

    // 迭代生成32个子密钥
    for (int i = 0; i < 32; ++i) {
        // 子密钥计算：Ki+4 = Ki ^ tau(Ki+1 ^ Ki+2 ^ Ki+3 ^ CK[i])
        rk[i] = K[i % 4] ^ tau(K[(i+1) % 4] ^ K[(i+2) % 4] ^ K[(i+3) % 4] ^ CK[i]);
        // 更新密钥寄存器
        K[i % 4] = rk[i];
    }
}

/**
 * SM4加密函数
 * 输入：128位明文、128位密钥
 * 输出：128位密文
 * 流程：32轮迭代 -> 反序变换 -> 输出密文
 */
void sm4Encrypt(const uint32_t plaintext[4], const uint32_t key[4], uint32_t ciphertext[4]) {
    // 生成32个子密钥
    uint32_t rk[32];
    keyExpansion(key, rk);

    // 初始化明文寄存器
    uint32_t X[4];
    X[0] = plaintext[0];
    X[1] = plaintext[1];
    X[2] = plaintext[2];
    X[3] = plaintext[3];

    // 32轮迭代：每轮更新寄存器（X0 = X1, X1 = X2, X2 = X3, X3 = X0 ^ tau(X1 ^ X2 ^ X3 ^ rk[i])）
    for (int i = 0; i < 32; ++i) {
        uint32_t temp = X[0] ^ tau(X[1] ^ X[2] ^ X[3] ^ rk[i]);
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = temp;
    }

    // 反序变换：将最后一轮的寄存器值反序后作为密文（因迭代后顺序为X3,X2,X1,X0，需调整为X3,X2,X1,X0 -> 密文顺序）
    ciphertext[0] = X[3];
    ciphertext[1] = X[2];
    ciphertext[2] = X[1];
    ciphertext[3] = X[0];
}

/**
 * 辅助函数：将字节数组转换为32位字数组（用于输入明文/密钥）
 * @param bytes 输入字节数组
 * @param words 输出32位字数组
 */
void bytesToWords(const uint8_t bytes[16], uint32_t words[4]) {
    for (int i = 0; i < 4; ++i) {
        // 每个字由4个字节组成
        words[i] = (static_cast<uint32_t>(bytes[4*i]) << 24) 
                 | (static_cast<uint32_t>(bytes[4*i + 1]) << 16) 
                 | (static_cast<uint32_t>(bytes[4*i + 2]) << 8) 
                 | bytes[4*i + 3];
    }
}

/**
 * 辅助函数：将32位字数组转换为字节数组，用于输出密文
 * @param words 输入32位字数组
 * @param bytes 输出字节数组
 */
void wordsToBytes(const uint32_t words[4], uint8_t bytes[16]) {
    for (int i = 0; i < 4; ++i) {
        // 拆分32位字为4个字节
        bytes[4*i] = (words[i] >> 24) & 0xFF;
        bytes[4*i + 1] = (words[i] >> 16) & 0xFF;
        bytes[4*i + 2] = (words[i] >> 8) & 0xFF;
        bytes[4*i + 3] = words[i] & 0xFF;
    }
}


// -------------------------- 测试代码 --------------------------

int main() {
    // 测试向量（来自SM4算法标准，用于验证实现正确性）
    // 明文：01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    uint8_t plaintextBytes[16] = {
        0x01, 0x23, 0x45, 0x67, 
        0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 
        0x76, 0x54, 0x32, 0x10
    };

    // 密钥：01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    uint8_t keyBytes[16] = {
        0x01, 0x23, 0x45, 0x67, 
        0x89, 0xab, 0xcd, 0xef, 
        0xfe, 0xdc, 0xba, 0x98, 
        0x76, 0x54, 0x32, 0x10
    };

    // 转换为32位字数组
    uint32_t plaintextWords[4], keyWords[4], ciphertextWords[4];
    bytesToWords(plaintextBytes, plaintextWords);
    bytesToWords(keyBytes, keyWords);

    // 加密执行
    sm4Encrypt(plaintextWords, keyWords, ciphertextWords);

    // 转换为字节数组并输出
    uint8_t ciphertextBytes[16];
    wordsToBytes(ciphertextWords, ciphertextBytes);

    // 输出结果（预期密文：68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46）
    cout << "明文: ";
    for (int i = 0; i < 16; ++i) cout << hex << setw(2) << setfill('0') << static_cast<int>(plaintextBytes[i]) << " ";
    cout << endl;

    cout << "密钥: ";
    for (int i = 0; i < 16; ++i) cout << hex << setw(2) << setfill('0') << static_cast<int>(keyBytes[i]) << " ";
    cout << endl;

    cout << "密文: ";
    for (int i = 0; i < 16; ++i) cout << hex << setw(2) << setfill('0') << static_cast<int>(ciphertextBytes[i]) << " ";
    cout << endl;

    return 0;
}