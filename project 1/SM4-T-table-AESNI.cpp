#include <iostream>
#include <cstdint>
#include <iomanip>
#include <cassert>
#include <chrono>
#include <immintrin.h>  // AESNI指令集头文件

// S盒
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
  * T-table
  */
uint32_t T0[256], T1[256], T2[256], T3[256];

/**
 * 初始化T-table
 */
void initTTable() {
    for (int i = 0; i < 256; i++) {
        uint32_t b = S_BOX[i];
        // 计算T0: S盒后左移24位并应用线性变换
        uint32_t t0 = static_cast<uint32_t>(b) << 24;
        t0 = t0 ^ ROTL32(t0, 2) ^ ROTL32(t0, 10) ^ ROTL32(t0, 18) ^ ROTL32(t0, 24);
        T0[i] = t0;
        // 计算T1: S盒后左移16位并应用线性变换
        uint32_t t1 = static_cast<uint32_t>(b) << 16;
        t1 = t1 ^ ROTL32(t1, 2) ^ ROTL32(t1, 10) ^ ROTL32(t1, 18) ^ ROTL32(t1, 24);
        T1[i] = t1;
        // 计算T2: S盒后左移8位并应用线性变换
        uint32_t t2 = static_cast<uint32_t>(b) << 8;
        t2 = t2 ^ ROTL32(t2, 2) ^ ROTL32(t2, 10) ^ ROTL32(t2, 18) ^ ROTL32(t2, 24);
        T2[i] = t2;
        // 计算T3: S盒后直接应用线性变换
        uint32_t t3 = static_cast<uint32_t>(b);
        t3 = t3 ^ ROTL32(t3, 2) ^ ROTL32(t3, 10) ^ ROTL32(t3, 18) ^ ROTL32(t3, 24);
        T3[i] = t3;
    }
}

/**
 * 非线性变换tau（使用T-table查表）
 */
uint32_t nonlinearTransform(uint32_t x) {
    return T0[(x >> 24) & 0xFF] ^
        T1[(x >> 16) & 0xFF] ^
        T2[(x >> 8) & 0xFF] ^
        T3[x & 0xFF];
}

/**
 * 使用AESNI优化的密钥扩展，利用向量寄存器一次处理多个字，加速子密钥生成
 */
void keyExpansionAESNI(const uint32_t key[4], uint32_t rk[32]) {
    assert(key != nullptr && rk != nullptr);
    // 使用AESNI向量寄存器加载密钥和FK参数
    __m128i key_vec = _mm_loadu_si128((const __m128i*)key);
    __m128i fk_vec = _mm_loadu_si128((const __m128i*)FK);
    // 初始化密钥寄存器：K[i] = key[i] ^ FK[i]
    __m128i K = _mm_xor_si128(key_vec, fk_vec);
    _mm_storeu_si128((__m128i*)rk, K);  // 存储初始密钥
    // 加载轮常量到向量寄存器
    __m128i ck_low = _mm_loadu_si128((const __m128i*) & CK[0]);
    __m128i ck_mid1 = _mm_loadu_si128((const __m128i*) & CK[4]);
    __m128i ck_mid2 = _mm_loadu_si128((const __m128i*) & CK[8]);
    __m128i ck_high = _mm_loadu_si128((const __m128i*) & CK[12]);
    // 循环生成子密钥，每次处理4个轮常量（利用AESNI向量并行性）
    for (int i = 0; i < 32; i += 4) {
        // 提取当前需要的轮常量
        __m128i ck_vec;
        if (i < 16) {
            if (i < 8) {
                ck_vec = (i < 4) ? ck_low : ck_mid1;
            }
            else {
                ck_vec = ck_mid2;
            }
        }
        else {
            ck_vec = ck_high;
        }
        // 提取K[i+1], K[i+2], K[i+3]
        __m128i K1 = _mm_shuffle_epi32(K, _MM_SHUFFLE(0, 3, 2, 1));
        __m128i K2 = _mm_shuffle_epi32(K, _MM_SHUFFLE(1, 0, 3, 2));
        __m128i K3 = _mm_shuffle_epi32(K, _MM_SHUFFLE(2, 1, 0, 3));
        // 计算 K[i+1]^K[i+2]^K[i+3]^CK[i]
        __m128i temp = _mm_xor_si128(K1, K2);
        temp = _mm_xor_si128(temp, K3);
        temp = _mm_xor_si128(temp, ck_vec);
        // 存储临时值用于非线性变换
        uint32_t temp_words[4];
        _mm_storeu_si128((__m128i*)temp_words, temp);
        // 对每个字应用非线性变换
        __m128i trans_vec;
        uint32_t trans_words[4];
        for (int j = 0; j < 4; j++) {
            if (i + j < 32) {
                trans_words[j] = nonlinearTransform(temp_words[j]);
            }
            else {
                trans_words[j] = 0;  // 超出范围的部分不用处理
            }
        }
        trans_vec = _mm_loadu_si128((const __m128i*)trans_words);
        // 计算新的子密钥: K[i+4] = K[i] ^ nonlinearTransform(...)
        __m128i new_K = _mm_xor_si128(K, trans_vec);
        // 存储生成的子密钥
        if (i < 28) {  // 确保不越界
            _mm_storeu_si128((__m128i*) & rk[i + 4], new_K);
        }
        else {
            // 处理最后几个子密钥
            uint32_t last_words[4];
            _mm_storeu_si128((__m128i*)last_words, new_K);
            for (int j = 0; j < 4 && i + 4 + j < 32; j++) {
                rk[i + 4 + j] = last_words[j];
            }
        }
        // 更新密钥寄存器
        K = new_K;
    }
}

/**
 * 使用AESNI优化的SM4加密
 * 利用向量指令加速轮函数计算
 */
void sm4EncryptAESNI(const uint32_t plaintext[4], const uint32_t key[4], uint32_t ciphertext[4]) {
    assert(plaintext != nullptr && key != nullptr && ciphertext != nullptr);
    uint32_t rk[32];
    keyExpansionAESNI(key, rk);  // 使用AESNI优化的密钥扩展
    // 使用AESNI向量寄存器加载明文
    __m128i X = _mm_loadu_si128((const __m128i*)plaintext);
    // 加载所有子密钥到向量寄存器
    __m128i rk_vecs[8];  // 32个子密钥 = 8个128位向量
    for (int i = 0; i < 8; i++) {
        rk_vecs[i] = _mm_loadu_si128((const __m128i*) & rk[i * 4]);
    }
    // 32轮迭代，使用AESNI指令优化
    for (int i = 0; i < 32; ++i) {
        // 提取当前轮需要的子密钥
        __m128i rk_vec = rk_vecs[i / 4];
        uint32_t rk_word;
        // 根据当前轮数提取对应的子密钥
        switch (i % 4) {
        case 0: rk_word = _mm_extract_epi32(rk_vec, 0); break;
        case 1: rk_word = _mm_extract_epi32(rk_vec, 1); break;
        case 2: rk_word = _mm_extract_epi32(rk_vec, 2); break;
        case 3: rk_word = _mm_extract_epi32(rk_vec, 3); break;
        }
        // 提取X1, X2, X3
        __m128i X1 = _mm_shuffle_epi32(X, _MM_SHUFFLE(0, 3, 2, 1));
        __m128i X2 = _mm_shuffle_epi32(X, _MM_SHUFFLE(1, 0, 3, 2));
        __m128i X3 = _mm_shuffle_epi32(X, _MM_SHUFFLE(2, 1, 0, 3));
        // 计算 X1 ^ X2 ^ X3 ^ rk[i]
        __m128i temp = _mm_xor_si128(X1, X2);
        temp = _mm_xor_si128(temp, X3);
        // 将子密钥扩展为向量
        __m128i rk_broadcast = _mm_set1_epi32(rk_word);
        temp = _mm_xor_si128(temp, rk_broadcast);
        // 存储临时值用于非线性变换
        uint32_t temp_word;
        temp_word = _mm_extract_epi32(temp, 0);  // 我们只需要第一个32位字
        // 应用非线性变换
        uint32_t trans_word = nonlinearTransform(temp_word);

        // 计算新的X3: X0 ^ 非线性变换结果
        uint32_t X0 = _mm_extract_epi32(X, 0);
        uint32_t new_X3 = X0 ^ trans_word;
        // 更新X寄存器（循环移位并加入新值）
        X = _mm_shuffle_epi32(X, _MM_SHUFFLE(0, 3, 2, 1));  // 左移一个字
        X = _mm_insert_epi32(X, new_X3, 3);  // 在最后一个位置插入新值
    }
    // 反序变换（加密最终输出：X3, X2, X1, X0）
    __m128i cipher = _mm_shuffle_epi32(X, _MM_SHUFFLE(0, 1, 2, 3));
    _mm_storeu_si128((__m128i*)ciphertext, cipher);
}

/**
 * 16字节数组转4个32位字
 */
void bytesToWords(const uint8_t bytes[16], uint32_t words[4]) {
    assert(bytes != nullptr && words != nullptr);
    // 使用AESNI指令优化字节到字的转换
    __m128i bytes_vec = _mm_loadu_si128((const __m128i*)bytes);
    _mm_storeu_si128((__m128i*)words, bytes_vec);
    // 调整字节序（小端到网络字节序）
    for (int i = 0; i < 4; ++i) {
        words[i] = _byteswap_ulong(words[i]);
    }
}

/**
 * 4个32位字转16字节数组
 */
void wordsToBytes(const uint32_t words[4], uint8_t bytes[16]) {
    assert(words != nullptr && bytes != nullptr);
    // 调整字节序（网络字节序到小端）
    uint32_t swapped[4];
    for (int i = 0; i < 4; ++i) {
        swapped[i] = _byteswap_ulong(words[i]);
    }
    // 使用AESNI指令优化字到字节的转换
    __m128i words_vec = _mm_loadu_si128((const __m128i*)swapped);
    _mm_storeu_si128((__m128i*)bytes, words_vec);
}

// -------------------------- 测试代码 --------------------------
int main() {

    // 初始化T-table
    initTTable();

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
    uint32_t plaintextWords[4], keyWords[4], ciphertextWords[4];
    bytesToWords(plaintextBytes, plaintextWords);
    bytesToWords(keyBytes, keyWords);

    // 性能测试
    const int TEST_ITERATIONS = 100000; // 增加迭代次数以更好地体现性能差异
    // AESNI优化版本性能测试
    auto start_aesni = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        sm4EncryptAESNI(plaintextWords, keyWords, ciphertextWords);
    }
    auto end_aesni = std::chrono::high_resolution_clock::now();
    auto duration_aesni = std::chrono::duration_cast<std::chrono::microseconds>(end_aesni - start_aesni).count();

    // 输出结果
    uint8_t ciphertextBytes[16];
    wordsToBytes(ciphertextWords, ciphertextBytes);
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
    // 性能结果
    std::cout << "\n性能测试 (" << TEST_ITERATIONS << " 次加密):\n";
    std::cout << "AESNI优化版本时间: " << duration_aesni << " 微秒\n";
    // 计算平均加密时间
    double avg_aesni = static_cast<double>(duration_aesni) / TEST_ITERATIONS;
    std::cout << "AESNI优化版本平均时间: " << avg_aesni << " 微秒/次\n";
    return 0;
}
