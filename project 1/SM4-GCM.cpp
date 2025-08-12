#include <iostream>
#include <vector>
#include <cstdint>
#include <iomanip>
#include <string>
#include <chrono>  // 新增：用于时间计算

using namespace std;
using namespace chrono;  // 新增：时间命名空间

//SM4算法常量和函数实现
class SM4 {
private:
    static const uint32_t FK[4];
    static const uint32_t CK[32];
    uint32_t rk[32]; //轮密钥
    //循环左移
    static uint32_t rotl(uint32_t x, int n) {
        return (x << n) | (x >> (32 - n));
    }
    //S盒
    static uint8_t sbox(uint8_t x) {
        static const uint8_t box[256] = {
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
        return box[x];
    }

    //字节替换
    static uint32_t byte_sub(uint32_t x) {
        uint8_t b[4];
        for (int i = 0; i < 4; i++) {
            b[i] = (x >> (8 * (3 - i))) & 0xff;
            b[i] = sbox(b[i]);
        }
        return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 |
            (uint32_t)b[2] << 8 | (uint32_t)b[3];
    }

    //线性变换L
    static uint32_t L(uint32_t x) {
        return x ^ rotl(x, 2) ^ rotl(x, 10) ^ rotl(x, 18) ^ rotl(x, 24);
    }

    //轮函数F
    static uint32_t F(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
        return x0 ^ L(byte_sub(x1 ^ x2 ^ x3 ^ rk));
    }

public:
    //密钥扩展
    void set_key(const uint8_t key[16]) {
        uint32_t mk[4];
        for (int i = 0; i < 4; i++) {
            mk[i] = (uint32_t)key[4 * i] << 24 | (uint32_t)key[4 * i + 1] << 16 |
                (uint32_t)key[4 * i + 2] << 8 | (uint32_t)key[4 * i + 3];
        }

        uint32_t k[36];
        k[0] = mk[0] ^ FK[0];
        k[1] = mk[1] ^ FK[1];
        k[2] = mk[2] ^ FK[2];
        k[3] = mk[3] ^ FK[3];

        for (int i = 0; i < 32; i++) {
            k[i + 4] = k[i] ^ L(byte_sub(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
            rk[i] = k[i + 4];
        }
    }

    //加密单块
    void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint32_t x[36];
        for (int i = 0; i < 4; i++) {
            x[i] = (uint32_t)in[4 * i] << 24 | (uint32_t)in[4 * i + 1] << 16 |
                (uint32_t)in[4 * i + 2] << 8 | (uint32_t)in[4 * i + 3];
        }

        for (int i = 0; i < 32; i++) {
            x[i + 4] = F(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]);
        }

        for (int i = 0; i < 4; i++) {
            uint32_t val = x[35 - i];
            out[4 * i] = (val >> 24) & 0xff;
            out[4 * i + 1] = (val >> 16) & 0xff;
            out[4 * i + 2] = (val >> 8) & 0xff;
            out[4 * i + 3] = val & 0xff;
        }
    }
};

//SM4常量初始化
const uint32_t SM4::FK[4] = {
    0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
};

const uint32_t SM4::CK[32] = {
   0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
   0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
   0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
   0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
   0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
   0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
   0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
   0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

//GCM相关函数
class GCM {
private:
    SM4 sm4;
    uint8_t H[16]; //哈希密钥

    //伽罗瓦域乘法(GF(2^128))
    void gfmul(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]) {
        uint8_t v[16];
        memcpy(v, y, 16);
        memset(z, 0, 16);
        for (int i = 0; i < 128; i++) {
            // 如果x的第i位为1，则z ^= v
            if ((x[i / 8] >> (7 - (i % 8))) & 1) {
                for (int j = 0; j < 16; j++) {
                    z[j] ^= v[j];
                }
            }
            //移位
            uint8_t carry = 0;
            for (int j = 15; j >= 0; j--) {
                uint8_t b = v[j] & 1;
                v[j] = (v[j] >> 1) | (carry << 7);
                carry = b;
            }
            //如果有进位，与R异或
            if (carry) {
                v[0] ^= 0xe1; //R = 0x87 = 10000111，多项式表示
            }
        }
    }
    //GHASH 函数
    void ghash(const uint8_t key[16], const uint8_t* data, size_t len, uint8_t hash[16]) {
        memset(hash, 0, 16);
        uint8_t block[16];
        size_t pos = 0;
        while (pos < len) {
            size_t rem = len - pos;
            size_t sz = (rem < 16) ? rem : 16;
            memset(block, 0, 16);
            memcpy(block, data + pos, sz);
            pos += sz;
            //hash ^= block
            for (int i = 0; i < 16; i++) {
                hash[i] ^= block[i];
            }
            //hash = hash * H mod P
            uint8_t temp[16];
            gfmul(hash, key, temp);
            memcpy(hash, temp, 16);
        }
    }
    //计数器生成
    void generate_ctr(const uint8_t nonce[12], uint64_t counter, uint8_t ctr[16]) {
        memcpy(ctr, nonce, 12);
        ctr[12] = (counter >> 24) & 0xff;
        ctr[13] = (counter >> 16) & 0xff;
        ctr[14] = (counter >> 8) & 0xff;
        ctr[15] = counter & 0xff;
    }
public:
    //初始化密钥
    void set_key(const uint8_t key[16]) {
        sm4.set_key(key);
        uint8_t zero[16] = { 0 };
        sm4.encrypt_block(zero, H); //H = SM4(K, 0^128)
    }
    //加密并生成标签
    void encrypt(const uint8_t nonce[12], const uint8_t* plaintext, size_t plaintext_len,
        const uint8_t* aad, size_t aad_len, uint8_t* ciphertext, uint8_t tag[16]) {
        //生成初始计数器块
        uint8_t ctr0[16];
        generate_ctr(nonce, 0, ctr0);
        //加密计数器块得到J0
        uint8_t J0[16];
        sm4.encrypt_block(ctr0, J0);
        //CTR模式加密
        for (size_t i = 0; i < plaintext_len; i += 16) {
            uint8_t ctr[16];
            generate_ctr(nonce, i / 16 + 1, ctr);

            uint8_t keystream[16];
            sm4.encrypt_block(ctr, keystream);

            size_t block_len = (plaintext_len - i < 16) ? plaintext_len - i : 16;
            for (size_t j = 0; j < block_len; j++) {
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            }
        }
        //计算GHASH得到标签
        size_t total_len = aad_len + ((aad_len % 16 != 0) ? (16 - aad_len % 16) : 0) +
            plaintext_len + ((plaintext_len % 16 != 0) ? (16 - plaintext_len % 16) : 0) + 16;
        vector<uint8_t> ghash_input(total_len);
        size_t pos = 0;
        //添加AAD
        memcpy(ghash_input.data() + pos, aad, aad_len);
        pos += aad_len;
        if (aad_len % 16 != 0) {
            pos += 16 - aad_len % 16;
        }
        //添加密文
        memcpy(ghash_input.data() + pos, ciphertext, plaintext_len);
        pos += plaintext_len;
        if (plaintext_len % 16 != 0) {
            pos += 16 - plaintext_len % 16;
        }
        //添加长度信息(64位AAD长度+64位密文长度)
        uint64_t aad_bits = aad_len * 8;
        uint64_t cipher_bits = plaintext_len * 8;
        for (int i = 0; i < 8; i++) {
            ghash_input[pos + i] = (aad_bits >> (64 - 8 * (i + 1))) & 0xff;
        }
        for (int i = 0; i < 8; i++) {
            ghash_input[pos + 8 + i] = (cipher_bits >> (64 - 8 * (i + 1))) & 0xff;
        }
        //计算GHASH
        uint8_t hash[16];
        ghash(H, ghash_input.data(), total_len, hash);
        //标签 = hash ^ J0
        for (int i = 0; i < 16; i++) {
            tag[i] = hash[i] ^ J0[i];
        }
    }
    //解密并验证标签
    bool decrypt(const uint8_t nonce[12], const uint8_t* ciphertext, size_t ciphertext_len,
        const uint8_t* aad, size_t aad_len, const uint8_t tag[16], uint8_t* plaintext) {
        //生成初始计数器块
        uint8_t ctr0[16];
        generate_ctr(nonce, 0, ctr0);
        //加密计数器块得到J0
        uint8_t J0[16];
        sm4.encrypt_block(ctr0, J0);
        //CTR模式解密
        for (size_t i = 0; i < ciphertext_len; i += 16) {
            uint8_t ctr[16];
            generate_ctr(nonce, i / 16 + 1, ctr);
            uint8_t keystream[16];
            sm4.encrypt_block(ctr, keystream);
            size_t block_len = (ciphertext_len - i < 16) ? ciphertext_len - i : 16;
            for (size_t j = 0; j < block_len; j++) {
                plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
            }
        }
        //计算GHASH验证标签
        size_t total_len = aad_len + ((aad_len % 16 != 0) ? (16 - aad_len % 16) : 0) +
            ciphertext_len + ((ciphertext_len % 16 != 0) ? (16 - ciphertext_len % 16) : 0) + 16;
        vector<uint8_t> ghash_input(total_len);
        size_t pos = 0;
        //添加AAD
        memcpy(ghash_input.data() + pos, aad, aad_len);
        pos += aad_len;
        if (aad_len % 16 != 0) {
            pos += 16 - aad_len % 16;
        }
        //添加密文
        memcpy(ghash_input.data() + pos, ciphertext, ciphertext_len);
        pos += ciphertext_len;
        if (ciphertext_len % 16 != 0) {
            pos += 16 - ciphertext_len % 16;
        }
        //添加长度信息
        uint64_t aad_bits = aad_len * 8;
        uint64_t cipher_bits = ciphertext_len * 8;
        for (int i = 0; i < 8; i++) {
            ghash_input[pos + i] = (aad_bits >> (64 - 8 * (i + 1))) & 0xff;
        }
        for (int i = 0; i < 8; i++) {
            ghash_input[pos + 8 + i] = (cipher_bits >> (64 - 8 * (i + 1))) & 0xff;
        }
        //计算GHASH
        uint8_t hash[16];
        ghash(H, ghash_input.data(), total_len, hash);
        //验证标签
        uint8_t computed_tag[16];
        for (int i = 0; i < 16; i++) {
            computed_tag[i] = hash[i] ^ J0[i];
        }
        //比较标签
        for (int i = 0; i < 16; i++) {
            if (computed_tag[i] != tag[i]) {
                return false;
            }
        }
        return true;
    }
};

//辅助函数：打印十六进制数据
void print_hex(const string& label, const uint8_t* data, size_t len) {
    cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i];
    }
    cout << dec << endl;
}

int main() {
    //测试向量
    uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t nonce[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };
    uint8_t aad[] = "Additional authenticated data";
    size_t aad_len = strlen((char*)aad);
    uint8_t plaintext[] = "SM4-GCM";
    size_t plaintext_len = strlen((char*)plaintext);
    //分配缓冲区
    vector<uint8_t> ciphertext(plaintext_len);
    uint8_t tag[16];
    vector<uint8_t> decrypted(plaintext_len);
    //加密
    GCM gcm;
    gcm.set_key(key);

    // 新增：加密时间计算
    auto start = high_resolution_clock::now();  // 记录开始时间
    gcm.encrypt(nonce, plaintext, plaintext_len, aad, aad_len, ciphertext.data(), tag);
    auto end = high_resolution_clock::now();    // 记录结束时间

    // 计算并输出加密耗时（毫秒）
    auto duration = duration_cast<microseconds>(end - start);
    double ms = duration.count() / 1000.0;  // 转换为毫秒
    cout << "加密耗时: " << fixed << setprecision(3) << ms << " ms" << endl;

    //打印结果
    print_hex("Key", key, 16);
    print_hex("Nonce", nonce, 12);
    cout << "AAD: " << aad << " (length: " << aad_len << ")" << endl;
    cout << "Plaintext: " << plaintext << " (length: " << plaintext_len << ")" << endl;
    print_hex("Ciphertext", ciphertext.data(), ciphertext.size());
    print_hex("Tag", tag, 16);
    //解密
    bool valid = gcm.decrypt(nonce, ciphertext.data(), ciphertext.size(),
        aad, aad_len, tag, decrypted.data());
    if (valid) {
        cout << "Decrypted (valid): " << (char*)decrypted.data() << endl;
    }
    else {
        cout << "Decrypted (invalid tag): " << (char*)decrypted.data() << endl;
    }
    //测试篡改检测
    ciphertext[0] ^= 0x01; //篡改密文
    valid = gcm.decrypt(nonce, ciphertext.data(), ciphertext.size(),
        aad, aad_len, tag, decrypted.data());
    if (valid) {
        cout << "Tampered decrypted (valid - ERROR): " << (char*)decrypted.data() << endl;
    }
    else {
        cout << "Tampered decrypted (invalid tag - CORRECT): " << (char*)decrypted.data() << endl;
    }
    return 0;
}