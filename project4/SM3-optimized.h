#include <iostream>
#include <cstring>
#include <vector>
#include <cstdint>

//架构检测
#if defined(__x86_64__) || defined(_M_X64)
#define X86_64_ARCH
#elif defined(__aarch64__) || defined(_M_ARM64)
#define ARM64_ARCH
#endif

//SM3密码杂凑算法优化实现
class SM3 {
private:
    static const uint32_t IV[8];  //初始向量IV
    uint8_t message_block[64];    //消息分组缓冲区
    uint64_t message_length;      //当前缓冲区中的字节数
    uint64_t total_bits;          //消息总长度
    uint32_t digest[8];           //压缩函数中间结果

    //循环左移函数
    static inline uint32_t rotate_left(uint32_t x, uint32_t n) {
#ifdef X86_64_ARCH
        //使用BMI2指令集的rorx指令优化循环移位
        if (n == 0) return x;
        return _rotl(x, n);
#elif defined(ARM64_ARCH)
        //ARM64桶形移位器可直接在运算中包含移位操作
        return (x << n) | (x >> (32 - n));
#else
        return (x << n) | (x >> (32 - n));
#endif
    }

    //置换函数P0 
    static inline uint32_t P0(uint32_t x) {
#ifdef X86_64_ARCH
        //X86_64: 减少寄存器移动，合并操作
        uint32_t r9 = rotate_left(x, 9);
        uint32_t r17 = rotate_left(x, 17);
        return x ^ r9 ^ r17;
#elif defined(ARM64_ARCH)
        //ARM64: 利用单条指令完成移位和异或
        return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
#endif
    }

    //置换函数P1
    static inline uint32_t P1(uint32_t x) {
#ifdef X86_64_ARCH
        uint32_t r15 = rotate_left(x, 15);
        uint32_t r23 = rotate_left(x, 23);
        return x ^ r15 ^ r23;
#elif defined(ARM64_ARCH)
        return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
#endif
    }

    //布尔函数FF
    static inline uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
#ifdef X86_64_ARCH
        //X86_64: 利用条件移动指令减少分支
        if (j <= 15) {
            return x ^ y ^ z;
        }
        else {
            return (x & y) | (x & z) | (y & z);
        }
#elif defined(ARM64_ARCH)
        //ARM64: 利用条件选择指令减少分支
        return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
#endif
    }

    //布尔函数GG
    static inline uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
#ifdef X86_64_ARCH
        if (j <= 15) {
            return x ^ y ^ z;
        }
        else {
            return (x & y) | (~x & z);
        }
#elif defined(ARM64_ARCH)
        return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (~x & z));
#endif
    }

    //常量Tj - 优化存储访问
    static inline uint32_t T(int j) {
        // 直接返回而不使用数组访问，减少内存操作
        return (j <= 15) ? 0x79CC4519 : 0x7A879D8A;
    }

    //消息扩展函数
    void expand(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
#ifdef X86_64_ARCH
        //X86_64使用SIMD指令加速消息扩展
        __m128i vec0, vec1, vec2, vec3;

        //加载16个32位字到4个128位寄存器
        vec0 = _mm_loadu_si128((const __m128i*) & block[0]);
        vec1 = _mm_loadu_si128((const __m128i*) & block[16]);
        vec2 = _mm_loadu_si128((const __m128i*) & block[32]);
        vec3 = _mm_loadu_si128((const __m128i*) & block[48]);

        //字节序转换并存储到W[0-15]
        _mm_storeu_si128((__m128i*) & W[0], _mm_shuffle_epi8(vec0, _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)));
        _mm_storeu_si128((__m128i*) & W[4], _mm_shuffle_epi8(vec1, _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)));
        _mm_storeu_si128((__m128i*) & W[8], _mm_shuffle_epi8(vec2, _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)));
        _mm_storeu_si128((__m128i*) & W[12], _mm_shuffle_epi8(vec3, _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12)));
#elif defined(ARM64_ARCH)
        //ARM64
        uint8x16_t vec0, vec1, vec2, vec3;
        uint32x4_t w;

        vec0 = vld1q_u8(&block[0]);
        vec1 = vld1q_u8(&block[16]);
        vec2 = vld1q_u8(&block[32]);
        vec3 = vld1q_u8(&block[48]);

        //字节序转换
        w = vrev32q_u32(vreinterpretq_u32_u8(vec0));
        vst1q_u32(&W[0], w);
        w = vrev32q_u32(vreinterpretq_u32_u8(vec1));
        vst1q_u32(&W[4], w);
        w = vrev32q_u32(vreinterpretq_u32_u8(vec2));
        vst1q_u32(&W[8], w);
        w = vrev32q_u32(vreinterpretq_u32_u8(vec3));
        vst1q_u32(&W[12], w);
#else
        //通用实现
        for (int i = 0; i < 16; i++) {
            W[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) |
                (block[4 * i + 2] << 8) | block[4 * i + 3];
        }
#endif

        //扩展W16-W67
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)) ^
                rotate_left(W[j - 13], 7) ^ W[j - 6];
        }

        //计算W'0-W'63
#ifdef X86_64_ARCH
        //X86_64: 使用SIMD并行计算W'
        for (int j = 0; j < 64; j += 4) {
            __m128i w = _mm_loadu_si128((const __m128i*) & W[j]);
            __m128i w4 = _mm_loadu_si128((const __m128i*) & W[j + 4]);
            __m128i xor_res = _mm_xor_si128(w, w4);
            _mm_storeu_si128((__m128i*) & W1[j], xor_res);
        }
#elif defined(ARM64_ARCH)
        //ARM64: NEON并行计算
        for (int j = 0; j < 64; j += 4) {
            uint32x4_t w = vld1q_u32(&W[j]);
            uint32x4_t w4 = vld1q_u32(&W[j + 4]);
            uint32x4_t xor_res = veorq_u32(w, w4);
            vst1q_u32(&W1[j], xor_res);
        }
#else
        //通用实现
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }
#endif
    }

    //压缩函数 - 架构优化版本
    void compress(const uint8_t block[64]) {
        uint32_t W[68], W1[64];
        expand(block, W, W1);

        //初始化工作变量，尽可能使用寄存器
        register uint32_t A = digest[0];
        register uint32_t B = digest[1];
        register uint32_t C = digest[2];
        register uint32_t D = digest[3];
        register uint32_t E = digest[4];
        register uint32_t F = digest[5];
        register uint32_t G = digest[6];
        register uint32_t H = digest[7];

#ifdef X86_64_ARCH
        //X86_64: 展开部分循环，减少循环开销
        //第0-15轮
        for (int j = 0; j < 16; j++) {
            uint32_t Tj = 0x79CC4519;
            uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(Tj, j), 7);
            uint32_t SS2 = SS1 ^ rotate_left(A, 12);
            uint32_t TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
            uint32_t TT2 = (E ^ F ^ G) + H + SS1 + W[j];
            D = C;
            C = rotate_left(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotate_left(F, 19);
            F = E;
            E = P0(TT2);
        }
        //第16-63轮
        for (int j = 16; j < 64; j++) {
            uint32_t Tj = 0x7A879D8A;
            uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(Tj, j), 7);
            uint32_t SS2 = SS1 ^ rotate_left(A, 12);
            uint32_t TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j];
            uint32_t TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j];
            D = C;
            C = rotate_left(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotate_left(F, 19);
            F = E;
            E = P0(TT2);
        }
#elif defined(ARM64_ARCH)
        //ARM64: 利用32个通用寄存器的优势，减少内存访问
        //使用LEA-like操作组合加法和移位
        for (int j = 0; j < 64; j++) {
            uint32_t Tj = (j <= 15) ? 0x79CC4519 : 0x7A879D8A;
            uint32_t rotA12 = rotate_left(A, 12);
            uint32_t rotTj = rotate_left(Tj, j);
            uint32_t SS1 = rotate_left(rotA12 + E + rotTj, 7);
            uint32_t SS2 = SS1 ^ rotA12;

            uint32_t TT1, TT2;
            if (j <= 15) {
                TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
                TT2 = (E ^ F ^ G) + H + SS1 + W[j];
            }
            else {
                TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j];
                TT2 = ((E & F) | (~E & G)) + H + SS1 + W[j];
            }

            //寄存器轮转优化
            D = C;
            C = rotate_left(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotate_left(F, 19);
            F = E;
            E = P0(TT2);
        }
#else
        //通用实现
        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T(j), j), 7);
            uint32_t SS2 = SS1 ^ rotate_left(A, 12);
            uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
            uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];
            D = C;
            C = rotate_left(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = rotate_left(F, 19);
            F = E;
            E = P0(TT2);
        }
#endif

        //与初始值异或
        digest[0] ^= A;
        digest[1] ^= B;
        digest[2] ^= C;
        digest[3] ^= D;
        digest[4] ^= E;
        digest[5] ^= F;
        digest[6] ^= G;
        digest[7] ^= H;
    }

public:
    //构造函数
    SM3() {
        reset();
    }

    //重置上下文
    void reset() {
        message_length = 0;
        total_bits = 0;
        memcpy(digest, IV, sizeof(IV));
        memset(message_block, 0, sizeof(message_block));
    }

    //更新哈希计算优化批量处理
    void update(const uint8_t* data, size_t length) {
#ifdef X86_64_ARCH
        //X86_64: 利用大块处理优化
        size_t block_aligned = length & ~(size_t)63; // 64字节对齐
        size_t remaining = length - block_aligned;

        //处理对齐的完整块
        for (size_t i = 0; i < block_aligned; i += 64) {
            if (message_length == 0) {
                compress(&data[i]);
                total_bits += 512;
            }
            else {
                //填充现有缓冲区
                size_t copy_len = 64 - message_length;
                memcpy(&message_block[message_length], &data[i], copy_len);
                message_length += copy_len;
                compress(message_block);
                total_bits += 512;
                message_length = 0;
                i += copy_len - 64; //调整循环索引
            }
        }

        //处理剩余数据
        if (remaining > 0) {
            memcpy(&message_block[message_length], &data[block_aligned], remaining);
            message_length += remaining;
        }
#elif defined(ARM64_ARCH)
        //ARM64:利用缓存特性优化
        size_t chunk_size = 64 * 16; //16个块为一组，适应ARM缓存
        size_t i = 0;

        while (i < length) {
            size_t process_len = (length - i) < chunk_size ? (length - i) : chunk_size;

            while (process_len > 0) {
                if (message_length == 64) {
                    compress(message_block);
                    total_bits += 512;
                    message_length = 0;
                }

                size_t copy_len = (64 - message_length) < process_len ?
                    (64 - message_length) : process_len;
                memcpy(&message_block[message_length], &data[i], copy_len);
                message_length += copy_len;
                i += copy_len;
                process_len -= copy_len;
            }
        }
#else
        //通用实现
        for (size_t i = 0; i < length; i++) {
            message_block[message_length++] = data[i];
            if (message_length == 64) {
                compress(message_block);
                total_bits += 512;
                message_length = 0;
            }
        }
#endif
    }

    //完成哈希计算
    void final(uint8_t* result) {
        total_bits += message_length * 8;
        message_block[message_length++] = 0x80;

        if (message_length > 56) {
            while (message_length < 64) {
                message_block[message_length++] = 0x00;
            }
            compress(message_block);
            message_length = 0;
        }

        while (message_length < 56) {
            message_block[message_length++] = 0x00;
        }

        //存储长度
#ifdef X86_64_ARCH
        //使用64位存储指令
        * (uint64_t*)&message_block[56] = _byteswap_uint64(total_bits);
#elif defined(ARM64_ARCH)
        //ARM64: 使用专门的64位存储
        uint64_t len = __builtin_bswap64(total_bits);
        memcpy(&message_block[56], &len, 8);
#else
        for (int i = 0; i < 8; i++) {
            message_block[56 + i] = (total_bits >> (8 * (7 - i))) & 0xFF;
        }
#endif

        compress(message_block);

        //输出结果
#ifdef X86_64_ARCH
        //使用SIMD指令批量转换字节序
        __m128i v0 = _mm_loadu_si128((const __m128i*) & digest[0]);
        __m128i v1 = _mm_loadu_si128((const __m128i*) & digest[4]);
        v0 = _mm_shuffle_epi8(v0, _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12));
        v1 = _mm_shuffle_epi8(v1, _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12));
        _mm_storeu_si128((__m128i*) & result[0], v0);
        _mm_storeu_si128((__m128i*) & result[16], v1);
#elif defined(ARM64_ARCH)
        //ARM64: NEON批量转换
        uint32x4_t v0 = vld1q_u32(&digest[0]);
        uint32x4_t v1 = vld1q_u32(&digest[4]);
        v0 = vrev32q_u32(v0);
        v1 = vrev32q_u32(v1);
        vst1q_u8(&result[0], vreinterpretq_u8_u32(v0));
        vst1q_u8(&result[16], vreinterpretq_u8_u32(v1));
#else
        for (int i = 0; i < 8; i++) {
            result[4 * i] = (digest[i] >> 24) & 0xFF;
            result[4 * i + 1] = (digest[i] >> 16) & 0xFF;
            result[4 * i + 2] = (digest[i] >> 8) & 0xFF;
            result[4 * i + 3] = digest[i] & 0xFF;
        }
#endif

        reset();
    }

    //计算SM3哈希值
    static void hash(const uint8_t* data, size_t length, uint8_t* result) {
        SM3 sm3;
        sm3.update(data, length);
        sm3.final(result);
    }
};

//初始化IV值
const uint32_t SM3::IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

//辅助函数：将字节数组转换为十六进制字符串
std::string bytes_to_hex(const uint8_t* bytes, size_t length) {
    const char* hex_chars = "0123456789ABCDEF";
    std::string hex_str;
    hex_str.reserve(length * 2);

#ifdef X86_64_ARCH
    //X86_64: 展开循环优化
    size_t i = 0;
    for (; i + 4 <= length; i += 4) {
        hex_str += hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i] & 0x0F];
        hex_str += hex_chars[(bytes[i + 1] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i + 1] & 0x0F];
        hex_str += hex_chars[(bytes[i + 2] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i + 2] & 0x0F];
        hex_str += hex_chars[(bytes[i + 3] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i + 3] & 0x0F];
    }
    //处理剩余字节
    for (; i < length; i++) {
        hex_str += hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i] & 0x0F];
    }
#else
    for (size_t i = 0; i < length; i++) {
        hex_str += hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i] & 0x0F];
    }
#endif

    return hex_str;
}

//测试函数
void test_sm3() {
    //测试案例1：空字符串
    {
        uint8_t result[32];
        SM3::hash(nullptr, 0, result);
        std::string hex = bytes_to_hex(result, 32);
        std::cout << "空字符串哈希: " << hex << std::endl;
        std::cout << "预期结果: 1AB21D8355CFA17F8E61194831E81A8F79C2B6773A0FF8E534DFB6406B7EDEE" << std::endl << std::endl;
    }

    //测试案例2："abc"
    {
        const char* data = "abc";
        uint8_t result[32];
        SM3::hash((const uint8_t*)data, strlen(data), result);
        std::string hex = bytes_to_hex(result, 32);
        std::cout << "字符串\"abc\"哈希: " << hex << std::endl;
        std::cout << "预期结果: 66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0" << std::endl << std::endl;
    }
}

int main() {
    test_sm3();

    //演示分块处理
    std::cout << "演示分块处理:" << std::endl;
    const char* long_data = "这是一个用于测试SM3算法分块处理的长字符串，将分多次调用update方法来处理它。";
    SM3 sm3;

    size_t len = strlen(long_data);
    size_t chunk_size = 10;
    for (size_t i = 0; i < len; i += chunk_size) {
        size_t process_len = (i + chunk_size > len) ? (len - i) : chunk_size;
        sm3.update((const uint8_t*)&long_data[i], process_len);
    }
    uint8_t result[32];
    sm3.final(result);
    std::cout << "长字符串哈希: " << bytes_to_hex(result, 32) << std::endl;

    return 0;
}
