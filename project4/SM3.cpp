#include <iostream>
#include <cstring>
#include <vector>
#include <cstdint>

//SM3密码杂凑算法
class SM3 {
private:
    static const uint32_t IV[8];  //初始向量IV
    uint8_t message_block[64];    //消息分组缓冲区
    uint64_t message_length;      //当前缓冲区中的字节数
    uint64_t total_bits;          //消息总长度
    uint32_t digest[8];           //压缩函数中间结果

    //循环左移函数
    static uint32_t rotate_left(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }
    //压缩函数中的置换函数P0
    static uint32_t P0(uint32_t x) {
        return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
    }
    //压缩函数中的置换函数P1
    static uint32_t P1(uint32_t x) {
        return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
    }
    //布尔函数FF
    static uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j >= 0 && j <= 15) {
            return x ^ y ^ z;
        }
        else {
            return (x & y) | (x & z) | (y & z);
        }
    }
    //布尔函数GG
    static uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
        if (j >= 0 && j <= 15) {
            return x ^ y ^ z;
        }
        else {
            return (x & y) | (~x & z);
        }
    }
    //常量Tj
    static uint32_t T(int j) {
        if (j >= 0 && j <= 15) {
            return 0x79CC4519;
        }
        else {
            return 0x7A879D8A;
        }
    }

    //消息扩展函数，将512位消息块扩展为132个字
    void expand(const uint8_t block[64], uint32_t W[68], uint32_t W1[64]) {
        //将消息块转换为32位字(W0-W15)
        for (int i = 0; i < 16; i++) {
            W[i] = (block[4 * i] << 24) | (block[4 * i + 1] << 16) |
                (block[4 * i + 2] << 8) | block[4 * i + 3];
        }
        //扩展W16-W67
        for (int j = 16; j < 68; j++) {
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ rotate_left(W[j - 3], 15)) ^
                rotate_left(W[j - 13], 7) ^ W[j - 6];
        }
        //计算W'0-W'63
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }
    }

    //压缩函数，对一个512位消息块进行压缩
    void compress(const uint8_t block[64]) {
        uint32_t W[68], W1[64];
        expand(block, W, W1);
        //初始化工作变量
        uint32_t A = digest[0];
        uint32_t B = digest[1];
        uint32_t C = digest[2];
        uint32_t D = digest[3];
        uint32_t E = digest[4];
        uint32_t F = digest[5];
        uint32_t G = digest[6];
        uint32_t H = digest[7];
        //64轮迭代
        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = rotate_left(
                rotate_left(A, 12) + E + rotate_left(T(j), j), 7
            );
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
    //构造函数，初始化SM3上下文
    SM3() {
        reset();
    }
    //重置SM3上下文，准备新的哈希计算
    void reset() {
        //初始化消息长度和总位数
        message_length = 0;
        total_bits = 0;
        //初始化哈希值为初始向量IV
        memcpy(digest, IV, sizeof(IV));
        //清空消息块
        memset(message_block, 0, sizeof(message_block));
    }
    //更新哈希计算，处理输入数据
    void update(const uint8_t* data, size_t length) {
        //处理每个字节
        for (size_t i = 0; i < length; i++) {
            //将数据放入消息块
            message_block[message_length++] = data[i];
            //当消息块满时(512位)，进行压缩
            if (message_length == 64) {
                compress(message_block);
                total_bits += 512;
                message_length = 0;
            }
        }
    }

    //完成哈希计算，获取最终结果
    void final(uint8_t* result) {
        //计算总位数
        total_bits += message_length * 8;
        //填充消息
        //首先添加一个1
        message_block[message_length++] = 0x80;
        //如果剩余空间不足以存放64位长度信息，则先处理当前块
        if (message_length > 56) {
            //填充剩余空间为0
            while (message_length < 64) {
                message_block[message_length++] = 0x00;
            }
            //压缩当前块
            compress(message_block);
            message_length = 0;
        }
        //填充0直到剩余8字节
        while (message_length < 56) {
            message_block[message_length++] = 0x00;
        }
        //添加消息总长度
        for (int i = 0; i < 8; i++) {
            message_block[56 + i] = (total_bits >> (8 * (7 - i))) & 0xFF;
        }
        //压缩最后一个块
        compress(message_block);
        //将结果转换为字节数组
        for (int i = 0; i < 8; i++) {
            result[4 * i] = (digest[i] >> 24) & 0xFF;
            result[4 * i + 1] = (digest[i] >> 16) & 0xFF;
            result[4 * i + 2] = (digest[i] >> 8) & 0xFF;
            result[4 * i + 3] = digest[i] & 0xFF;
        }
        //重置上下文
        reset();
    }
    //计算数据的SM3哈希值
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
    for (size_t i = 0; i < length; i++) {
        hex_str += hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_str += hex_chars[bytes[i] & 0x0F];
    }
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

    //演示如何使用更新接口处理大数据
    std::cout << "演示分块处理:" << std::endl;
    const char* long_data = "这是一个用于测试SM3算法分块处理的长字符串，将分多次调用update方法来处理它。";  //输入
    SM3 sm3;

    //分块处理数据
    size_t len = strlen(long_data);
    size_t chunk_size = 10;
    for (size_t i = 0; i < len; i += chunk_size) {
        size_t process_len = (i + chunk_size > len) ? (len - i) : chunk_size;
        sm3.update((const uint8_t*)&long_data[i], process_len);
    }
    uint8_t result[32];
    sm3.final(result);
    std::cout << "长字符串哈希: " << bytes_to_hex(result, 32) << std::endl;  //输出

    return 0;
}
