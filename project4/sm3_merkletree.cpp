#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <stdint.h>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include "SM3.cpp"

//定义哈希值长度
const size_t HASH_SIZE = 32;
//Merkle树节点类型
enum NodeType {
    LEAF_NODE,
    INTERNAL_NODE
};
//Merkle树节点
struct MerkleNode {
    uint8_t hash[HASH_SIZE];
    NodeType type;
    size_t index;  //叶子节点的索引，内部节点为-1
    MerkleNode* left;
    MerkleNode* right;

    MerkleNode() : type(INTERNAL_NODE), index(-1), left(nullptr), right(nullptr) {
        memset(hash, 0, HASH_SIZE);
    }
};
//RFC6962中定义的空哈希
uint8_t EMPTY_HASH[HASH_SIZE] = {
    0x1A, 0xB2, 0x1D, 0x83, 0x55, 0xCF, 0xA1, 0x7F,
    0x8E, 0x61, 0x19, 0x48, 0x31, 0xE8, 0x1A, 0x8F,
    0x79, 0xC2, 0xB6, 0x77, 0x3A, 0x0F, 0xF8, 0xE5,
    0x34, 0xDF, 0xB6, 0x40, 0x6B, 0x7E, 0xDE, 0xE
};
//合并两个哈希值并计算新哈希
void combineHashes(const uint8_t* left, const uint8_t* right, uint8_t* result) {
    uint8_t combined[HASH_SIZE * 2];
    memcpy(combined, left, HASH_SIZE);
    memcpy(combined + HASH_SIZE, right, HASH_SIZE);
    SM3::hash(combined, HASH_SIZE * 2, result);
}
//Merkle树实现
class MerkleTree {
private:
    MerkleNode* root;
    std::vector<MerkleNode*> leaves;
    size_t leafCount;
    std::vector<std::vector<MerkleNode*>> levels;  //存储每一层的节点

    //构建树
    void buildTree() {
        //如果叶子数为0，直接返回
        if (leafCount == 0) {
            root = nullptr;
            return;
        }
        //确保叶子数是2的幂，不是则补充空节点
        size_t required = 1;
        while (required < leafCount) {
            required <<= 1;
        }
        //补充空叶子节点
        for (size_t i = leafCount; i < required; ++i) {
            MerkleNode* emptyLeaf = new MerkleNode();
            emptyLeaf->type = LEAF_NODE;
            emptyLeaf->index = i;
            memcpy(emptyLeaf->hash, EMPTY_HASH, HASH_SIZE);
            leaves.push_back(emptyLeaf);
        }
        leafCount = required;
        //初始化层级
        levels.clear();
        levels.push_back(leaves);
        //逐层构建直到根节点
        while (levels.back().size() > 1) {
            std::vector<MerkleNode*> nextLevel;
            for (size_t i = 0; i < levels.back().size(); i += 2) {
                MerkleNode* left = levels.back()[i];
                MerkleNode* right = (i + 1 < levels.back().size()) ? levels.back()[i + 1] : left;
                MerkleNode* parent = new MerkleNode();
                combineHashes(left->hash, right->hash, parent->hash);
                parent->left = left;
                parent->right = right;
                nextLevel.push_back(parent);
            }
            levels.push_back(nextLevel);
        }
        root = levels.back()[0];
    }
    //递归删除树节点
    void deleteTree(MerkleNode* node) {
        if (node == nullptr) return;
        deleteTree(node->left);
        deleteTree(node->right);
        delete node;
    }
public:
    MerkleTree() : root(nullptr), leafCount(0) {}

    ~MerkleTree() {
        deleteTree(root);
    }
    //从数据列表初始化Merkle树
    void initialize(const std::vector<std::vector<uint8_t>>& dataList) {
        //清除现有树
        deleteTree(root);
        leaves.clear();
        leafCount = dataList.size();
        //创建叶子节点
        for (size_t i = 0; i < dataList.size(); ++i) {
            MerkleNode* leaf = new MerkleNode();
            leaf->type = LEAF_NODE;
            leaf->index = i;
            SM3::hash(dataList[i].data(), dataList[i].size(), leaf->hash);
            leaves.push_back(leaf);
        }
        //构建树
        buildTree();
    }
    //获取根哈希
    void getRootHash(uint8_t* result) {
        if (root == nullptr) {
            memset(result, 0, HASH_SIZE);
            return;
        }
        memcpy(result, root->hash, HASH_SIZE);
    }
    //生成存在性证明
    bool generateInclusionProof(size_t index, std::vector<std::pair<uint8_t*, bool>>& proof) {
        if (index >= leafCount || root == nullptr) {
            return false;
        }
        proof.clear();
        size_t currentIndex = index;
        //从叶子节点向上收集证明
        for (size_t i = 0; i < levels.size() - 1; ++i) {
            bool isLeft = (currentIndex % 2 == 0);
            size_t siblingIndex = isLeft ? currentIndex + 1 : currentIndex - 1;
            //处理边界情况，当节点数为奇数时
            if (siblingIndex >= levels[i].size()) {
                siblingIndex = currentIndex;
            }
            //存储兄弟节点的哈希和当前节点是否为左节点
            uint8_t* siblingHash = new uint8_t[HASH_SIZE];
            memcpy(siblingHash, levels[i][siblingIndex]->hash, HASH_SIZE);
            proof.emplace_back(siblingHash, isLeft);

            currentIndex /= 2;
        }

        return true;
    }
    //验证存在性证明
    bool verifyInclusionProof(const uint8_t* dataHash, size_t index,
        const std::vector<std::pair<uint8_t*, bool>>& proof,
        const uint8_t* rootHash) {
        uint8_t currentHash[HASH_SIZE];
        memcpy(currentHash, dataHash, HASH_SIZE);
        for (const auto& p : proof) {
            uint8_t combinedHash[HASH_SIZE];
            if (p.second) {  //当前节点是左节点
                combineHashes(currentHash, p.first, combinedHash);
            }
            else {  //当前节点是右节点
                combineHashes(p.first, currentHash, combinedHash);
            }
            memcpy(currentHash, combinedHash, HASH_SIZE);
        }
        return memcmp(currentHash, rootHash, HASH_SIZE) == 0;
    }
    //生成不存在性证明
    bool generateExclusionProof(size_t index, std::vector<std::pair<uint8_t*, bool>>& leftProof,
        std::vector<std::pair<uint8_t*, bool>>& rightProof,
        size_t& leftIndex, size_t& rightIndex) {
        if (index >= leafCount || leafCount < 2 || root == nullptr) {
            return false;
        }
        //找到index的前一个和后一个存在的叶子节点
        leftIndex = index - 1;
        while (leftIndex < leafCount && leaves[leftIndex] == nullptr) {
            leftIndex--;
        }
        rightIndex = index + 1;
        while (rightIndex < leafCount && leaves[rightIndex] == nullptr) {
            rightIndex++;
        }
        //处理边界情况
        if (leftIndex >= leafCount && rightIndex >= leafCount) {
            return false;
        }
        //生成左邻居的存在性证明
        if (leftIndex < leafCount) {
            generateInclusionProof(leftIndex, leftProof);
        }
        //生成右邻居的存在性证明
        if (rightIndex < leafCount) {
            generateInclusionProof(rightIndex, rightProof);
        }

        return true;
    }
    //验证不存在性证明
    bool verifyExclusionProof(size_t index,
        const std::vector<std::pair<uint8_t*, bool>>& leftProof,
        const std::vector<std::pair<uint8_t*, bool>>& rightProof,
        size_t leftIndex, size_t rightIndex,
        const uint8_t* leftHash, const uint8_t* rightHash,
        const uint8_t* rootHash) {
        //验证左邻居存在
        bool leftValid = false;
        if (leftIndex < leafCount) {
            leftValid = verifyInclusionProof(leftHash, leftIndex, leftProof, rootHash);
            if (!leftValid || leftIndex >= index) {
                return false;
            }
        }
        //验证右邻居存在
        bool rightValid = false;
        if (rightIndex < leafCount) {
            rightValid = verifyInclusionProof(rightHash, rightIndex, rightProof, rootHash);
            if (!rightValid || rightIndex <= index) {
                return false;
            }
        }
        //确保左右邻居是相邻的
        if (leftIndex < leafCount && rightIndex < leafCount && rightIndex != leftIndex + 1) {
            return false;
        }
        return leftValid || rightValid;
    }
    //获取叶子节点数量
    size_t getLeafCount() const {
        return leafCount;
    }
    //获取叶子节点的哈希
    bool getLeafHash(size_t index, uint8_t* result) {
        if (index >= leafCount) {
            return false;
        }
        memcpy(result, leaves[index]->hash, HASH_SIZE);
        return true;
    }
};
//辅助函数：将字节数组转换为十六进制字符串
std::string bytesToHex(const uint8_t* bytes, size_t length) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}
//测试函数
void testMerkleTree() {
    //生成10万个测试数据
    const size_t LEAF_COUNT = 100000;
    std::vector<std::vector<uint8_t>> testData;
    testData.reserve(LEAF_COUNT);

    std::cout << "生成" << LEAF_COUNT << "个测试数据..." << std::endl;
    for (size_t i = 0; i < LEAF_COUNT; ++i) {
        // 生成简单的测试数据
        std::vector<uint8_t> data(16);
        for (int j = 0; j < 16; ++j) {
            data[j] = static_cast<uint8_t>((i + j) % 256);
        }
        testData.push_back(data);
    }
    //构建Merkle树
    std::cout << "构建Merkle树..." << std::endl;
    MerkleTree mt;
    mt.initialize(testData);

    uint8_t rootHash[HASH_SIZE];
    mt.getRootHash(rootHash);
    std::cout << "Merkle树 root hash: " << bytesToHex(rootHash, HASH_SIZE) << std::endl;
    //存在性证明
    size_t testIndex = 12345;
    std::vector<std::pair<uint8_t*, bool>> inclusionProof;

    std::cout << "测试存在性证明 (索引: " << testIndex << ")..." << std::endl;
    if (mt.generateInclusionProof(testIndex, inclusionProof)) {
        uint8_t leafHash[HASH_SIZE];
        SM3::hash(testData[testIndex].data(), testData[testIndex].size(), leafHash);

        bool valid = mt.verifyInclusionProof(leafHash, testIndex, inclusionProof, rootHash);
        std::cout << "存在性证明验证结果: " << (valid ? "成功" : "失败") << std::endl;
    }
    else {
        std::cout << "生成存在性证明失败" << std::endl;
    }
    for (auto& p : inclusionProof) {
        delete[] p.first;
    }
    //不存在性证明
    size_t nonExistentIndex = LEAF_COUNT / 2 + 1000;  //选择一个不在范围内的索引
    if (nonExistentIndex >= LEAF_COUNT) nonExistentIndex = LEAF_COUNT - 2;

    std::vector<std::pair<uint8_t*, bool>> leftProof, rightProof;
    size_t leftIndex, rightIndex;

    std::cout << "测试不存在性证明 (索引: " << nonExistentIndex << ")..." << std::endl;
    if (mt.generateExclusionProof(nonExistentIndex, leftProof, rightProof, leftIndex, rightIndex)) {
        uint8_t leftHash[HASH_SIZE], rightHash[HASH_SIZE];
        mt.getLeafHash(leftIndex, leftHash);
        mt.getLeafHash(rightIndex, rightHash);

        bool valid = mt.verifyExclusionProof(nonExistentIndex, leftProof, rightProof,
            leftIndex, rightIndex, leftHash, rightHash, rootHash);
        std::cout << "不存在性证明验证结果: " << (valid ? "成功" : "失败") << std::endl;
    }
    else {
        std::cout << "生成不存在性证明失败" << std::endl;
    }

    for (auto& p : leftProof) {
        delete[] p.first;
    }
    for (auto& p : rightProof) {
        delete[] p.first;
    }
}
int main() {
    testMerkleTree();
    return 0;
}