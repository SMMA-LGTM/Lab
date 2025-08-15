# project 5： a）SM2 的软件实现优化。 b）20250713-温-sm2-public.pdf 中提到的关于签名算法的误用 分别基于做poc验证，给出推导文档以及验证代码。 c）伪造中本聪的数字签名。
SM2是中国国家密码管理局发布的一种基于椭圆曲线密码（ECC）的公钥密码算法标准，采用256位素数域上的椭圆曲线，安全性相当于3072位RSA。
# 椭圆曲线基础：
### 基本方程
- **一般形式**:  
  `y² = x³ + ax + b`（定义在有限域上，如素数域 𝔽ₚ）
- **约束条件**:  
  `4a³ + 27b² ≠ 0`（确保曲线无奇点，光滑性）
- **SM2的曲线参数**:
  - 素数 `p`、系数 `a`、`b`、基点 `G`、阶 `n` 等均由国家密码管理局标准化

### 有限域上的运算
- 所有坐标和运算均在有限域 𝔽ₚ 上进行（模 `p` 运算）

## 椭圆曲线上的群运算

### 点加法（P + Q）
1. 若 `P ≠ Q`: 连接P和Q的直线与曲线交于第三点-R，取对称点R
2. 若 `P = Q`（倍点运算）: 取曲线在P点的切线的交点
3. **公式**（素数域 𝔽ₚ）:
   - 斜率 λ = 
     ```
     (y_Q - y_P)/(x_Q - x_P) mod p    if P ≠ Q
     (3x_P² + a)/(2y_P) mod p         if P = Q
     ```
   - 结果点 R = (x_R, y_R):
     ```
     x_R = λ² - x_P - x_Q mod p
     y_R = λ(x_P - x_R) - y_P mod p
     ```

### 单位元和逆元
- **单位元**: 无穷远点 𝒪（满足 P + 𝒪 = P）
- **逆元**: 点 (x, y) 的逆元为 (x, -y mod p)

## 椭圆曲线离散对数问题（ECDLP）
- **问题描述**: 已知基点 G 和点 P = k·G，求整数 k（私钥）
- **SM2的安全性基础**: ECDLP在经典计算机上无有效解法（量子计算机除外）
- **对比**: 256位ECC密钥的安全性 ≈ 3072位RSA

## SM2的椭圆曲线参数：
| 参数 | 值（16进制） |
|------|-------------|
| 素数 p | FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF |
| 系数 a | FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC |
| 系数 b | 28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93 |
| 阶 n | FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123 |

## 密钥对生成
- **私钥 d**: 随机数 d ∈ [1, n-1]
- **公钥 P**: 通过标量乘法计算 P = d·G

