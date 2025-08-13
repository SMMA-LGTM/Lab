import cv2
import numpy as np
import os
from encode import encode
from decode import decode

# 测试参数配置
ORIGINAL_IMAGE = "ori.png"
WATERMARK_IMAGE = "watermark.png"
WATERMARKED_IMAGE = "watermarked.png"
TEST_OUTPUT_DIR = "robustness_tests"

# 确保测试输出目录存在
os.makedirs(TEST_OUTPUT_DIR, exist_ok=True)

def apply_attack(image, attack_type):
    """应用不同类型的攻击，确保输出尺寸与输入一致"""
    attacked = image.copy()
    original_shape = image.shape  # 保存原始尺寸
    
    if attack_type == "flip_horizontal":
        # 水平翻转
        attacked = cv2.flip(image, 1)
    elif attack_type == "flip_vertical":
        # 垂直翻转
        attacked = cv2.flip(image, 0)
    elif attack_type == "rotate_90":
        # 旋转90度并恢复原始尺寸
        attacked = cv2.rotate(image, cv2.ROTATE_90_CLOCKWISE)
        attacked = cv2.resize(attacked, (original_shape[1], original_shape[0]))
    elif attack_type == "rotate_180":
        # 旋转180度
        attacked = cv2.rotate(image, cv2.ROTATE_180)
    elif attack_type == "translate":
        # 平移（向右下移动50像素）
        rows, cols = image.shape[:2]
        M = np.float32([[1, 0, 50], [0, 1, 50]])
        attacked = cv2.warpAffine(image, M, (cols, rows))
    elif attack_type == "crop":
        # 中心截取（保留70%区域）
        rows, cols = image.shape[:2]
        start_row, start_col = int(rows*0.15), int(cols*0.15)
        end_row, end_col = int(rows*0.85), int(cols*0.85)
        attacked = image[start_row:end_row, start_col:end_col]
        # 恢复原始尺寸
        attacked = cv2.resize(attacked, (cols, rows))
    elif attack_type == "contrast_up":
        # 提高对比度（1.5倍）
        attacked = cv2.convertScaleAbs(image, alpha=1.5, beta=0)
    elif attack_type == "contrast_down":
        # 降低对比度（0.5倍）
        attacked = cv2.convertScaleAbs(image, alpha=0.5, beta=0)
    elif attack_type == "noise":
        # 添加高斯噪声
        mean = 0
        var = 0.001
        sigma = var ** 0.5
        gauss = np.random.normal(mean, sigma, image.shape)
        attacked = image + gauss * 255
        attacked = np.clip(attacked, 0, 255).astype(np.uint8)
    elif attack_type == "jpeg_compress":
        # JPEG压缩攻击
        encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 50]  # 50%质量
        result, encimg = cv2.imencode('.jpg', image, encode_param)
        attacked = cv2.imdecode(encimg, 1)
    
    # 确保所有攻击后的图像尺寸与原始一致
    if attacked.shape != original_shape:
        attacked = cv2.resize(attacked, (original_shape[1], original_shape[0]))
    
    return attacked

def test_robustness(alpha=0.1):
    """测试水印算法的鲁棒性"""
    # 首先嵌入水印
    encode(ORIGINAL_IMAGE, WATERMARK_IMAGE, WATERMARKED_IMAGE, alpha)
    
    # 读取原始水印图像和含水印图像
    watermarked_img = cv2.imread(WATERMARKED_IMAGE)
    if watermarked_img is None:
        raise FileNotFoundError(f"无法读取含水印图像: {WATERMARKED_IMAGE}")
    
    # 获取原始图像尺寸用于校验
    original_img = cv2.imread(ORIGINAL_IMAGE)
    original_shape = original_img.shape if original_img is not None else watermarked_img.shape
    
    # 定义要测试的攻击类型
    attacks = [
        "flip_horizontal", "flip_vertical", 
        "rotate_90", "rotate_180",
        "translate", "crop",
        "contrast_up", "contrast_down",
        "noise", "jpeg_compress"
    ]
    
    # 对每种攻击进行测试
    for attack in attacks:
        print(f"测试攻击: {attack}")
        
        # 应用攻击
        attacked_img = apply_attack(watermarked_img, attack)
        attacked_path = os.path.join(TEST_OUTPUT_DIR, f"attacked_{attack}.png")
        cv2.imwrite(attacked_path, attacked_img)
        
        # 检查攻击后图像尺寸是否与原始一致
        if attacked_img.shape != original_shape:
            print(f"  警告: 攻击后图像尺寸与原始不一致，已自动调整")
            attacked_img = cv2.resize(attacked_img, (original_shape[1], original_shape[0]))
            cv2.imwrite(attacked_path, attacked_img)
        
        # 提取水印
        extracted_path = os.path.join(TEST_OUTPUT_DIR, f"extracted_{attack}.png")
        decode(ORIGINAL_IMAGE, attacked_path, extracted_path, alpha)
        
        print(f"  攻击后图像保存至: {attacked_path}")
        print(f"  提取的水印保存至: {extracted_path}")

if __name__ == "__main__":
    # 可以调整alpha值进行测试
    test_robustness(alpha=0.1)
    print("鲁棒性测试完成，结果保存在 robustness_tests 目录下")
