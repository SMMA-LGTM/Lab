import cv2
import numpy as np
import os
from skimage.metrics import structural_similarity as ssim
from skimage.metrics import peak_signal_noise_ratio as psnr

def calculate_nc(original, extracted):
    """计算归一化互相关系数（NC），衡量两个图像的相似性"""
    # 转为灰度图并归一化
    original_gray = cv2.cvtColor(original, cv2.COLOR_BGR2GRAY) / 255.0
    extracted_gray = cv2.cvtColor(extracted, cv2.COLOR_BGR2GRAY) / 255.0
    
    # 确保尺寸一致
    if original_gray.shape != extracted_gray.shape:
        extracted_gray = cv2.resize(extracted_gray, (original_gray.shape[1], original_gray.shape[0]))
    
    # 计算均值
    mean_original = np.mean(original_gray)
    mean_extracted = np.mean(extracted_gray)
    
    # 计算分子和分母
    numerator = np.sum((original_gray - mean_original) * (extracted_gray - mean_extracted))
    denominator = np.sqrt(np.sum((original_gray - mean_original) **2) * np.sum((extracted_gray - mean_extracted)** 2))
    
    return numerator / denominator if denominator != 0 else 0

def calculate_metrics(original_watermark, extracted_watermark):
    """计算并返回所有评估指标"""
    # 读取图像
    original = cv2.imread(original_watermark)
    extracted = cv2.imread(extracted_watermark)
    
    if original is None or extracted is None:
        raise FileNotFoundError("原始水印或提取的水印图像不存在")
    
    # 确保尺寸一致
    if original.shape != extracted.shape:
        extracted = cv2.resize(extracted, (original.shape[1], original.shape[0]))
    
    # 计算指标
    nc = calculate_nc(original, extracted)
    ssim_val = ssim(
        cv2.cvtColor(original, cv2.COLOR_BGR2GRAY),
        cv2.cvtColor(extracted, cv2.COLOR_BGR2GRAY),
        data_range=255
    )
    psnr_val = psnr(original, extracted, data_range=255)
    
    return {
        "NC": round(nc, 4),       # 归一化互相关系数 
        "SSIM": round(ssim_val, 4), # 结构相似性 
        "PSNR": round(psnr_val, 2)  # 峰值信噪比
        }

def evaluate_robustness(original_watermark, test_dir):
    """评估所有攻击下的水印提取质量并生成报告"""
    # 获取所有提取的水印文件
    extracted_files = [f for f in os.listdir(test_dir) if f.startswith("extracted_")]
    results = []
    
    print("水印鲁棒性量化评估结果：")
    print("攻击类型 | NC值 | SSIM值 | PSNR值(dB)")
    print("-" * 40)
    
    for file in extracted_files:
        # 提取攻击类型
        attack_type = file[len("extracted_"):-4]  # 去除前缀和.png后缀
        extracted_path = os.path.join(test_dir, file)
        
        # 计算指标
        metrics = calculate_metrics(original_watermark, extracted_path)
        
        # 保存结果
        results.append({
            "attack": attack_type,
            "nc": metrics["NC"],
            "ssim": metrics["SSIM"],
            "psnr": metrics["PSNR"]
        })
        
        # 打印结果
        print(f"{attack_type:10} | {metrics['NC']:6} | {metrics['SSIM']:7} | {metrics['PSNR']:10}")
    
    return results

def save_results_to_csv(results, output_file="robustness_metrics.csv"):
    """将结果保存为CSV文件"""
    import csv
    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["attack", "nc", "ssim", "psnr"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n结果已保存至 {output_file}")

if __name__ == "__main__":
    # 配置路径
    ORIGINAL_WATERMARK = "watermark.png"  # 原始水印图像
    TEST_DIR = "robustness_tests"         # 测试结果目录
    
    # 评估并保存结果
    results = evaluate_robustness(ORIGINAL_WATERMARK, TEST_DIR)
    save_results_to_csv(results)
