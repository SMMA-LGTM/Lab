# coding=utf-8
import cv2
import numpy as np
import random
import os
from argparse import ArgumentParser

ALPHA = 0.1  # 水印强度系数（乘法嵌入时使用较小值）

def build_parser():
    """构建命令行参数解析器"""
    parser = ArgumentParser(description='数字水印嵌入工具')
    parser.add_argument('--image', dest='img', required=False, 
                      default='C:/Users/jmz/Desktop/project2/ori.png',
                      help='原始图像路径（默认：项目目录下ori.png）')
    parser.add_argument('--watermark', dest='wm', required=False,
                      default='C:/Users/jmz/Desktop/project2/watermark.png',
                      help='水印图像路径（默认：项目目录下watermark.png）')
    parser.add_argument('--result', dest='res', required=False,
                      default='C:/Users/jmz/Desktop/project2/watermarked.png',
                      help='输出图像路径（默认：项目目录下watermarked.png）')
    parser.add_argument('--alpha', dest='alpha', default=ALPHA,
                      help='水印强度系数（默认：0.1）')
    return parser

def normalize_image(img):
    """图像归一化处理（将像素值缩放到[0,1]范围）"""
    return img.astype(np.float32) / 255.0

def denormalize_image(img):
    """图像反归一化（将像素值还原到[0,255]范围）"""
    return (img * 255.0).clip(0, 255).astype(np.uint8)

def main():
    """主函数：处理命令行参数并执行水印嵌入"""
    parser = build_parser()
    options = parser.parse_args()
    
    # 验证文件是否存在
    if not os.path.isfile(options.img):
        raise FileNotFoundError(f"原始图像 {options.img} 不存在")
    if not os.path.isfile(options.wm):
        raise FileNotFoundError(f"水印图像 {options.wm} 不存在")
    
    encode(options.img, options.wm, options.res, float(options.alpha))

def encode(img_path, wm_path, res_path, alpha):
    """
    水印嵌入函数
    参数：
        img_path: 原始图像路径
        wm_path: 水印图像路径
        res_path: 结果保存路径
        alpha: 水印强度系数
    """
    # 读取并归一化图像
    img = normalize_image(cv2.imread(img_path))
    watermark = normalize_image(cv2.imread(wm_path))
    
    # 执行二维FFT变换（分别在高度和宽度方向）
    img_f = np.fft.fft2(img, axes=(0, 1))
    img_f_shifted = np.fft.fftshift(img_f)  # 将低频移到中心
    
    # 获取图像尺寸
    height, width, _ = img.shape
    wm_height, wm_width = watermark.shape[0], watermark.shape[1]
    
    # 生成随机位置序列（使用图像尺寸作为随机种子保证可重复性）
    random.seed(height + width)
    x_indices = list(range(height // 2))  # 只使用上半部分频率
    y_indices = list(range(width))
    random.shuffle(x_indices)
    random.shuffle(y_indices)
    
    # 在频域创建水印模板
    watermark_pattern = np.zeros_like(img)
    for i in range(height // 2):
        for j in range(width):
            if x_indices[i] < wm_height and y_indices[j] < wm_width:
                # 对称嵌入（同时修改对称位置）
                val = watermark[x_indices[i], y_indices[j]] * alpha
                watermark_pattern[i, j] = val
                watermark_pattern[height - 1 - i, width - 1 - j] = val
    
    # 幅度域乘法嵌入
    magnitude = np.abs(img_f_shifted)  # 获取幅度谱
    phase = np.angle(img_f_shifted)    # 获取相位谱
    
    # 修改幅度谱嵌入水印
    watermarked_magnitude = magnitude * (1 + watermark_pattern)
    
    # 重建频域复数表示
    watermarked_freq = watermarked_magnitude * np.exp(1j * phase)
    watermarked_freq_shifted = np.fft.ifftshift(watermarked_freq)  # 移回原位置
    
    # 执行逆FFT变换
    watermarked = np.fft.ifft2(watermarked_freq_shifted, axes=(0, 1))
    watermarked = np.real(watermarked)  # 取实部
    
    # 保存结果图像
    cv2.imwrite(res_path, denormalize_image(watermarked), 
               [int(cv2.IMWRITE_JPEG_QUALITY), 100])

if __name__ == '__main__':
    main()
