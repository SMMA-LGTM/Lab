# coding=utf-8
import cv2
import numpy as np
import random
import os
from argparse import ArgumentParser

ALPHA = 0.1  # 必须与嵌入时使用的参数一致

def build_parser():
    """构建命令行参数解析器"""
    parser = ArgumentParser(description='数字水印提取工具')
    parser.add_argument('--original', dest='ori', required=False,
                      default='C:/Users/jmz/Desktop/project2/ori.png',
                      help='原始图像路径（默认：项目目录下ori.png）')
    parser.add_argument('--image', dest='img', required=False,
                      default='C:/Users/jmz/Desktop/project2/watermarked.png',
                      help='含水印图像路径（默认：项目目录下watermarked.png）')
    parser.add_argument('--result', dest='res', required=False,
                      default='C:/Users/jmz/Desktop/project2/extracted_wm.png',
                      help='提取的水印保存路径（默认：项目目录下extracted_wm.png）')
    parser.add_argument('--alpha', dest='alpha', default=ALPHA,
                      help='水印强度系数')
    return parser

def normalize_image(img):
    """图像归一化处理（将像素值缩放到[0,1]范围）"""
    return img.astype(np.float32) / 255.0

def denormalize_image(img):
    """图像反归一化（将像素值还原到[0,255]范围）"""
    return (img * 255.0).clip(0, 255).astype(np.uint8)

def main():
    """主函数：处理命令行参数并执行水印提取"""
    parser = build_parser()
    options = parser.parse_args()
    
    # 验证文件是否存在
    if not os.path.isfile(options.ori):
        raise FileNotFoundError(f"原始图像 {options.ori} 不存在")
    if not os.path.isfile(options.img):
        raise FileNotFoundError(f"含水印图像 {options.img} 不存在")
    
    decode(options.ori, options.img, options.res, float(options.alpha))

def decode(ori_path, img_path, res_path, alpha):
    """
    水印提取函数
    参数：
        ori_path: 原始图像路径
        img_path: 含水印图像路径
        res_path: 提取结果保存路径
        alpha: 水印强度系数
    """
    # 读取并归一化图像
    ori = normalize_image(cv2.imread(ori_path))
    img = normalize_image(cv2.imread(img_path))
    
    # 执行二维FFT变换
    ori_f = np.fft.fft2(ori, axes=(0, 1))
    ori_f_shifted = np.fft.fftshift(ori_f)
    img_f = np.fft.fft2(img, axes=(0, 1))
    img_f_shifted = np.fft.fftshift(img_f)
    
    # 计算幅度谱差异
    ori_magnitude = np.abs(ori_f_shifted)
    img_magnitude = np.abs(img_f_shifted)
    
    # 提取水印模式（基于乘法嵌入的逆运算）
    watermark_pattern = (img_magnitude - ori_magnitude) / (ori_magnitude * alpha)
    
    height, width = ori.shape[0], ori.shape[1]
    res = np.zeros_like(watermark_pattern)
    
    # 使用相同的随机序列重建水印
    random.seed(height + width)  # 必须与嵌入时相同的种子
    x_indices = list(range(height // 2))
    y_indices = list(range(width))
    random.shuffle(x_indices)
    random.shuffle(y_indices)
    
    # 按照嵌入时的随机位置恢复水印
    for i in range(height // 2):
        for j in range(width):
            if x_indices[i] < height and y_indices[j] < width:
                res[x_indices[i], y_indices[j]] = watermark_pattern[i, j]
    
    # 后处理并保存提取的水印
    extracted_wm = denormalize_image(res.clip(0, 1))  # 限制范围并转换到[0,255]
    cv2.imwrite(res_path, extracted_wm, 
               [int(cv2.IMWRITE_JPEG_QUALITY), 100])

if __name__ == '__main__':
    main()
