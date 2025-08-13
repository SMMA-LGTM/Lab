# **Project 2:** 编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等。

在网上找到一份blind-watermark开源项目[linyacool/blind-watermark](https://github.com/linyacool/blind-watermark/tree/master)，以他为基准二次开发


原嵌入代码encode.py的工作原理：

1.将原始图像使用傅里叶变换转换到频域；

2.将水印信息以随机分布的方式嵌入到频域中；

3.通过傅里叶逆变换将修改后的频域数据转换回空域，得到带有水印的图像；


原提取代码decode.py的工作原理：

1.分别读取原始图像和含水印图像，对这两幅图像进行二维傅里叶变换，将它们从空域转换到频域。

2.水印提取：在频域中，利用原始图像与含水印图像的频域差异，通过公式 (原始图像频域 - 含水印图像频域) / alpha 计算得到水印的频域信息将计算结果转换为实数（去除傅里叶变换可能产生的虚部）。

3.水印恢复：使用与嵌入时相同的随机种子（图像尺寸）和打乱方式，重建随机索引，根据这些索引，将频域中提取到的水印信息恢复到正确位置。


尝试运行原代码，没有得到预期的结果，水印提取的图片根本看不清是什么。


**对两种代码进行鲁棒性测试，改进优化：**

----------------------------------------------------------------------

1. 将加法嵌入改为基于幅度谱的乘法嵌入，提高鲁棒性：



magnitude = np.abs(img_f_shifted) _\# 获取幅度谱_

phase = np.angle(img_f_shifted) _\# 获取相位谱_

_\# 在幅度谱上做乘法嵌入（1+α\*W保证非负）_

watermarked_magnitude = magnitude \* (1 + alpha \* watermark_pattern) _\# 关键改进点_

_\# 重建复数频域_

watermarked_freq = watermarked_magnitude \* np.exp(1j \* phase) _\# 保持相位不变_


乘法嵌入通过修改幅度谱而非直接修改复数，能更好地抵抗JPEG压缩等攻击。

----------------------------------------------------------------------------------

2. 增加了完整的频域中心化处理（fftshift/ifftshift）

img_f = np.fft.fft2(img, axes=(0, 1))

img_f_shifted = np.fft.fftshift(img_f) _\# 低频移至中心_

_\# 在中心化频域嵌入水印_

watermarked_freq_shifted = img_f_shifted \* (1 + alpha \* watermark_pattern)

_\# 逆中心化后逆变换_

watermarked_freq = np.fft.ifftshift(watermarked_freq_shifted)

watermarked = np.fft.ifft2(watermarked_freq, axes=(0, 1))

****可视化优势****：中心化后，低频集中在频谱中心，水印可精准嵌入中频区域，避免修改极低频导致可见失真。

--------------------------------------------------------------------------------

3.使用归一化处理保证数值稳定性

def normalize_image(img):

return img.astype(np.float32) / 255.0 _\# 归一化到\[0,1\]_

img = normalize_image(cv2.imread(img_path)) _\# 输入范围稳定_

watermark = normalize_image(cv2.imread(wm_path))

_\# 处理完成后反归一化_

def denormalize_image(img):

return (img \* 255).clip(0, 255).astype(np.uint8)

cv2.imwrite(res_path, denormalize_image(watermarked))

归一化后所有运算在\[0,1\]范围内进行，避免溢出（如FFT后实部可能超出255）。

未归一化时，逆变换后需手动裁剪值域（np.clip），而归一化后自动满足约束条件。

----------------------------------------------------------------------------

4.增加错误处理机制

----------------------------------------------------------------------

5.由于个人习惯，将代码改为了使用python的IDLE上运行

----------------------------------------------------------------

**同样使用原始代码的测试图片，生成结果：**

水印嵌入

<img width="960" height="600" alt="watermarked" src="https://github.com/user-attachments/assets/16e5286c-c5bb-48dd-bb1f-ec34b6442671" />

水印提取

<img width="960" height="600" alt="extracted_wm" src="https://github.com/user-attachments/assets/6583f3a2-3a6e-428c-ab46-d5cde8b4d386" />


**鲁棒性测试：**

robustness.py和robustness_metrics.py分别是鲁棒性图片测试和数据结果测试。

分别测试了水平翻转，垂直翻转，旋转90度，旋转180度，平移，中心截取，提高对比度，降低对比度，添加高斯噪声，JPEG压缩攻击几种鲁棒性。

从测试结果综合来看，该算法的鲁棒性较差。在结构相似性和图像质量方面表现不佳，不同攻击的影响差异较大，虽然在nc指标上相对稳定，但整体而言在面对各种攻击时的表现有待提高。

测试结果分别是robustness_tests和robustness_metrics.csv。
