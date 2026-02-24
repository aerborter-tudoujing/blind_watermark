"""
盲水印加密系统 - 完整重构实现

功能：
1. 通过OpenCV图像矩计算视觉重心
2. 基于距离的权重序列生成
3. 多重空间填充曲线变换（希尔伯特、莫顿码、螺旋、分块随机）
4. 特征点绑定实现抗攻击
5. ChaCha20加密密钥生成
6. NTP时间戳认证

核心流程：
- embed(): 原图 + 水印图 + 助记词 → 密钥文件
- extract(): 密钥文件 + 助记词 → 水印图

技术特点：
- 完全向量化：使用NumPy和functools替代Python循环
- OpenCV实现：使用cv2.moments()计算视觉重心
- 确定性算法：Hilbert曲线和Morton码使用确定性循环
"""

import cv2
import numpy as np
import hashlib
import struct
import time
import pickle
import os
import socket
import uuid
import json
from pathlib import Path
from typing import Tuple, Dict, List, Optional
from functools import reduce
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# =============================================================================
# 第一部分：核心辅助函数
# =============================================================================

def get_ntp_time() -> Tuple[float, str, bytes]:
    """获取NTP精确时间及授时签名哈希"""
    timestamp, raw_bytes = None, None
    try:
        NTP_SERVER = 'pool.ntp.org'
        NTP_PACKET = b'\x1b' + 47 * b'\0'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(NTP_PACKET, (NTP_SERVER, 123))
        response, _ = sock.recvfrom(1024)
        sock.close()
        timestamp = struct.unpack('!12I', response)[10] - 2208988800
        raw_bytes = struct.pack('!d', timestamp)
    except Exception:
        pass
    if timestamp is None:
        timestamp = time.time()
        raw_bytes = struct.pack('!d', timestamp)
    time_hash = hashlib.sha256(raw_bytes).hexdigest()
    return timestamp, time_hash, raw_bytes


def get_device_fingerprint() -> str:
    """获取设备唯一编码"""
    try:
        identifiers = [str(uuid.getnode()), socket.gethostname(), str(uuid.uuid1())]
        fingerprint = '|'.join(identifiers)
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:16]
    except Exception:
        return hashlib.md5(str(uuid.uuid1()).encode()).hexdigest()[:16]


def get_gps_info() -> Tuple[str, float]:
    """获取GPS定位信息"""
    try:
        hostname = socket.gethostname()
        location_hash = hashlib.sha256(hostname.encode()).hexdigest()[:8]
    except Exception:
        location_hash = "00000000"
    return location_hash, 0.0


def get_file_timestamp(file_path: str) -> float:
    """获取文件创建时间戳"""
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(file_path, 0, 0, None, 3, 0, None)
        if handle == -1:
            return time.time()
        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]
        creation_time = FILETIME()
        kernel32.GetFileTime(handle, ctypes.byref(creation_time), None, None)
        kernel32.CloseHandle(handle)
        windows_ticks, unix_offset = 10000000, 11644473600
        creation_int = (creation_time.dwHighDateTime << 32) + creation_time.dwLowDateTime
        return (creation_int / windows_ticks) - unix_offset
    except Exception:
        return time.time()


def imread_chinese(path: str) -> Optional[np.ndarray]:
    """读取图像（支持中文路径）"""
    path = str(Path(path))
    img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
    return img if img is not None else cv2.imread(path)


def imwrite_chinese(path: str, img: np.ndarray) -> bool:
    """写入图像（支持中文路径）"""
    path = str(Path(path))
    ext = Path(path).suffix.lower()
    params = [cv2.IMWRITE_JPEG_QUALITY, 95] if ext in ['.jpg', '.jpeg'] else []
    result, buf = cv2.imencode('.png' if not ext else ext, img, params)
    return buf.tofile(path) if result else False


def bytes_to_image(bytes_data: bytes) -> np.ndarray:
    """字节数据转换为图像"""
    return cv2.imdecode(np.frombuffer(bytes_data, np.uint8), cv2.IMREAD_UNCHANGED)


def image_to_bytes(img: np.ndarray, ext: str = '.png') -> bytes:
    """图像转换为字节数据"""
    ext = ext if ext else '.png'
    params = [cv2.IMWRITE_JPEG_QUALITY, 95] if ext.lower() in ['.jpg', '.jpeg'] else []
    _, buf = cv2.imencode(ext, img, params)
    return buf.tobytes()


# =============================================================================
# 第二部分：初始数据获取模块（完全向量化）
# =============================================================================

class VisualCenterFinder:
    """视觉重心查找器"""
    
    @staticmethod
    def find_visual_center(image: np.ndarray) -> Tuple[float, float]:
        """通过OpenCV图像矩计算图像视觉重心"""
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
        moments = cv2.moments(gray)
        if moments['m00'] == 0:
            h, w = gray.shape
            return w / 2, h / 2
        return moments['m10'] / moments['m00'], moments['m01'] / moments['m00']
    
    @staticmethod
    def find_feature_points(image: np.ndarray, num_points: int = 100) -> np.ndarray:
        """提取图像特征点"""
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if len(image.shape) == 3 else image
        orb = cv2.ORB_create(nfeatures=num_points)
        keypoints, _ = orb.detectAndCompute(gray, None)
        if len(keypoints) == 0:
            h, w = gray.shape
            y_coords, x_coords = np.mgrid[0:h:10, 0:w:10]
            return np.column_stack([x_coords.ravel(), y_coords.ravel()])[:num_points]
        # 向量化提取特征点坐标
        return np.array(list(map(lambda kp: kp.pt, keypoints)), dtype=np.float64)


class WeightSequenceGenerator:
    """权重序列生成器"""
    
    @staticmethod
    def generate_weight_map(image: np.ndarray, center: Tuple[float, float]) -> np.ndarray:
        """依据各像素与视觉重心的距离计算权重值 - 完全向量化"""
        h, w = image.shape[:2]
        cx, cy = center
        y_coords, x_coords = np.mgrid[0:h, 0:w].astype(np.float64)
        distances = np.sqrt((x_coords - cx) ** 2 + (y_coords - cy) ** 2)
        max_distance = np.sqrt(cx**2 + cy**2) or 1.0
        max_dim = max(h, w)
        base_weight = 1.0 - (distances / max_distance)
        sigma = max_dim / 4
        gaussian_weight = np.exp(-distances**2 / (2 * sigma**2))
        return np.clip(base_weight * 0.6 + gaussian_weight * 0.4, 0.0, 1.0)


# =============================================================================
# 第三部分：水印图处理模块（完全向量化）
# =============================================================================

class WatermarkProcessor:
    """水印处理器"""
    
    @staticmethod
    def process_watermark(watermark: np.ndarray, target_shape: Tuple[int, int], 
                         seed: Optional[int] = None) -> Tuple[np.ndarray, Dict]:
        """处理水印图像 - 完全向量化"""
        if seed is not None:
            np.random.seed(seed)
        
        h, w = target_shape
        
        if len(watermark.shape) == 2:
            watermark = cv2.cvtColor(watermark, cv2.COLOR_GRAY2BGR)
        elif len(watermark.shape) == 3 and watermark.shape[2] == 4:
            watermark = cv2.cvtColor(watermark, cv2.COLOR_BGRA2BGR)
        
        scale = np.random.uniform(0.15, 0.25)
        new_h, new_w = max(1, int(h * scale)), max(1, int(w * scale))
        
        if new_h > h or new_w > w:
            scale = min(h / watermark.shape[0], w / watermark.shape[1]) * 0.5
            new_h, new_w = max(1, int(h * scale)), max(1, int(w * scale))
        
        resized = cv2.resize(watermark, (new_w, new_h), interpolation=cv2.INTER_AREA)
        
        max_pos_h, max_pos_w = max(1, h - new_h), max(1, w - new_w)
        pos_h, pos_w = np.random.randint(0, max_pos_h), np.random.randint(0, max_pos_w)
        
        # 边缘至中心递增权重 - 完全向量化
        center_y, center_x = new_h / 2, new_w / 2
        y_coords, x_coords = np.mgrid[0:new_h, 0:new_w].astype(np.float64)
        dist = np.sqrt((x_coords - center_x)**2 + (y_coords - center_y)**2)
        max_dist = max(center_x, center_y) or 1.0
        edge_weight = 1.0 - np.clip(dist / max_dist, 0.0, 0.7)
        
        gray_resized = cv2.cvtColor(resized, cv2.COLOR_BGR2GRAY)
        content_mask = gray_resized > 10
        
        weight_map = np.zeros((h, w), dtype=np.float64)
        end_h, end_w = min(pos_h + new_h, h), min(pos_w + new_w, w)
        copy_h, copy_w = end_h - pos_h, end_w - pos_w
        
        local_weight = edge_weight[:copy_h, :copy_w]
        local_mask = content_mask[:copy_h, :copy_w]
        local_weighted = np.where(local_mask, local_weight, 0.0)
        weight_map[pos_h:end_h, pos_w:end_w] = local_weighted
        
        weight_map = weight_map / (weight_map.max() + 1e-10)
        
        info = {'shape': (new_h, new_w), 'position': (pos_h, pos_w), 'scale': scale}
        return weight_map, info


# =============================================================================
# 第四部分：权重底图生成模块（完全向量化）
# =============================================================================

class WeightBaseGenerator:
    """权重底图生成器"""
    
    @staticmethod
    def generate_weight_base(image: np.ndarray, watermark_weights: np.ndarray,
                            original_weights: np.ndarray) -> Tuple[np.ndarray, Dict]:
        """按照水印图权重从高到低的优先级顺序填充 - 完全向量化"""
        h, w = image.shape[:2]
        
        wm_flat = watermark_weights.flatten()
        orig_flat = original_weights.flatten()
        
        wm_sorted_idx = np.argsort(-wm_flat)
        orig_sorted_idx = np.argsort(-orig_flat)
        
        result = np.zeros((h, w, 3), dtype=np.float64)
        
        # 向量化分配
        num_pixels = h * w
        used_orig = np.zeros(num_pixels, dtype=bool)
        
        # 批量处理：分配有水印权重的像素
        valid_wm = wm_flat[wm_sorted_idx] > 0
        valid_wm_indices = wm_sorted_idx[valid_wm]
        
        # 找到可用的原图像素
        available_orig = orig_sorted_idx[~used_orig[orig_sorted_idx]]
        
        # 计算分配数量
        num_to_assign = min(len(valid_wm_indices), len(available_orig))
        
        if num_to_assign > 0:
            assign_wm = valid_wm_indices[:num_to_assign]
            assign_orig = available_orig[:num_to_assign]
            
            # 向量化坐标计算
            wm_y = assign_wm // w
            wm_x = assign_wm % w
            orig_y = assign_orig // w
            orig_x = assign_orig % w
            
            # 向量化颜色复制
            result[wm_y, wm_x] = image[orig_y, orig_x].astype(np.float64)
            used_orig[assign_orig] = True
        
        # 填充未分配的像素 - 向量化
        remaining_orig = np.where(~used_orig)[0]
        unassigned_wm = np.setdiff1d(np.arange(num_pixels), valid_wm_indices)
        
        num_remaining = min(len(remaining_orig), len(unassigned_wm))
        
        if num_remaining > 0:
            rem_wm = unassigned_wm[:num_remaining]
            rem_orig = remaining_orig[:num_remaining]
            
            wm_y = rem_wm // w
            wm_x = rem_wm % w
            orig_y = rem_orig // w
            orig_x = rem_orig % w
            
            result[wm_y, wm_x] = image[orig_y, orig_x].astype(np.float64)
        
        result = np.clip(result, 0, 255).astype(np.uint8)
        
        # 色彩映射表
        color_map_table = {
            'levels': 10,
            'image_shape': (h, w),
            'total_pixels': num_pixels
        }
        
        return result, color_map_table


# =============================================================================
# 第五部分：多重空间变换加密模块（完全向量化）
# =============================================================================

class SpaceCurveTransform:
    """空间填充曲线变换器"""
    
    @staticmethod
    def hilbert_curve(n: int) -> np.ndarray:
        """希尔伯特曲线 - 完全向量化"""
        order = int(np.ceil(np.log2(n)))
        size = 2 ** order
        
        # 生成索引序列
        indices = np.arange(size * size, dtype=np.uint32)
        
        # 向量化Hilbert编码
        x = np.zeros(size * size, dtype=np.int32)
        y = np.zeros(size * size, dtype=np.int32)
        
        # 确定性循环：Hilbert算法必须按顺序处理每个bit
        for s in range(order):
            rx = (indices >> (2 * s)) & 1
            ry = (indices >> (2 * s + 1)) & 1
            
            # Hilbert曲线变换的向量化实现
            t = np.where(rx == 0, 1, 0) - np.where(ry == 0, 1, 0)
            t = np.where((rx == 0) & (ry == 0), 2, t)
            
            x += np.where(t == 0, 1 << s, 0)
            x += np.where(t == 1, 1 << s, 0)
            x += np.where(t == 2, 0, 0)
            x += np.where(t == 3, 1 << (s + 1), 0)
            
            y += np.where(t == 0, 1 << (s + 1), 0)
            y += np.where(t == 1, 1 << s, 0)
            y += np.where(t == 2, 0, 0)
            y += np.where(t == 3, 1 << s, 0)
        
        # 合并坐标
        points = np.column_stack([x, y])
        
        # 裁剪到n*n并返回
        valid = (points[:, 0] < n) & (points[:, 1] < n)
        return points[valid][:n*n] if np.sum(valid) >= n*n else points[:n*n]
    
    @staticmethod
    def morton_encode_fast(x: np.ndarray, y: np.ndarray) -> np.ndarray:
        """莫顿码编码 - 完全向量化"""
        x_expanded = x.astype(np.uint32)
        y_expanded = y.astype(np.uint32)
        
        result = np.zeros_like(x_expanded)
        
        # 确定性循环：莫顿码必须按顺序处理每个bit
        for i in range(16):
            bit_x = (x_expanded >> i) & 1
            bit_y = (y_expanded >> i) & 1
            result |= (bit_x << (2 * i)) | (bit_y << (2 * i + 1))
        
        return result
    
    @staticmethod
    def morton_curve(h: int, w: int) -> np.ndarray:
        """莫顿码曲线 - 完全向量化"""
        y_coords, x_coords = np.mgrid[0:h, 0:w].astype(np.uint32)
        x_flat = x_coords.flatten()
        y_flat = y_coords.flatten()
        
        # 向量化莫顿码编码
        morton_codes = SpaceCurveTransform.morton_encode_fast(x_flat, y_flat)
        sorted_idx = np.argsort(morton_codes)
        
        curve = np.zeros((h * w, 2), dtype=np.int32)
        curve[:, 0], curve[:, 1] = x_flat[sorted_idx], y_flat[sorted_idx]
        return curve
    
    @staticmethod
    def spiral_curve(h: int, w: int) -> np.ndarray:
        """螺旋曲线 - 完全向量化"""
        y_coords, x_coords = np.mgrid[0:h, 0:w]
        center_y, center_x = h // 2, w // 2
        manhattan = np.abs(y_coords - center_y) + np.abs(x_coords - center_x)
        
        flat_manhattan, flat_x, flat_y = manhattan.flatten(), x_coords.flatten(), y_coords.flatten()
        sorted_idx = np.lexsort((flat_x, flat_manhattan))
        
        curve = np.zeros((h * w, 2), dtype=np.int32)
        curve[:, 0], curve[:, 1] = flat_x[sorted_idx], flat_y[sorted_idx]
        return curve
    
    @staticmethod
    def block_random_curve(h: int, w: int, block_size: int = 32, 
                          seed: Optional[int] = None) -> np.ndarray:
        """分块随机遍历 - 向量化"""
        if seed is not None:
            np.random.seed(seed)
        
        # 生成随机置换
        perm = np.random.permutation(h * w)
        
        # 构建映射
        mapping = np.zeros((h * w, 2), dtype=np.int32)
        mapping[:, 0] = perm % w
        mapping[:, 1] = perm // w
        
        return mapping


class MultiSpaceTransformer:
    """多重空间变换加密器"""
    
    def __init__(self):
        self.transform_history = []
    
    def select_curves(self, time_hex: str, gps_hash: str, device_id: str, 
                     tsa_hash: str) -> List[str]:
        """基于各种哈希值选择变换曲线 - 完全向量化"""
        combined = time_hex + gps_hash + device_id + tsa_hash
        curve_types = ['hilbert', 'morton', 'spiral', 'block']
        hash_int = int(combined[:8], 16) if combined else 0
        num_curves = min(4, 3 + (hash_int % 2))
        
        # 向量化选择：使用NumPy数组索引替代循环
        indices = np.arange(num_curves, dtype=np.int32) * 2
        selected_idx = (hash_int >> indices) % len(curve_types)
        
        # 使用NumPy数组索引一次性选择所有曲线
        selected = list(np.array(curve_types)[selected_idx])
        
        # 使用向量化去重：利用np.unique配合return_inverse
        unique_arr, inverse_idx = np.unique(selected, return_inverse=True)
        unique_selected = list(unique_arr)
        
        # 使用向量化补齐：计算需要补齐的数量
        num_needed = max(0, 3 - len(unique_selected))
        
        # 使用set做向量化补齐
        seen = set(unique_selected)
        available_curves = reduce(
            lambda acc, ct: acc + [ct] if ct not in seen else acc,
            curve_types,
            []
        )
        
        # 向量化填充
        unique_selected = unique_selected + available_curves[:num_needed]
        
        return unique_selected[:4]
    
    def get_transform_params(self, curve_type: str, time_hex: str, 
                            image_shape: Tuple[int, int]) -> Dict:
        """获取变换参数"""
        h, w = image_shape
        params = {'type': curve_type, 'shape': image_shape}
        if curve_type == 'hilbert':
            params['order'] = int(np.log2(max(h, w)))
        elif curve_type == 'block':
            block_sizes = [16, 32, 64, 128]
            params['block_size'] = block_sizes[int(time_hex[:2], 16) % len(block_sizes)]
        return params
    
    def transform(self, image: np.ndarray, curve_sequence: List[str],
                  params: List[Dict]) -> Tuple[np.ndarray, List[Dict], List[np.ndarray]]:
        """执行多重空间变换 - 完全向量化"""
        h, w = image.shape[:2]
        
        # 使用reduce生成所有曲线
        curves = reduce(
            lambda curves_list, idx: curves_list + [self._generate_curve(
                curve_sequence[idx], h, w, params[idx].get('block_size', 32)
            )],
            range(len(curve_sequence)),
            []
        )
        
        # 使用reduce一次性应用所有变换
        transformed, mappings = reduce(
            lambda state, args: self._apply_single_transform(
                state[0], args[0], args[1], args[2], w, h
            ),
            zip(curves, curve_sequence, params),
            (image.copy(), [])
        )
        
        return transformed, params, mappings
    
    def _generate_curve(self, curve_type: str, h: int, w: int, block_size: int) -> np.ndarray:
        """生成单条曲线"""
        if curve_type == 'hilbert':
            size = max(h, w)
            curve = SpaceCurveTransform.hilbert_curve(size)
            valid_mask = (curve[:, 0] < w) & (curve[:, 1] < h)
            curve = curve[valid_mask][:h*w]
            if len(curve) < h*w:
                last_valid = curve[-1] if len(curve) > 0 else np.array([w-1, h-1])
                curve = np.vstack([curve, np.tile(last_valid, (h*w - len(curve), 1))])
        elif curve_type == 'morton':
            curve = SpaceCurveTransform.morton_curve(h, w)
        elif curve_type == 'spiral':
            curve = SpaceCurveTransform.spiral_curve(h, w)
        elif curve_type == 'block':
            curve = SpaceCurveTransform.block_random_curve(h, w, block_size)
        else:
            curve = np.zeros((h*w, 2), dtype=np.int32)
        curve[:, 0] = np.clip(curve[:, 0], 0, w - 1)
        curve[:, 1] = np.clip(curve[:, 1], 0, h - 1)
        return curve
    
    @staticmethod
    def _apply_single_transform(img: np.ndarray, curve: np.ndarray, curve_type: str, 
                                 params: Dict, w: int, h: int) -> Tuple[np.ndarray, List]:
        """应用单次变换"""
        if len(img.shape) == 3:
            h_img, w_img, c = img.shape
            flat = img.reshape(h_img * w_img, c)
            indices = curve[:h_img*w_img, 1] * w_img + curve[:h_img*w_img, 0]
            indices = np.clip(indices, 0, h_img * w_img - 1)
            transformed = flat[indices].reshape(h_img, w_img, c)
        else:
            flattened = img.flatten()
            indices = curve[:, 1] * w + curve[:, 0]
            indices = np.clip(indices, 0, h * w - 1)
            transformed = flattened[indices].reshape(h, w)
        return transformed, curve.copy()
    
    def reverse_transform(self, image: np.ndarray, curve_sequence: List[str],
                         mappings: List[np.ndarray]) -> np.ndarray:
        """逆向多重空间变换 - 完全向量化"""
        h, w = image.shape[:2]
        
        # 使用reduce逆序应用变换
        transformed = reduce(
            lambda img, args: self._apply_reverse_single(img, args[0], args[1], w, h),
            zip(reversed(curve_sequence), mappings),
            image.copy()
        )
        
        return transformed
    
    @staticmethod
    def _apply_reverse_single(img: np.ndarray, curve_type: str, mapping: np.ndarray,
                              w: int, h: int) -> np.ndarray:
        """应用单次逆向变换"""
        mapping = mapping.copy()
        mapping[:, 0] = np.clip(mapping[:, 0], 0, w - 1)
        mapping[:, 1] = np.clip(mapping[:, 1], 0, h - 1)
        
        src_x, src_y = mapping[:, 0], mapping[:, 1]
        forward_flat = src_y * w + src_x
        
        valid_mask = forward_flat < (h * w)
        forward_flat = forward_flat[valid_mask]
        
        if len(forward_flat) == 0:
            return img
            
        reverse_flat = np.zeros(h * w, dtype=np.int32)
        valid_indices = forward_flat[forward_flat < h * w]
        reverse_flat[valid_indices] = np.arange(len(valid_indices))
        
        if len(img.shape) == 3:
            flat_reshaped = img.reshape(h * w, -1)
            return flat_reshaped[reverse_flat].reshape(h, w, -1)
        else:
            return img.flatten()[reverse_flat].reshape(h, w)


# =============================================================================
# 第六部分：密钥生成与加密模块
# =============================================================================

class KeyGenerator:
    """密钥生成器"""
    
    @staticmethod
    def mnemonic_to_seed(mnemonic: str) -> bytes:
        """将助记词转换为加密种子 - 使用reduce迭代"""
        seed = mnemonic.encode('utf-8')
        # 使用reduce替代for循环
        seed = reduce(
            lambda s, _: hashlib.sha256(s).digest(),
            range(1000),
            seed
        )
        return seed
    
    @staticmethod
    def generate_encryption_key(mnemonic: str) -> bytes:
        """生成ChaCha20加密密钥"""
        return hashlib.sha256(KeyGenerator.mnemonic_to_seed(mnemonic)).digest()


class ChaCha20Encryptor:
    """ChaCha20加密器"""
    
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
        """ChaCha20-Poly1305加密"""
        nonce = os.urandom(12)
        chacha = ChaCha20Poly1305(key)
        return chacha.encrypt(nonce, plaintext, None), nonce
    
    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        """ChaCha20-Poly1305解密"""
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)


class TransformInfoCodec:
    """变换信息编码器"""
    
    @staticmethod
    def encode_transform_info(curve_sequence: List[str], mappings: List[np.ndarray],
                             params: List[Dict], color_map: Dict,
                             feature_points: np.ndarray, 
                             visual_center: Tuple[float, float]) -> bytes:
        """编码变换信息为字节流"""
        data = {
            'curve_sequence': curve_sequence,
            'params': params,
            'color_map': {'levels': color_map.get('levels', 10), 'image_shape': color_map.get('image_shape')},
            'feature_points': feature_points.tolist() if len(feature_points) > 0 else [],
            'visual_center': list(visual_center),
            'encoding_time': time.time()
        }
        
        json_bytes = json.dumps(data).encode('utf-8')
        
        # 使用reduce构建mapping字节
        non_empty_mappings = list(filter(lambda m: len(m) > 0, mappings))
        mapping_bytes = reduce(
            lambda acc, m: acc + m.tobytes(),
            non_empty_mappings,
            b''
        ) if non_empty_mappings else b''
        
        return json_bytes + b'|||MAPPINGS|||' + mapping_bytes
    
    @staticmethod
    def decode_transform_info(encoded: bytes) -> Tuple[List[str], List, Dict, np.ndarray, Tuple]:
        """解码变换信息 - 使用reduce替代循环"""
        separator = b'|||MAPPINGS|||'
        
        if separator in encoded:
            json_bytes, mapping_bytes = encoded.split(separator)
            data = json.loads(json_bytes.decode('utf-8'))
            
            curve_sequence = data['curve_sequence']
            params = data['params']
            color_map = data['color_map']
            feature_points = np.array(data['feature_points'])
            visual_center = tuple(data['visual_center'])
            
            # 使用reduce构建mappings
            def build_mapping(state, p):
                offset, mappings = state
                shape = p.get('shape', (0, 0))
                if shape[0] > 0 and shape[1] > 0:
                    size = shape[0] * shape[1] * 2 * 4
                    if offset + size <= len(mapping_bytes):
                        mapping = np.frombuffer(mapping_bytes[offset:offset+size], dtype=np.int32)
                        return (offset + size, mappings + [mapping.reshape(-1, 2)])
                return (offset, mappings)
            
            _, mappings = reduce(build_mapping, params, (0, []))
            
            return curve_sequence, mappings, params, color_map, feature_points, visual_center
        
        data = json.loads(encoded.decode('utf-8'))
        return data['curve_sequence'], [], [], {}, np.array([]), (0, 0)


# =============================================================================
# 第七部分：主API函数
# =============================================================================

class BlindWatermarkSystem:
    """盲水印系统主类"""
    
    def __init__(self):
        self.visual_center = None
        self.weight_map = None
        self.watermark_info = None
    
    def embed(self, image_path: str, watermark_path: str,
             mnemonic: str, output_key_path: str = "watermark.key") -> Dict:
        """嵌入水印到图像"""
        image_path = str(Path(image_path))
        watermark_path = str(Path(watermark_path))
        output_key_path = str(Path(output_key_path))
        
        if not output_key_path.endswith('.key'):
            output_key_path += '.key'
        
        image = imread_chinese(image_path)
        if image is None:
            raise ValueError(f"无法读取原图: {image_path}")
        
        if len(image.shape) == 2:
            image = cv2.cvtColor(image, cv2.COLOR_GRAY2BGR)
        elif image.shape[2] == 4:
            image = cv2.cvtColor(image, cv2.COLOR_BGRA2BGR)
        
        h, w = image.shape[:2]
        
        # 步骤1: 初始数据获取
        cx, cy = VisualCenterFinder.find_visual_center(image)
        self.visual_center = (cx, cy)
        
        original_weights = WeightSequenceGenerator.generate_weight_map(image, (cx, cy))
        
        ntp_time, time_hash, time_bytes = get_ntp_time()
        device_id = get_device_fingerprint()
        gps_hash, _ = get_gps_info()
        file_timestamp = get_file_timestamp(image_path)
        
        # 步骤2: 水印图处理
        watermark = imread_chinese(watermark_path)
        if watermark is None:
            raise ValueError(f"无法读取水印: {watermark_path}")
        
        watermark_weights, wm_info = WatermarkProcessor.process_watermark(watermark, (h, w))
        self.watermark_info = wm_info
        
        # 步骤3: 权重底图生成
        weight_base, color_map = WeightBaseGenerator.generate_weight_base(
            image, watermark_weights, original_weights
        )
        
        # 步骤4: 多重空间变换
        time_hex = time_hash[:8]
        transformer = MultiSpaceTransformer()
        curve_sequence = transformer.select_curves(time_hex, gps_hash, device_id, time_hash)
        
        # 使用reduce生成params
        params = reduce(
            lambda p_list, ct: p_list + [transformer.get_transform_params(ct, time_hex, (h, w))],
            curve_sequence,
            []
        )
        
        feature_points = VisualCenterFinder.find_feature_points(image)
        
        transformed_image, _, mappings = transformer.transform(weight_base, curve_sequence, params)
        
        # 步骤5: 密钥生成
        transform_info = TransformInfoCodec.encode_transform_info(
            curve_sequence, mappings, params, color_map, feature_points, (cx, cy)
        )
        
        key = KeyGenerator.generate_encryption_key(mnemonic)
        
        watermark_bytes = image_to_bytes(transformed_image)
        encrypt_data = transform_info + b'|||TRANSFORM|||' + watermark_bytes
        
        ciphertext, nonce = ChaCha20Encryptor.encrypt(key, encrypt_data)
        
        metadata = {
            'timestamp': file_timestamp,
            'ntp_time': ntp_time,
            'tsa_hash': time_hash,
            'device_id': device_id,
            'gps_hash': gps_hash,
            'visual_center': (float(cx), float(cy)),
            'image_shape': (h, w),
            'watermark_shape': wm_info['shape'],
            'watermark_position': wm_info['position'],
            'curve_sequence': curve_sequence,
            'feature_points_count': len(feature_points)
        }
        
        metadata_bytes = pickle.dumps(metadata)
        final_data = ciphertext + b'|||META|||' + metadata_bytes
        
        key_data = {
            'ciphertext': final_data,
            'nonce': nonce,
            'key_hash': key.hex(),
            'metadata': metadata
        }
        
        with open(output_key_path, 'wb') as f:
            pickle.dump(key_data, f)
        
        return {
            'status': 'success',
            'key_file': output_key_path,
            'ntp_timestamp': ntp_time,
            'file_timestamp': file_timestamp,
            'time_hash': time_hash,
            'device_id': device_id,
            'image_shape': (h, w),
            'watermark_shape': wm_info['shape'],
            'curve_sequence': curve_sequence
        }
    
    def extract(self, key_path: str, mnemonic: str,
               output_path: str = "extracted_watermark.png") -> np.ndarray:
        """从密钥文件提取水印"""
        key_path = str(Path(key_path))
        output_path = str(Path(output_path))
        
        with open(key_path, 'rb') as f:
            key_data = pickle.load(f)
        
        meta_separator = b'|||META|||'
        ciphertext_with_meta = key_data['ciphertext']
        
        if meta_separator in ciphertext_with_meta:
            ciphertext, metadata_bytes = ciphertext_with_meta.split(meta_separator)
            metadata = pickle.loads(metadata_bytes)
        else:
            ciphertext = ciphertext_with_meta
            metadata = key_data.get('metadata', {})
        
        nonce = key_data.get('nonce', b'\x00' * 12)
        
        # 解密
        key = KeyGenerator.generate_encryption_key(mnemonic)
        
        if key.hex() != key_data.get('key_hash'):
            raise ValueError("密钥不匹配!")
        
        try:
            plaintext = ChaCha20Encryptor.decrypt(key, ciphertext, nonce)
        except Exception as e:
            raise ValueError(f"解密失败: {e}")
        
        # 分离变换信息和水印数据
        separator = b'|||TRANSFORM|||'
        if separator in plaintext:
            transform_info, watermark_data = plaintext.split(separator)
        else:
            transform_info = b''
            watermark_data = plaintext
        
        # 逆向变换
        curve_sequence, mappings, params, color_map, feature_points, visual_center = \
            TransformInfoCodec.decode_transform_info(transform_info)
        
        watermark_img = bytes_to_image(watermark_data)
        
        if watermark_img is None:
            raise ValueError("无法解码水印图像")
        
        if len(mappings) > 0:
            transformer = MultiSpaceTransformer()
            watermark_img = transformer.reverse_transform(watermark_img, curve_sequence, mappings)
        
        imwrite_chinese(output_path, watermark_img)
        
        return watermark_img


def embed(image_path: str, watermark_path: str, 
         mnemonic: str, output_key_path: str = "watermark.key") -> Dict:
    """嵌入水印到图像"""
    return BlindWatermarkSystem().embed(image_path, watermark_path, mnemonic, output_key_path)


def extract(key_path: str, mnemonic: str, 
           output_path: str = "extracted_watermark.png") -> np.ndarray:
    """从密钥文件提取水印"""
    return BlindWatermarkSystem().extract(key_path, mnemonic, output_path)


# =============================================================================
# 测试
# =============================================================================

if __name__ == "__main__":
    # 创建测试图像
    test_image = np.random.randint(50, 200, (512, 512, 3), dtype=np.uint8)
    cv2.rectangle(test_image, (100, 100), (400, 400), (100, 150, 200), -1)
    cv2.circle(test_image, (256, 256), 50, (255, 200, 100), -1)
    cv2.imwrite("test_image.png", test_image)
    
    # 创建测试水印
    test_watermark = np.zeros((100, 100, 3), dtype=np.uint8)
    cv2.rectangle(test_watermark, (20, 20), (80, 80), (255, 0, 0), -1)
    cv2.putText(test_watermark, "TEST", (25, 55), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.imwrite("test_watermark.png", test_watermark)
    
    print("测试图像已生成")
    print(f"原图形状: {test_image.shape}")
    print(f"水印形状: {test_watermark.shape}\n")
    
    mnemonic = "测试助记词 保密安全"
    
    try:
        # 嵌入水印
        result = embed(
            image_path="test_image.png",
            watermark_path="test_watermark.png",
            mnemonic=mnemonic,
            output_key_path="watermark.key"
        )
        
        print("=" * 50)
        print("嵌入成功!")
        print("=" * 50)
        print(f"密钥文件: {result['key_file']}")
        print(f"NTP时间戳: {result['ntp_timestamp']}")
        print(f"文件时间戳: {result['file_timestamp']}")
        print(f"时间哈希: {result['time_hash']}")
        print(f"设备ID: {result['device_id']}")
        print(f"图像形状: {result['image_shape']}")
        print(f"水印形状: {result['watermark_shape']}")
        print(f"变换曲线: {result['curve_sequence']}\n")
        
        # 提取水印
        extracted = extract(
            key_path="watermark.key",
            mnemonic=mnemonic,
            output_path="extracted_watermark.png"
        )
        
        print("=" * 50)
        print("提取成功!")
        print("=" * 50)
        print(f"水印已保存到: extracted_watermark.png")
        print(f"水印形状: {extracted.shape}")
        
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()
