# -*- coding: utf-8 -*-
"""
盲水印加密系统 - 图形用户界面
基于tkinter实现

功能：
- 嵌入水印：原图 + 水印图 → 密钥文件（含TSA时间戳）
- 提取水印：原图 + 密钥文件 → 水印图
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
import threading
import numpy as np
import cv2
from PIL import Image, ImageTk


class BlindWatermarkGUI:
    """盲水印加密系统图形界面"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("盲水印加密系统")
        self.root.geometry("700x550")
        self.root.minsize(650, 500)
        
        # 导入加解密模块
        from blind_watermark import embed, extract
        self.embed_func = embed
        self.extract_func = extract
        
        # 变量
        self.image_path = tk.StringVar()      # 原图路径
        self.watermark_path = tk.StringVar()   # 水印图路径
        self.key_path = tk.StringVar()         # 密钥文件路径
        self.mnemonic = tk.StringVar()         # 助记词
        self.status_text = tk.StringVar(value="就绪")
        
        self._create_widgets()
        
    def _create_widgets(self):
        """创建界面组件"""
        # 标题
        title_label = tk.Label(
            self.root, 
            text="盲水印加密系统", 
            font=("Microsoft YaHei", 18, "bold"),
            fg="#2c3e50"
        )
        title_label.pack(pady=10)
        
        # 主框架
        main_frame = ttk.Frame(self.root, padding="12")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # ========== 功能选择标签页 ==========
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # 嵌入水印标签页
        self.embed_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.embed_frame, text="  嵌入水印  ")
        
        # 提取水印标签页
        self.extract_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.extract_frame, text="  提取水印  ")
        
        # ========== 嵌入水印页面 ==========
        self._create_embed_tab()
        
        # ========== 提取水印页面 ==========
        self._create_extract_tab()
        
        # ========== 状态栏 ==========
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(status_frame, text="状态:").pack(side=tk.LEFT, padx=3)
        self.status_label = ttk.Label(status_frame, textvariable=self.status_text, foreground="blue")
        self.status_label.pack(side=tk.LEFT, padx=3)
        
        # 进度条
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=100)
        self.progress.pack(pady=3)
        
    def _create_embed_tab(self):
        """创建嵌入水印标签页"""
        # 原图像选择
        img_frame = ttk.LabelFrame(self.embed_frame, text="原图像", padding="8")
        img_frame.pack(fill=tk.X, pady=3)
        
        img_row = ttk.Frame(img_frame)
        img_row.pack(fill=tk.X)
        ttk.Label(img_row, text="原图:", width=6).pack(side=tk.LEFT, padx=3)
        ttk.Entry(img_row, textvariable=self.image_path, width=45).pack(side=tk.LEFT, padx=3)
        ttk.Button(img_row, text="浏览", command=self._browse_image, width=6).pack(side=tk.LEFT, padx=3)
        
        # 水印图像选择
        wm_frame = ttk.LabelFrame(self.embed_frame, text="水印图像", padding="8")
        wm_frame.pack(fill=tk.X, pady=3)
        
        wm_row = ttk.Frame(wm_frame)
        wm_row.pack(fill=tk.X)
        ttk.Label(wm_row, text="水印:", width=6).pack(side=tk.LEFT, padx=3)
        ttk.Entry(wm_row, textvariable=self.watermark_path, width=45).pack(side=tk.LEFT, padx=3)
        ttk.Button(wm_row, text="浏览", command=self._browse_watermark, width=6).pack(side=tk.LEFT, padx=3)
        
        # 密钥设置
        key_frame = ttk.LabelFrame(self.embed_frame, text="密钥设置", padding="8")
        key_frame.pack(fill=tk.X, pady=3)
        
        mnemonic_row = ttk.Frame(key_frame)
        mnemonic_row.pack(fill=tk.X)
        ttk.Label(mnemonic_row, text="助记词:", width=6).pack(side=tk.LEFT, padx=3)
        self.embed_mnemonic_entry = ttk.Entry(mnemonic_row, textvariable=self.mnemonic, width=35, show="*")
        self.embed_mnemonic_entry.pack(side=tk.LEFT, padx=3)
        ttk.Button(mnemonic_row, text="显示", command=self._toggle_mnemonic, width=5).pack(side=tk.LEFT, padx=2)
        ttk.Button(mnemonic_row, text="随机", command=self._generate_mnemonic, width=5).pack(side=tk.LEFT, padx=2)
        
        # 预览区域
        preview_frame = ttk.LabelFrame(self.embed_frame, text="预览", padding="5")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=3)
        
        # 左侧原图预览
        left_frame = ttk.Frame(preview_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        ttk.Label(left_frame, text="原图").pack()
        self.embed_canvas = tk.Canvas(left_frame, width=180, height=140, bg="#f0f0f0")
        self.embed_canvas.pack(pady=2)
        
        # 右侧水印预览
        right_frame = ttk.Frame(preview_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=2)
        ttk.Label(right_frame, text="水印").pack()
        self.wm_canvas = tk.Canvas(right_frame, width=140, height=100, bg="#f0f0f0")
        self.wm_canvas.pack(pady=2)
        
        # 嵌入按钮
        btn_frame = ttk.Frame(self.embed_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.embed_btn = ttk.Button(
            btn_frame, 
            text="嵌入水印", 
            command=self._do_embed,
            width=18
        )
        self.embed_btn.pack(padx=5, pady=3)
        
    def _create_extract_tab(self):
        """创建提取水印标签页"""
        # 原图像选择
        img_frame = ttk.LabelFrame(self.extract_frame, text="原图像（含水印）", padding="8")
        img_frame.pack(fill=tk.X, pady=3)
        
        img_row = ttk.Frame(img_frame)
        img_row.pack(fill=tk.X)
        ttk.Label(img_row, text="原图:", width=6).pack(side=tk.LEFT, padx=3)
        self.extract_image_path = tk.StringVar()
        ttk.Entry(img_row, textvariable=self.extract_image_path, width=45).pack(side=tk.LEFT, padx=3)
        ttk.Button(img_row, text="浏览", command=self._browse_extract_image, width=6).pack(side=tk.LEFT, padx=3)
        
        # 密钥文件选择
        key_frame = ttk.LabelFrame(self.extract_frame, text="密钥文件", padding="8")
        key_frame.pack(fill=tk.X, pady=3)
        
        key_row = ttk.Frame(key_frame)
        key_row.pack(fill=tk.X)
        ttk.Label(key_row, text="密钥:", width=6).pack(side=tk.LEFT, padx=3)
        ttk.Entry(key_row, textvariable=self.key_path, width=45).pack(side=tk.LEFT, padx=3)
        ttk.Button(key_row, text="浏览", command=self._browse_key, width=6).pack(side=tk.LEFT, padx=3)
        
        # 助记词输入
        mnemonic_frame = ttk.LabelFrame(self.extract_frame, text="密钥验证", padding="8")
        mnemonic_frame.pack(fill=tk.X, pady=3)
        
        mnemonic_row = ttk.Frame(mnemonic_frame)
        mnemonic_row.pack(fill=tk.X)
        ttk.Label(mnemonic_row, text="助记词:", width=6).pack(side=tk.LEFT, padx=3)
        self.extract_mnemonic_entry = ttk.Entry(mnemonic_row, textvariable=self.mnemonic, width=35, show="*")
        self.extract_mnemonic_entry.pack(side=tk.LEFT, padx=3)
        ttk.Button(mnemonic_row, text="显示", command=self._toggle_extract_mnemonic, width=5).pack(side=tk.LEFT, padx=2)
        
        # 预览区域
        preview_frame = ttk.LabelFrame(self.extract_frame, text="预览", padding="5")
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=3)
        
        # 左侧原图
        left_frame = ttk.Frame(preview_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=2)
        ttk.Label(left_frame, text="原图").pack()
        self.extract_canvas = tk.Canvas(left_frame, width=180, height=140, bg="#f0f0f0")
        self.extract_canvas.pack(pady=2)
        
        # 右侧提取的水印
        right_frame = ttk.Frame(preview_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=2)
        ttk.Label(right_frame, text="水印").pack()
        self.result_canvas = tk.Canvas(right_frame, width=140, height=100, bg="#f0f0f0")
        self.result_canvas.pack(pady=2)
        
        # 提取按钮
        btn_frame = ttk.Frame(self.extract_frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        self.extract_btn = ttk.Button(
            btn_frame, 
            text="提取水印", 
            command=self._do_extract,
            width=18
        )
        self.extract_btn.pack(padx=5, pady=3)
        
    def _browse_image(self):
        """浏览原图像"""
        path = filedialog.askopenfilename(
            title="选择原图像",
            filetypes=[
                ("图像文件", "*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.webp"),
                ("PNG图像", "*.png"),
                ("JPEG图像", "*.jpg *.jpeg"),
                ("BMP图像", "*.bmp"),
                ("TIFF图像", "*.tiff *.tif"),
                ("WEBP图像", "*.webp"),
                ("所有文件", "*.*")
            ]
        )
        if path:
            self.image_path.set(path)
            self._preview_image(path, self.embed_canvas)
            self.status_text.set("已加载原图像")
            
    def _browse_watermark(self):
        """浏览水印图像"""
        path = filedialog.askopenfilename(
            title="选择水印图像",
            filetypes=[
                ("图像文件", "*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.webp"),
                ("PNG图像", "*.png"),
                ("JPEG图像", "*.jpg *.jpeg"),
                ("BMP图像", "*.bmp"),
                ("TIFF图像", "*.tiff *.tif"),
                ("WEBP图像", "*.webp"),
                ("所有文件", "*.*")
            ]
        )
        if path:
            self.watermark_path.set(path)
            self._preview_image(path, self.wm_canvas)
            self.status_text.set("已加载水印图像")
            
    def _browse_extract_image(self):
        """浏览要提取的图像"""
        path = filedialog.askopenfilename(
            title="选择含水印的图像",
            filetypes=[
                ("图像文件", "*.png *.jpg *.jpeg *.bmp *.tiff *.tif *.webp"),
                ("PNG图像", "*.png"),
                ("JPEG图像", "*.jpg *.jpeg"),
                ("BMP图像", "*.bmp"),
                ("TIFF图像", "*.tiff *.tif"),
                ("WEBP图像", "*.webp"),
                ("所有文件", "*.*")
            ]
        )
        if path:
            self.extract_image_path.set(path)
            self._preview_image(path, self.extract_canvas)
            self.status_text.set("已加载图像")
            
    def _browse_key(self):
        """浏览密钥文件"""
        path = filedialog.askopenfilename(
            title="选择密钥文件",
            filetypes=[
                ("密钥文件", "*.key"),
                ("所有文件", "*.*")
            ]
        )
        if path:
            self.key_path.set(path)
            self.status_text.set("已加载密钥文件")
            
    def _toggle_mnemonic(self):
        """显示/隐藏助记词"""
        current_show = self.embed_mnemonic_entry.cget("show")
        if current_show == "*":
            self.embed_mnemonic_entry.config(show="")
        else:
            self.embed_mnemonic_entry.config(show="*")
            
    def _toggle_extract_mnemonic(self):
        """显示/隐藏提取页面的助记词"""
        current_show = self.extract_mnemonic_entry.cget("show")
        if current_show == "*":
            self.extract_mnemonic_entry.config(show="")
        else:
            self.extract_mnemonic_entry.config(show="*")
            
    def _generate_mnemonic(self):
        """生成随机助记词"""
        import secrets
        import string
        # 生成12个随机字符
        chars = string.ascii_letters + string.digits
        mnemonic = ''.join(secrets.choice(chars) for _ in range(12))
        self.mnemonic.set(mnemonic)
        self.status_text.set("已生成随机助记词，请妥善保存!")
        messagebox.showinfo("提示", f"随机助记词已生成:\n\n{mnemonic}\n\n请妥善保存此助记词，提取水印时需要使用!")
        
    def _preview_image(self, path, canvas):
        """预览图像（支持中文路径）"""
        if not path or not os.path.exists(path):
            return
            
        try:
            # 支持中文路径
            img = cv2.imdecode(np.fromfile(path, dtype=np.uint8), cv2.IMREAD_UNCHANGED)
            if img is None:
                img = cv2.imread(path)
                if img is None:
                    return
            
            # 确保是BGR图像
            if len(img.shape) == 2:
                img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
            elif img.shape[2] == 4:
                img = cv2.cvtColor(img, cv2.COLOR_BGRA2BGR)
            
            h, w = img.shape[:2]
            
            # 调整显示大小
            max_size = 280
            scale = min(max_size/h, max_size/w, 1.0)
            new_h, new_w = int(h*scale), int(w*scale)
            
            # 转换颜色
            img_rgb = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
            img_pil = Image.fromarray(img_rgb)
            img_tk = ImageTk.PhotoImage(img_pil.resize((new_w, new_h)))
            
            canvas.image = img_tk
            canvas.delete("all")
            
            # 居中显示
            canvas_width = canvas.winfo_width() or 300
            canvas_height = canvas.winfo_height() or 250
            x = (canvas_width - new_w) // 2
            y = (canvas_height - new_h) // 2
            canvas.create_image(canvas_width//2, canvas_height//2, image=img_tk, anchor=tk.CENTER)
            
        except Exception as e:
            print(f"预览错误: {e}")
            
    def _start_progress(self):
        """开始进度条"""
        self.progress.pack(fill=tk.X, pady=5)
        self.progress.start(10)
        self.root.update()
        
    def _stop_progress(self):
        """停止进度条"""
        self.progress.stop()
        self.progress.pack_forget()
        
    def _do_embed(self):
        """执行嵌入水印"""
        # 验证输入
        if not self.image_path.get():
            messagebox.showwarning("警告", "请选择原图像")
            return
        if not os.path.exists(self.image_path.get()):
            messagebox.showwarning("警告", "原图像文件不存在")
            return
        if not self.watermark_path.get():
            messagebox.showwarning("警告", "请选择水印图像")
            return
        if not os.path.exists(self.watermark_path.get()):
            messagebox.showwarning("警告", "水印图像文件不存在")
            return
        if not self.mnemonic.get():
            messagebox.showwarning("警告", "请输入助记词")
            return
            
        # 选择密钥文件保存路径
        key_path = filedialog.asksaveasfilename(
            title="保存密钥文件",
            defaultextension=".key",
            filetypes=[
                ("密钥文件", "*.key"),
                ("所有文件", "*.*")
            ],
            initialfile="watermark.key"
        )
        if not key_path:
            return
            
        # 禁用按钮
        self.embed_btn.config(state=tk.DISABLED)
        
        # 线程执行
        def embed_thread():
            try:
                self.root.after(0, lambda: self.status_text.set("正在嵌入水印..."))
                self.root.after(0, self._start_progress)
                
                # 执行嵌入
                result = self.embed_func(
                    image_path=self.image_path.get(),
                    watermark_path=self.watermark_path.get(),
                    mnemonic=self.mnemonic.get(),
                    output_key_path=key_path
                )
                
                self.root.after(0, self._stop_progress)
                self.root.after(0, lambda: self.status_text.set("嵌入完成!"))
                
                # 显示结果
                info = f"""嵌入成功!

原图: {os.path.basename(self.image_path.get())}
水印: {os.path.basename(self.watermark_path.get())}
密钥文件: {os.path.basename(key_path)}

NTP时间戳: {result.get('ntp_timestamp', 'N/A')}
文件时间戳: {result.get('file_timestamp', 'N/A')}

请妥善保存密钥文件和助记词!"""
                
                self.root.after(0, lambda: messagebox.showinfo("成功", info))
                    
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, self._stop_progress)
                self.root.after(0, lambda msg=err_msg: self.status_text.set(f"嵌入失败: {msg}"))
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("错误", f"嵌入失败:\n{msg}"))
            finally:
                self.root.after(0, lambda: self.embed_btn.config(state=tk.NORMAL))
                
        threading.Thread(target=embed_thread, daemon=True).start()
        
    def _do_extract(self):
        """执行提取水印"""
        # 验证输入
        if not self.extract_image_path.get():
            messagebox.showwarning("警告", "请选择原图像（含水印）")
            return
        if not os.path.exists(self.extract_image_path.get()):
            messagebox.showwarning("警告", "图像文件不存在")
            return
        if not self.key_path.get():
            messagebox.showwarning("警告", "请选择密钥文件")
            return
        if not os.path.exists(self.key_path.get()):
            messagebox.showwarning("警告", "密钥文件不存在")
            return
        if not self.mnemonic.get():
            messagebox.showwarning("警告", "请输入助记词")
            return
            
        # 选择输出路径
        output_path = filedialog.asksaveasfilename(
            title="保存水印图像",
            defaultextension=".png",
            filetypes=[
                ("PNG图像", "*.png"),
                ("JPEG图像", "*.jpg"),
                ("所有文件", "*.*")
            ],
            initialfile="extracted_watermark.png"
        )
        if not output_path:
            return
            
        # 禁用按钮
        self.extract_btn.config(state=tk.DISABLED)
        
        # 线程执行
        def extract_thread():
            try:
                self.root.after(0, lambda: self.status_text.set("正在提取水印..."))
                self.root.after(0, self._start_progress)
                
                # 执行提取
                extracted = self.extract_func(
                    image_path=self.extract_image_path.get(),
                    key_path=self.key_path.get(),
                    mnemonic=self.mnemonic.get(),
                    output_path=output_path
                )
                
                self.root.after(0, self._stop_progress)
                self.root.after(0, lambda: self.status_text.set("提取完成!"))
                self.root.after(0, lambda: self._preview_image(output_path, self.result_canvas))
                
                self.root.after(0, lambda: messagebox.showinfo("成功", 
                    f"提取成功!\n\n水印已保存至: {output_path}"))
                    
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, self._stop_progress)
                self.root.after(0, lambda msg=err_msg: self.status_text.set(f"提取失败: {msg}"))
                self.root.after(0, lambda msg=err_msg: messagebox.showerror("错误", 
                    f"提取失败:\n{msg}\n\n请检查:\n1. 助记词是否正确\n2. 密钥文件是否匹配\n3. 图像是否包含水印"))
            finally:
                self.root.after(0, lambda: self.extract_btn.config(state=tk.NORMAL))
                
        threading.Thread(target=extract_thread, daemon=True).start()


def main():
    """主函数"""
    root = tk.Tk()
    
    # 设置样式
    style = ttk.Style()
    style.theme_use('clam')
    
    # 设置字体
    default_font = ("Microsoft YaHei", 10)
    root.option_add("*Font", default_font)
    
    app = BlindWatermarkGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
