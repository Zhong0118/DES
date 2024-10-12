import os
import tkinter as tk
from tkinter import font, scrolledtext, messagebox, filedialog

from DES import *

# 创建主窗口
window = tk.Tk()
window.title("DES Algorithm")

# 设置窗口大小和居中显示
window_width = 1200
window_height = 600
screen_width = window.winfo_screenwidth()
screen_height = window.winfo_screenheight()
center_x = int(screen_width / 2 - window_width / 2)
center_y = int(screen_height / 2 - window_height / 2)
window.geometry(f"{window_width}x{window_height}+{center_x}+{center_y}")

# 设置背景颜色
window.configure(bg='#f0f0f0')  # 设置背景颜色为浅灰色
# 创建自定义字体
title_font1 = font.Font(family="STENCIL", size=20, weight="bold")
title_font2 = font.Font(family="Consolas", size=16, weight="bold")
text_font = font.Font(family="Helvetica", size=12)
input_font = font.Font(family="Consolas", size=12)

# 添加标题标签
title_label1 = tk.Label(window, text="Welcome to DES APP", font=title_font1, bg='#f0f0f0', fg='#111')
title_label2 = tk.Label(window, text="You can input Plaintext, Ciphertext, and Key.", font=title_font2, bg='#f0f0f0',
                        fg='#444')
title_label3 = tk.Label(window, text="or choose your files", font=title_font2, bg='#f0f0f0', fg='#444')
title_label1.pack(pady=2)
title_label2.pack(pady=1)
title_label3.pack(pady=1)

# 创建主框架
main_frame = tk.Frame(window, bg="#f0f0f0")
# 将主框架放置在窗口中，填充整个窗口，并在四周留出边距
main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

'''
明文区域的设计
'''
# 创建左侧框架（明文）
left_frame = tk.Frame(main_frame, bg="#f0f0f0")
# 允许宽度进行自适应扩展
left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
tk.Label(left_frame, text="Plaintext", font=title_font2, bg="#f0f0f0").pack(pady=2)
plaintext_input = scrolledtext.ScrolledText(
    left_frame, wrap=tk.WORD, width=20, height=15, font=input_font
)
plaintext_input.pack(fill=tk.BOTH, expand=False)

"""
密文区域的设计
"""
# 创建右侧框架（密文）
right_frame = tk.Frame(main_frame, bg="#f0f0f0")
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

tk.Label(right_frame, text="Ciphertext", font=title_font2, bg="#f0f0f0").pack(pady=2)
ciphertext_output = scrolledtext.ScrolledText(
    right_frame, wrap=tk.WORD, width=20, height=15, font=input_font
)
ciphertext_output.pack(fill=tk.BOTH, expand=False)

"""
密钥区域的设计
"""
# 创建中间框架（密钥和按钮）
middle_frame = tk.Frame(main_frame, bg="#f0f0f0", width=200)
middle_frame.pack(side=tk.LEFT, fill=tk.Y, padx=20)

tk.Label(middle_frame, text="Key", font=title_font2, bg="#f0f0f0").pack(pady=2)
key_input = scrolledtext.ScrolledText(middle_frame, wrap=tk.WORD, width=20, height=5, font=input_font)
key_input.pack(pady=10)

'''
加密解密的逻辑以及按钮
'''


# 是否选择文件
def toggle_input_mode():
    if input_mode.get():
        plaintext_input.config(state=tk.DISABLED)
        ciphertext_output.config(state=tk.DISABLED)
        file_button.config(state=tk.NORMAL)
    else:
        plaintext_input.config(state=tk.NORMAL)
        ciphertext_output.config(state=tk.NORMAL)
        file_button.config(state=tk.DISABLED)


# 选择文件
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        global current_file
        current_file = file_path
        file_label.config(text=f"Selected file: {file_path}")


def key_encrypt():
    key_str = key_input.get("1.0", "end-1c").strip()
    if not key_str:
        messagebox.showerror("Error", "Key is empty")
        return
    if input_mode.get():
        if not current_file:
            messagebox.showerror("Error", "No file selected")
            return
        with open(current_file, "r", encoding="utf-8") as file:
            plaintext_str = file.read()
        ciphertext = encrypt(plaintext_str, key_str)
        # 让用户选择保存加密文件的路径
        # 获取原文件名（不包括扩展名）
        original_filename = os.path.splitext(os.path.basename(current_file))[0]
        # 构造新的文件名
        new_filename = f"dec_{original_filename}.txt"
        save_path = filedialog.asksaveasfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=new_filename,
        )
        if save_path:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(ciphertext)
            messagebox.showinfo("Success", "Encryption completed")
    else:
        plaintext_str = plaintext_input.get("1.0", "end-1c").strip()
        if not plaintext_str:
            messagebox.showerror("Error", "Plaintext is empty")
            return
        ciphertext = encrypt(plaintext_str, key_str)
        ciphertext_output.delete("1.0", "end")
        ciphertext_output.insert("1.0", ciphertext)


def key_decrypt():
    key_str = key_input.get("1.0", "end-1c").strip()
    if not key_str:
        messagebox.showerror("Error", "Key is empty")
        return
    if input_mode.get():
        if not current_file:
            messagebox.showerror("Error", "No file selected")
            return
        with open(current_file, "r", encoding="utf-8") as file:
            ciphertext_str = file.read()
        try:
            plaintext = decrypt(ciphertext_str, key_str)
            if plaintext is None:
                messagebox.showerror("Error", "Sorry, your key is not correct.")
                return
            # 获取原文件名（不包括扩展名）
            original_filename = os.path.splitext(os.path.basename(current_file))[0]
            # 构造新的文件名
            new_filename = f"enc_{original_filename}.txt"
            save_path = filedialog.asksaveasfilename(
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=new_filename,
            )
            if save_path:
                with open(save_path, "w", encoding="utf-8") as f:
                    f.write(plaintext)
                messagebox.showinfo("Success", "Decryption completed")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    else:
        ciphertext_str = ciphertext_output.get("1.0", "end-1c").strip()
        if not ciphertext_str:
            messagebox.showerror("Error", "Ciphertext is empty")
            return
        try:
            plaintext = decrypt(ciphertext_str, key_str)
            if plaintext is None:
                messagebox.showerror("Error", "Sorry, your key is not correct.")
                return
            plaintext_input.delete("1.0", "end")
            plaintext_input.insert("1.0", plaintext)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")


encrypt_button = tk.Button(
    middle_frame,
    text="Encrypt→",
    font=text_font,
    bg="#4CAF50",
    fg="white",
    activebackground="#45a049",
    command=key_encrypt
)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(
    middle_frame,
    text="←Decrypt",
    font=text_font,
    bg="#2196F3",
    fg="white",
    activebackground="#1E88E5",
    command=key_decrypt
)
decrypt_button.pack(pady=10)
'''
选择文件或者直接输入
'''
# 添加输入模式切换
input_mode = tk.BooleanVar()
input_mode_check = tk.Checkbutton(
    middle_frame,
    text="File Mode",
    variable=input_mode,
    command=toggle_input_mode,
    font=text_font,
    bg="#f0f0f0",
)
input_mode_check.pack(pady=10)

# 添加文件选择按钮和标签
file_button = tk.Button(
    middle_frame,
    text="choose your file",
    font=text_font,
    command=select_file,
    state=tk.DISABLED,
)
file_button.pack(pady=10)

file_label = tk.Label(
    middle_frame, text="No file selected", font=text_font, bg="#f0f0f0", wraplength=180
)
file_label.pack(pady=10)

current_file = None

# 启动主事件循环
window.mainloop()
