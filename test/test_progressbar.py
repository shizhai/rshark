import tkinter as tk
from tkinter import ttk

class YourApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Progressbar 示例")

        # 创建 ttk.Style 对象
        self.style = ttk.Style()

        # 设置 TProgressbar.trough 样式
        self.style.configure("TProgressbar.trough",
                             background="lightgray",  # 进度条底色
                             )

        # 设置 TProgressbar.pbar 样式
        self.style.configure("TProgressbar.pbar",
                             thickness=2,  # 进度条的粗细
                             color="green",  # 进度条的颜色
                             )

        # 创建进度条
        self.progress = ttk.Progressbar(self.root, orient="horizontal", length=300, mode="determinate", style="TProgressbar")

        # 将进度条放置在布局中
        self.progress.pack(pady=10)

        # 创建按钮用于演示
        self.start_button = tk.Button(self.root, text="开始", command=self.simulate_progress)
        self.start_button.pack(pady=10)

    def simulate_progress(self):
        self.progress["maximum"] = 100
        for i in range(101):
            self.progress["value"] = i
            self.root.update_idletasks()

if __name__ == "__main__":
    root = tk.Tk()
    app = YourApp(root)
    root.mainloop()
