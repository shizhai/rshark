import tkinter as tk

root = tk.Tk()

# 创建 StringVar
string_var = tk.StringVar()
string_var.set("Hello, Tkinter!")

# 创建 Entry 组件并关联 StringVar
entry = tk.Entry(root, textvariable=string_var, background="lightblue")
entry.pack()

root.mainloop()
