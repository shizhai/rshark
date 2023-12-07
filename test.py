# import tkinter as tk
# root = tk.Tk()

# def myfunction(event):
#     print(buttons[event.widget])

# buttons = {}
# for i in range(10):
#     b = tk.Button(root, text='button' + str(i))
#     buttons[b] = i # save button, index as key-value pair
#     b.bind("<Button-1>", myfunction)
#     b.place(x=10,y=(10+(25*i)))
# root.mainloop()

import re

def is_valid_mac_address(mac_address):
    # 正则表达式匹配标准MAC地址格式
    pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(pattern.match(mac_address))

# 示例用法
mac_address1 = "00:1a:2b:3c:4d:5e"
mac_address2 = "00-1A-2B-3C-4D-5E"
mac_address3 = "invalid_mac_address"

print(is_valid_mac_address(mac_address1))  # 输出 True
print(is_valid_mac_address(mac_address2))  # 输出 True
print(is_valid_mac_address(mac_address3))  # 输出 False
