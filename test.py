import time
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

# import re

# def is_valid_mac_address(mac_address):
#     # 正则表达式匹配标准MAC地址格式
#     pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
#     return bool(pattern.match(mac_address))

# # 示例用法
# mac_address1 = "00:1a:2b:3c:4d:5e"
# mac_address2 = "00-1A-2B-3C-4D-5E"
# mac_address3 = "invalid_mac_address"

# print(is_valid_mac_address(mac_address1))  # 输出 True
# print(is_valid_mac_address(mac_address2))  # 输出 True
# print(is_valid_mac_address(mac_address3))  # 输出 False

# import asyncio
# import time

# async def mainx():
#     print(f"{time.ctime()} Hello!")
#     await asyncio.sleep(1.0)
#     print(f"{time.ctime()} Goodbye!")

# loop = asyncio.get_event_loop() 
# mainxx = loop.create_task(mainx())

# loop.run_until_complete(mainxx)

import re
glines = [
    '325626824713us tsft 1.0 Mb/s 2412 MHz 11b -29dBm signal -98dBm noise antenna 0 BSSID:08:10:7a:88:37:dd DA:ff:ff:ff:ff:ff:ff SA:08:10:7a:88:37:dd Beacon (Netcore_test2481) [1.0* 2.0* 5.5* 11.0* 9.0 18.0 36.0 54.0 Mbit] ESS CH: 1, PRIVACY',
    '325626827836us tsft 1.0 Mb/s 2412 MHz 11b -41dBm signal -98dBm noise antenna 0 BSSID:c8:bf:4c:a7:cf:14 DA:a0:9f:10:44:3e:a6 SA:c8:bf:4c:a7:cf:14 Probe Response (tprate) [24.0* Mbit] CH: 1, PRIVACY',
    '325626829309us tsft 1.0 Mb/s 2412 MHz 11b -63dBm signal -98dBm noise antenna 0 CF +QoS BSSID:4c:77:66:c5:c2:c1 SA:48:f1:7f:a9:a1:55 DA:4c:77:66:c5:c2:c1 Data IV:7647 Pad 20 KeyID 0',
    '325626829626us tsft 1.0 Mb/s 2412 MHz 11b -42dBm signal -98dBm noise antenna 0 RA:48:f1:7f:a9:a1:55 Acknowledgment',
    '325626832046us tsft 1.0 Mb/s 2412 MHz 11b -49dBm signal -98dBm noise antenna 0 CF +QoS BSSID:4c:77:66:c5:c2:c1 SA:48:f1:7f:a9:a1:55 DA:4c:77:66:c5:c2:c1 Data IV:7648 Pad 20 KeyID 0',
    '336729100313us tsft 24.0 Mb/s 2412 MHz 11g -58dBm signal -96dBm noise antenna 0 Retry Protected 106us CF +QoS BSSID:06:05:88:34:2c:8f SA:3c:a0:67:41:bf:65 DA:ff:ff:ff:ff:ff:ff Data IV:d923 Pad 20 KeyID 0',
    '409555445523us tsft 1.0 Mb/s 2412 MHz 11b 5dBm signal -68dBm noise antenna 0 DA:01:00:5e:7f:ff:fa BSSID:78:60:5b:bb:67:d7 SA:78:60:5b:bb:67:d7 Data IV:b45 Pad 20 KeyID 1',
    '407009562477us tsft 2412 MHz 11n -26dBm signal -97dBm noise antenna 0 65.0 Mb/s MCS 7 20 MHz long GI CF +QoS DA:c2:95:73:f3:b4:56 BSSID:78:60:5b:b9:35:fd SA:00:0e:c6:26:74:0a Data IV:6373 Pad 20 KeyID 0',
    '407008927922us tsft 2412 MHz 11n -36dBm signal -97dBm noise antenna 0 65.0 Mb/s MCS 6 20 MHz short GI CF +QoS BSSID:78:60:5b:b9:35:fd SA:c2:95:73:f3:b4:56 DA:00:0e:c6:26:74:0a Data IV:a7c8 Pad 20 KeyID 0',
    '336727797556us tsft bad-fcs 11.0 Mb/s 2412 MHz 11b -47dBm signal -96dBm noise antenna 0 Pwr Mgmt Retry Protected 0us BSSID:cc:20:e8:50:4a:e2 DA:ff:5d:86:c4:62:79 SA:d5:54:e4:ab:2f:be ReAssoc Request IV:f5d281 Pad 36 KeyID 0',
    '511373197670us tsft 1.0 Mb/s 2412 MHz 11b -30dBm signal -99dBm noise antenna 0 314us BSSID:78:60:5b:b9:35:fd DA:78:60:5b:b9:35:fd SA:c2:95:73:f3:b4:56 DeAuthentication: Deauthenticated',
    '511373205045us tsft 6.0 Mb/s 2412 MHz 11g -23dBm signal -99dBm noise antenna 0 208us BSSID:78:60:5b:b9:35:fd DA:c2:95:73:f3:b4:56 SA:78:60:5b:b9:35:fd Action: BA DELBA',
    '325626832046us tsft 1.0 Mb/s 2412 MHz 11b -49dBm signal -98dBm noise antenna 0 CF Request-To-Send BSSID:4c:77:66:c5:c2:c1 SA:48:f1:7f:a9:a1:55 DA:4c:77:66:c5:c2:c1 Data IV:7648 Pad 20 KeyID 0']

def rshark_parse_lines(line):
    rets = {}

    # rclass = ["data", "mgmt"]
    rclass_list = []
    rclass_reg_list = []
    rclass_ctrl_name = {"Acknowledgment": "ack", "Request-To-Send": "rts", "Clear-To-Send": "cts", "BA": None, "BAR": None, "Power Save-Poll": None, "CF-End": None, "CF-End+CF-Ack": None}
    rclass_data_name = {"Data": "data"}
    # rclass_ctrl_list = ["Acknowledgment", "Request-To-Send", "Clear-To-Send", "BA", "BAR", "Power Save-Poll", "CF-End", "CF-End+CF-Ack"]
    rclass_ctrl_list = list(rclass_ctrl_name.keys())
    rclass_list = rclass_ctrl_list
    rclass_ctrl_reg = r"|".join(rclass_ctrl_list)
    rclass_reg_list.append(rclass_ctrl_reg)
    # rclass_reg_list = rclass_ctrl_list

    rclass_data_list = list(rclass_data_name.keys())
    rclass_list = rclass_list + rclass_data_list
    rclass_data_reg = r"|".join(rclass_data_list)
    rclass_reg_list.append(rclass_data_reg)
    # rclass_reg_list = rclass_reg_list + rclass_data_list

    # print(rclass)

    rclass_names = {**rclass_data_name, **rclass_ctrl_name}
    # print(rclass_names)

    regs = {}
    regsd = {
        "ra": [
            re.compile(r'(DA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) (BSSID|SA).*Data', re.I),
            re.compile(r'(BSSID):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) SA.*Data', re.I),
            re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.*Data', re.I),
        ],
        "ta": [
            re.compile(r'(DA|BSSID):.* SA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) .*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Data', re.I),
            re.compile(r'(DA):.* BSSID:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) .*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Data', re.I),
            re.compile(r'(RA):.* TA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) .*(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Data', re.I),
        ]}

    regs["Data"] = regsd

    regs["Acknowledgment"] = {
        "ra":[
            re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Acknowledgment', re.I),
        ],
        "ta":[

        ]
    }

    # RA:48:f1:7f:a9:a1:55 TA:4c:77:66:c5:c2:c1 Request-To-Send
    regs["Request-To-Send"] = {
        "ra":[
            re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.* Request-To-Send', re.I),
        ],
        "ta":[
            re.compile(r'(RA):.* TA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Request-To-Send', re.I),
        ]
    }

    # RA:c2:95:73:6d:df:fe Clear-To-Send
    regs["Clear-To-Send"] = {
        "ra":[
            re.compile(r'(RA):(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) TA.* Clear-To-Send', re.I),
        ],
        "ta":[
            re.compile(r'(RA):.* TA:(([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}) Clear-To-Send', re.I),
        ]
    }

    regs["rssi"] = re.compile(r'(\S*)dBm signal', re.I)
    regs["Retry"] = re.compile(r'\sRetry\s', re.I)

    # print(rclass_ctrl_reg)
    rci = -1
    # print(rclass_reg_list)
    # print(rclass_list)
    for rc in rclass_reg_list:
        rcc = re.compile(r'\s('+rc+')', re.I)
        # print(rcc)
        rcs = rcc.search(line)
        if not rcs:
            continue

        item = rcs.groups()[0]
        # print(rclass_list, item)
        rci = rclass_list.index(item)
        break

    # print(rclass_list[rci] if rci >= 0 else "None")
    if rci >= 0 and rclass_list[rci] in regs:
        rets["dot11_frame_type"] = rclass_names[rclass_list[rci]]
        # print(rclass_list[rci], rclass_names[rclass_list[rci]])

        rets["ra"] = "None"
        rets["ta"] = "None"
        srssi = regs["rssi"].search(line)
        rets["rssi"] = srssi.groups()[0] if srssi else 0
        sretry = regs["Retry"].search(line)
        rets["retry"] = True if sretry else False
        regt = regs[rclass_list[rci]]
        # print(regt)

        for c in regt:
            for r in regt[c]:
                ci = r.search(line)
                if ci:
                    g = ci.groups()
                    # print(" ", c, "->", g[1], end="")
                    rets[c] = g[1]
                    break

        return rets

# for line in glines:
#     # print(rshark_parse_lines(line))
#     # rshark_parse_lines(line)
#     # xr = re.compile('\s(Acknowledgment)', re.IGNORECASE)
#     # print(xr.search(line))

#     with open("./t.hdr.txt", "r") as f:
#         while True:
#             line = f.readline()
#             if not line:
#                 break
#             pret = rshark_parse_lines(line)
#             if pret and pret["retry"]:
#                 print(pret)

# '''
# 动态折线图演示示例
# '''

# import numpy as np
# import matplotlib.pyplot as plt

# plt.ion()
# plt.figure(1)
# t_list = []
# result_list = []
# t = 0

# while True:
#     if t >= 10 * np.pi:
#         plt.clf()
#         t = 0
#         t_list.clear()
#         result_list.clear()
#     else:
#         t += np.pi / 4
#         t_list.append(t)
#         result_list.append(np.sin(t))
#         plt.plot(t_list, result_list,c='r',ls='-', marker='o', mec='b',mfc='w')  ## 保存历史数据
#         #plt.plot(t, np.sin(t), 'o')
#         plt.pause(0.1)

# import numpy as np
# import matplotlib.pyplot as plt
# import random
# import sys

# # plt.ion()
# plt.figure(1)
# t_list = []
# r_list = []
# r_list1 = []
# t = 0

# while True:
#     try:
#         t += 1
#         t_list.append(t)
#         r_list.append(random.randint(0, 10))
#         plt.plot(t_list, r_list,c='r',ls='-', marker='o', mec='b',mfc='w')  ## 保存历史数据
#         if t > 5:
#             if len(r_list1) == 0:
#                 r_list1 = [0] * len(r_list)
#             else:
#                 r_list1.append(random.randint(0, 10))

#             print(len(r_list), len(r_list1))
#             plt.plot(t_list, r_list1,c='b',ls='solid', marker='o', mec='b',mfc='w')  ## 保存历史数据
#         #plt.plot(t, np.sin(t), 'o')
#         plt.pause(0.5)
#     except KeyboardInterrupt:
#         plt.close()
#         sys.exit()


# import tkinter as tk
# from matplotlib.figure import Figure
# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
# import numpy as np
# import random
# import sys

# class MatplotlibEmbed(tk.Frame):
#     def __init__(self, master=None):
#         super().__init__(master)
#         self.master = master
#         self.pack()
#         self.create_widgets()

#     def create_widgets(self):
#         # 创建 Figure 对象
#         self.fig = Figure(figsize=(5, 4), dpi=100)

#         # 获取 Figure 的坐标轴对象
#         self.ax = self.fig.add_axes([0.1, 0.1, 0.8, 0.8])

#         # 创建 FigureCanvasTkAgg 对象
#         self.canvas = FigureCanvasTkAgg(self.fig, master=self)   
#         self.canvas.draw()

#         # 将 Canvas 组件放置在 Tkinter 窗口中
#         self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

#         # 启动动态更新
#         self.animate()

#     def animate(self):
#         t_list = []
#         r_list = []
#         r_list1 = []
#         t = 0

#         while True:
#             try:
#                 t += 1
#                 t_list.append(t)
#                 r_list.append(random.randint(0, 10))
#                 self.ax.clear()
#                 self.ax.plot(t_list, r_list, c='r', ls='-', marker='o', mec='b', mfc='w')  # 保存历史数据

#                 if t > 5:
#                     if len(r_list1) == 0:
#                         r_list1 = [0] * len(r_list)
#                     else:
#                         r_list1.append(random.randint(0, 10))

#                     print(len(r_list), len(r_list1))
#                     self.ax.plot(t_list, r_list1, c='b', ls='solid', marker='o', mec='b', mfc='w')  # 保存历史数据

#                 self.canvas.draw()
#                 self.update_idletasks()
#                 self.master.update()  # 更新主循环
#                 self.after(500)  # 间隔500毫秒
#             except KeyboardInterrupt:
#                 plt.close()
#                 sys.exit()

# # 创建 Tkinter 窗口
# root = tk.Tk()
# root.title("Matplotlib in Tkinter - Dynamic Update")

# # 创建 MatplotlibEmbed 对象
# app = MatplotlibEmbed(master=root)

# # 运行 Tkinter 主循环
# root.mainloop()


# import matplotlib.pyplot as plt
# import numpy as np
# import mplcursors

# # 创建一些示例数据
# x = np.linspace(0, 10, 100)
# y = np.sin(x)

# # 绘制曲线
# fig, ax = plt.subplots()
# line, = ax.plot(x, y, label='sin(x)')

# # 添加标签
# mplcursors.cursor(hover=True).connect("add", lambda sel: sel.annotation.set_text(f"Point {sel.target[0]:.2f}, {sel.target[1]:.2f}"))

# plt.legend()
# plt.show()


import tkinter as tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt


import mplcursors

class ZoomablePlot:
    def __init__(self, master):
        self.master = master
        self.fig, self.ax = self.create_plot()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.master)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)

        # 绑定鼠标事件
        self.canvas.mpl_connect('scroll_event', self.on_scroll)
        self.canvas.mpl_connect('button_press_event', self.on_button_press)
        self.canvas.mpl_connect('motion_notify_event', self.on_motion)
        self.canvas.mpl_connect('button_release_event', self.on_button_release)

        # 用于存储鼠标左键按下的初始位置
        self.start_x = None
        self.start_y = None

        # 在鼠标悬停时显示坐标值
        mplcursors.cursor(hover=True)

    def create_plot(self):
        fig, ax = plt.subplots()
        x = [i for i in range(10)]
        y = [i**2 for i in x]
        ax.plot(x, y, marker='o', label='y = x^2')
        ax.set_xlabel('X-axis')
        ax.set_ylabel('Y-axis')
        ax.set_title('Zoomable Plot')
        ax.legend()
        return fig, ax

    def on_scroll(self, event):
        if event.name == 'scroll_event' and event.inaxes:
            x, y = event.xdata, event.ydata
            self.zoom_at_point(x, y, event.step)

    def on_button_press(self, event):
        if event.button == 1:
            self.start_x = event.x
            self.start_y = event.y

    def on_motion(self, event):
        if self.start_x is not None and self.start_y is not None:
            # 防止拖动窗口的默认行为
            self.master.geometry('+%d+%d' % (self.master.winfo_x() + (event.x - self.start_x),
                                             self.master.winfo_y() + (event.y - self.start_y)))

    def on_button_release(self, event):
        if event.button == 1:
            self.start_x = None
            self.start_y = None

    def zoom_at_point(self, x, y, step):
        zoom_factor = 1.2 if step > 0 else 1 / 1.2
        new_xlim = [x - (x - self.ax.get_xlim()[0]) / zoom_factor,
                    x + (self.ax.get_xlim()[1] - x) / zoom_factor]
        new_ylim = [y - (y - self.ax.get_ylim()[0]) / zoom_factor,
                    y + (self.ax.get_ylim()[1] - y) / zoom_factor]
        self.ax.set_xlim(new_xlim)
        self.ax.set_ylim(new_ylim)
        self.canvas.draw()

# 创建主窗口
root = tk.Tk()
root.title("Zoomable Plot Example")

# 创建 ZoomablePlot 实例
zoomable_plot = ZoomablePlot(root)

# 运行主循环
root.mainloop()

