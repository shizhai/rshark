import os
import argparse
from math import ceil
import copy
import asyncio
import threading
import tkinter as tk
from tkinter import ttk
# from tkinter import messagebox
import time
import rshark
import subprocess
import sys
from tkinter import messagebox
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import mplcursors
from tkinter.font import Font

os_platform = sys.platform.lower()

root = tk.Tk()
notebook = ttk.Notebook(root)

gwidth = 1780
gheight = 840
gwidth_min = 495
gheight_min = gheight

clients_file = "./clients"

IPERF_PATH=None
if os_platform.startswith("win"):
    IPERF_PATH="./files/iperf/iperf.exe"
else:
    IPERF_PATH="iperf"

class HoverInfo:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.show_tooltip)
        self.widget.bind("<Leave>", self.hide_tooltip)

    def show_tooltip(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 20

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = ttk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
        self.tooltip = None

class NetworkTestGUI:
    def __init__(self, mframe, pdframe, pfframe):
        self.running = False
        self.parse_on_time = True
        self.event_loop = asyncio.get_event_loop()
        self.client_thread = None
        self.pshark_thread = None
        self.mframe = mframe
        self.pdframe = pdframe
        self.pfframe = pfframe
        self.rows = 0
        self.data_boxs={}

        self.widget_bg = "lightblue"
        self.widget_width = 20
        self.widget_padx = 1
        self.widgets_all = []

        self.ptitle_fields = {"data": 0, "mgmt": 1, "ack": 2, "rts": 3, "cts": 4}
        self.psub_fields = ["rssi", "cnt", "retry"]

        # 停止标志
        self.stop_event = threading.Event()

        self.content_label = ttk.Label(self.mframe, text="/ " * 20 + "Iperf Client Info" + " /" * 20, background="lightblue")
        self.content_label.grid(row=self.rows, column=0, columnspan=3, padx=self.widget_padx, pady=0, sticky="we")
        self.widgets_all.append(self.content_label)
        self.rows = self.rows + 1

        # IP 输入框和标签
        self.ip_label = ttk.Label(self.mframe, text="IP Address:")
        self.ip_label.grid(row=self.rows, column=0, padx=self.widget_padx, pady=0, sticky="e")
        self.widgets_all.append(self.ip_label)
        self.ip_entry = ttk.Entry(self.mframe, width=self.widget_width)
        self.ip_entry.insert(0, "192.168.1.102")
        self.ip_entry.grid(row=self.rows, column=1, padx=self.widget_padx, pady=0, sticky="w")
        self.widgets_all.append(self.ip_entry)
        self.rows = self.rows + 1

        self.pt_pre = 0
        self.pt_list = []
        self.pr_list = {}
        self.prc_list = []
        self.plot_color_handle("RESET")

        # self.pframe_start_row = 0
        # self.pframe_start_col = 3
        self.pframe_start_row = 0
        self.pframe_start_col = 0
        self.title_sub_start_column = self.pframe_start_col + 1
        self.data_rows = self.pframe_start_row  + 2 # main title(data, mgmt, ...) + subtitle(cnts, retry, rssi)

        # Port 输入框和标签
        self.port_label = ttk.Label(self.mframe, text="Port:")
        self.port_label.grid(row=self.rows, column=0, padx=self.widget_padx, pady=5, sticky="e")
        self.widgets_all.append(self.port_label)
        self.port_entry = ttk.Entry(self.mframe, width=self.widget_width)
        self.port_entry.insert(0, "5001")
        self.port_entry.grid(row=self.rows, column=1, padx=self.widget_padx, pady=5, sticky="w")
        self.widgets_all.append(self.port_entry)
        self.rows = self.rows + 1

        # Protocol 输入框和标签
        self.protocol_label = ttk.Label(self.mframe, text="Protocol:")
        self.protocol_label.grid(row=self.rows, column=0, padx=self.widget_padx, pady=5, sticky="e")
        self.widgets_all.append(self.protocol_label)
        self.protocol_var = tk.StringVar()
        self.protocol_var.set("UDP")
        self.protocol_menu = ttk.OptionMenu(self.mframe, self.protocol_var, "UDP", "TCP")
        self.protocol_menu.grid(row=self.rows, column=1, padx=self.widget_padx, pady=5, sticky="w")
        self.widgets_all.append(self.protocol_menu)
        self.rows = self.rows + 1

        # 发送速率选择
        self.rate_label = ttk.Label(self.mframe, text="Rate:")
        self.rate_label.grid(row=self.rows, column=0, padx=self.widget_padx, pady=5, sticky="e")
        self.widgets_all.append(self.rate_label)
        self.rate_select = ttk.Combobox(self.mframe, width=self.widget_width - 2)
        self.rate_select["value"] = [ str(v) + " Mbps" for v in range(5, 80, 5) ]
        self.rate_select.current(4)
        self.rate_select.grid(row=self.rows, column=1, padx=self.widget_padx, pady=5, sticky="w")
        self.widgets_all.append(self.rate_select)
        self.rows = self.rows + 1

        self.check_box_enable_iperf = tk.IntVar()
        self.check_box_enable_iperf_w = ttk.Checkbutton(self.mframe, text = "Enable Iperf Client",
                                                       variable = self.check_box_enable_iperf, onvalue = 1, offvalue = 0)
                                                    #    variable = self.check_box_enable_iperf, onvalue = 1, offvalue = 0, width = 20)
        self.check_box_enable_iperf_w.grid(row=self.rows, column=1, padx=self.widget_padx, pady=5, sticky="we")
        self.widgets_all.append(self.check_box_enable_iperf_w)
        self.rows = self.rows + 1

        self.content_label = ttk.Label(self.mframe, text="/ " * 20 + "Sniffer Info" + " /" * 20, background="lightblue")
        self.content_label.grid(row=self.rows, column=0, columnspan=3, padx=self.widget_padx, pady=5, sticky="we")
        self.widgets_all.append(self.content_label)
        self.rows = self.rows + 1

        self.upmacs = {}

        hosts_out = []
        rshark.rshark_from_conf(clients_file, hosts_out=hosts_out)
        # print(hosts_out)
        # msgbox_info = rshark_msgbox_info() 
        self.rinfos = []
        for item_host in hosts_out:
            rinfo = {}
            rinfo["user"] = item_host["user"]
            rinfo["password"] = item_host["password"]
            rinfo["port"] = item_host["port"]
            rinfo["ip"] = item_host["ip"]
            rinfo["interface"] = item_host["interface"]
            rinfo["type"] = item_host["type"]
            rinfo["channel"] = list(range(1, 14))
            # rinfo["stores"] = ["pshark://."]
            if self.parse_on_time:
                rinfo["stores"] = ["wireshark://.", "local://./", "pshark://."]
            else:
                rinfo["stores"] = ["wireshark://.", "local://./"]
            self.upmacs[rinfo["ip"]] = item_host["upmacs"]
            self.rinfos.append(rinfo)

        self.wrinfo = {}
        self.rinfo = {}
        self.trigger_item = "ip"
        self.tirgger_pframe = "stores"
        self.mac_entry_start_row = 0
        self.mac_entry_diff_rows = 3      # max 3 mac filters
        self.mac_entries = []
        self.mac_entry_pair = []
        self.pmacs = {}
        self.ptitles = {}
        self.psubs = {}

        first_info = self.rinfos[0]
        for item in first_info:
            if type(first_info[item]) == list:
                self.wrinfo["label" + item] = ttk.Label(self.mframe, text=item + ": ")
                self.wrinfo["value" + item] = ttk.Combobox(self.mframe, width=self.widget_width - 2)
                self.wrinfo["value" + item]["value"] = first_info[item]
                if len(first_info[item]) > 0:
                    self.wrinfo["value" + item].current(0)
                if item == self.tirgger_pframe:
                    self.wrinfo["value" + item].bind('<<ComboboxSelected>>', self.trigger_update_pframe_info)
            elif item == self.trigger_item:
                self.wrinfo["label" + item] = ttk.Label(self.mframe, text=item + ": ")
                self.wrinfo["value" + item] = ttk.Combobox(self.mframe, width=self.widget_width - 2)
                info_trigger_items = []
                for item_each in self.rinfos:
                    info_trigger_items.append(item_each[self.trigger_item])

                self.wrinfo["value" + item]["value"] = info_trigger_items
                self.wrinfo["value" + item].current(0)
                self.wrinfo["value" + item].bind('<<ComboboxSelected>>', self.trigger_update_info)
            else:
                self.wrinfo["label" + item] = ttk.Label(self.mframe, text=item + ": ")
                self.wrinfo["value" + item] = ttk.Entry(self.mframe, width=self.widget_width)
                self.wrinfo["value" + item].insert(0, first_info[item])

            self.wrinfo["label" + item].grid(row=self.rows, column=0, sticky="e", padx=self.widget_padx, pady=5)
            self.widgets_all.append(self.wrinfo["label" + item])
            self.wrinfo["value" + item].grid(row=self.rows, column=1, sticky="w", padx=self.widget_padx, pady=5)
            self.widgets_all.append(self.wrinfo["value" + item])
            _hide = ttk.Label(self.mframe, text="")
            _hide.grid(row=len(self.mac_entries) + self.rows, column=2, sticky="w", padx=self.widget_padx, pady=5)
            self.widgets_all.append(_hide)
            self.rows = self.rows + 1

        # for spaces line to add mac filter with max lines == 3
        self.mac_entry_start_row = self.rows + 1

        # 添加 "添加MAC地址" 按钮
        self.add_mac_button = ttk.Button(self.mframe, text="Add MAC Group", command=self.add_mac_entry)
        self.add_mac_button.grid(row=self.rows, column=0, padx=self.widget_padx, pady=5, sticky="we")
        self.add_mac_entry_default()
        self.widgets_all.append(self.add_mac_button)

        self.hide_mac_label1 = ttk.Label(self.mframe, text="Addr.A")
        self.widgets_all.append(self.hide_mac_label1)
        self.hide_mac_label2 = ttk.Label(self.mframe, text="Addr.B")
        self.widgets_all.append(self.hide_mac_label2)

        self.rows += 1
        self.rows += self.mac_entry_diff_rows

        # self.rows = self.rows + self.sw.rows

        self.client_button = ttk.Button(self.mframe, text="Start", command=self.start_run)
        self.client_button.grid(row=self.rows, column=0, padx=self.widget_padx, pady = 5, sticky="we")
        self.widgets_all.append(self.client_button)

        # 停止按钮
        self.stop_button = ttk.Button(self.mframe, text="Stop", command=self.stop)
        self.stop_button.grid(row=self.rows, column=1, padx=self.widget_padx, pady=5, sticky="we")
        self.widgets_all.append(self.stop_button)

        # 保存按钮
        self.save_button = ttk.Button(self.mframe, text="Save", command=self.save)
        self.save_button.grid(row=self.rows, column=2, padx=self.widget_padx, pady=5, sticky="we")
        self.widgets_all.append(self.save_button)

        self.rows = self.rows + 1

        # print("cur rows {}".format(self.rows))
        # 统计
        stats_list = ["tx_rate", "tx_cnts", "running_time"]
        self.stats = self.gen_stats_menu_list(stats_list)

        self.mframe.update()
        self.pfframe.update()
        self.pdframe.update()

        # for itx in self.widgets_all:
        #     # itx.config(width=self.widget_width, background=self.widget_bg)
        #     print(itx.winfo_width())

        # create pdframe
        self.create_pdframe_title()

        root.update()

    def add_mac_entry_default(self):
        info_trigger_value = self.wrinfo["value" + self.trigger_item].get()
        for rinfo in self.rinfos:
            if rinfo[self.trigger_item] == info_trigger_value:
                if self.upmacs[info_trigger_value]:
                    for upmac in self.upmacs[info_trigger_value]:
                        upmacx = upmac.split("_")
                        me = self.add_mac_entry()
                        for upmacn in upmacx:
                            me[upmacx.index(upmacn)].insert(0, upmacn)

    def trigger_update_info(self, event):
        info_trigger_value = self.wrinfo["value" + self.trigger_item].get()
        for rinfo in self.rinfos:
            if rinfo[self.trigger_item] == info_trigger_value:
                for item in rinfo:
                    if type(rinfo[item]) == list:
                        self.wrinfo["value" + item]["value"] = []
                        self.wrinfo["value" + item]["value"] = rinfo[item]
                        self.wrinfo["value" + item].current(0)
                        self.mframe.update()
                    else:
                        self.wrinfo["value" + item].delete(0, 'end')
                        self.wrinfo["value" + item].insert(0, rinfo[item])
                break

    def create_pdframe_title(self):
        self.ptitles["tmenu"] = tk.StringVar()
        self.ptitles["tmenu"].set("src-->dst")
        self.ptitles["t_value_menu"] = ttk.Entry(self.pdframe, textvariable=self.ptitles["tmenu"], state="readonly", justify="center",
                                                 width=30, background='lightblue')
        self.ptitles["t_value_menu"].grid(row=self.pframe_start_row, column=self.pframe_start_col, rowspan=2, padx=0, pady=0, sticky="wens")

        for ptitle in self.ptitle_fields:
            self.ptitles["t"+ptitle] = tk.StringVar()
            self.ptitles["t"+ptitle].set(ptitle)
            self.ptitles["t_value"+ptitle] = ttk.Entry(self.pdframe,
                                                 textvariable=self.ptitles["t"+ptitle],
                                                 state="readonly",
                                                 justify="center",
                                                 width=8,
                                                 background='lightblue')
            self.ptitles["t_value"+ptitle].grid(row=self.pframe_start_row,
                                           column=self.title_sub_start_column + self.ptitle_fields[ptitle] * len(self.psub_fields),
                                           columnspan=len(self.psub_fields),
                                           padx=0, pady=0, sticky="we")

            # print(len(self.psub_fields))

        for idx in range(0, len(self.ptitle_fields), 1):
            for psub in self.psub_fields:
                column=self.title_sub_start_column + self.psub_fields.index(psub) + idx * len(self.psub_fields)
                self.psubs["t"+psub+str(idx)] = tk.StringVar()
                self.psubs["t"+psub+str(idx)].set(psub)
                self.psubs["t_value"+psub+str(idx)] = ttk.Entry(self.pdframe,
                                                          textvariable=self.psubs["t"+psub+str(idx)],
                                                          state="readonly",
                                                          justify="center",
                                                          width=8,
                                                          background="lightblue")
                self.psubs["t_value"+psub+str(idx)].grid(row=self.pframe_start_row + 1, column=column, padx=0, pady=0, sticky="we")
                # print(idx, psub, column)

    def trigger_update_pframe_info(self, event):
        self.data_rows = 2
        
        info_trigger_value = self.wrinfo["value" + self.tirgger_pframe].get()
        if info_trigger_value.startswith("pshark://"):
            # print(info_trigger_value)
            rshark_toggle_pframe(self.pdframe, True)
            # self.ptitles["t_value_menu"].grid(row=self.pframe_start_row, column=self.pframe_start_col, rowspan=2, padx=1, pady=0, sticky="wens")
            # for ptitle in self.ptitle_fields:
            #     self.ptitles["t_value"+ptitle].grid(row=self.pframe_start_row,
            #                                    column=self.title_sub_start_column + self.ptitle_fields[ptitle] * len(self.psub_fields),
            #                                    columnspan=len(self.psub_fields),
            #                                    padx=1, pady=0, sticky="we")

            # for idx in range(0, len(self.ptitle_fields), 1):
            #     for psub in self.psub_fields:
            #         column=self.title_sub_start_column + self.psub_fields.index(psub) + idx * len(self.psub_fields)
            #         self.psubs["t_value"+psub+str(idx)].grid(row=self.data_rows, column=column, padx=1, pady=0, sticky="we")
        else:
            rshark_toggle_pframe(self.pdframe, False)

    def remove_mac_entry(self, event):
        for item in self.mac_entries:
            if item["rmb"] == event.widget:
                # button_x = item["rmb"].winfo_x()
                # button_y = item["rmb"].winfo_y()
                # print(button_x, event.x, item["rmb"].winfo_width())
                # print(button_y, event.y, item["rmb"].winfo_height())
                if 0 <= event.x <= item["rmb"].winfo_width() and 0 <= event.y <= item["rmb"].winfo_height():
                    event.widget.grid_forget()
                    item["maca"].grid_forget()
                    item["macb"].grid_forget()
                    self.mac_entry_pair.remove([item["maca", "macb"]])
                    self.mac_entries.remove(item)
                    self.add_mac_button.configure(state="active")
                    break

        if len(self.mac_entries) == 0:
            self.hide_mac_label1.grid_forget()
            self.hide_mac_label2.grid_forget()

    def add_mac_entry(self):
        self.hide_mac_label1.grid(row=self.mac_entry_start_row - 1, column=1, pady=5)#, sticky="we")
        self.hide_mac_label2.grid(row=self.mac_entry_start_row - 1, column=2, pady=5)#, sticky="we")
        remove_mac_button = ttk.Button(self.mframe, text="X", width=2)
        # remove_mac_button.bind("<Button-1>", self.remove_mac_entry)
        remove_mac_button.bind("<ButtonRelease>", self.remove_mac_entry)
        remove_mac_button.grid(row=len(self.mac_entries) + self.mac_entry_start_row, column=0, padx=self.widget_padx, pady=5, sticky="e")

        # mac_entry1 = ttk.Entry(self.mframe, width=20)
        mac_entry1 = ttk.Entry(self.mframe)
        mac_entry1.grid(row=len(self.mac_entries) + self.mac_entry_start_row, column=1, padx=self.widget_padx, pady=5,sticky="we")
        # mac_entry1.insert(0, "FF:FF:FF:FF:FF:FF")
        mac_entry1.insert(0, "c2:95:73:53:a5:5e")
        HoverInfo(mac_entry1, "'-' means any mac")
        # mac_entry2 = ttk.Entry(self.mframe, width=20)
        mac_entry2 = ttk.Entry(self.mframe)
        mac_entry2.grid(row=len(self.mac_entries) + self.mac_entry_start_row, column=2, padx=self.widget_padx, pady=5, sticky="we")
        # mac_entry2.insert(0, "FF:FF:FF:FF:FF:FF")
        mac_entry2.insert(0, "-")
        HoverInfo(mac_entry2, "'-' means any mac")

        self.mac_entries.append({"maca": mac_entry1, "macb": mac_entry2, "rmb": remove_mac_button})

        if (len(self.mac_entries) >= self.mac_entry_diff_rows):
            print("Max filter macs group added!")
            self.add_mac_button.configure(state="disabled")

        mp = [mac_entry1, mac_entry2]

        self.mac_entry_pair.append(mp)

        return mp

    def save(self):
        uinfo = self.get_user_input()
        info_trigger_value = self.wrinfo["value" + self.trigger_item].get()
        print(uinfo)
        print(info_trigger_value)
        # with open(clients_file, "r") as f:

    def get_user_input(self):
        found = False
        input = self.wrinfo["value" + self.trigger_item].get()
        self.rinfo = {}
        rinfo = {}
        for rinfo in self.rinfos:
            if rinfo[self.trigger_item] == input:
                found = True
                break

        if not found:
            self.rinfo = copy.deepcopy(self.rinfos[0])
        else:
            self.rinfo = copy.deepcopy(rinfo)

        for item in self.rinfo:
            input = self.wrinfo["value" + item].get().strip("\r").strip("\n")
            # print("value" + item + "--->" + input)
            self.rinfo[item] = input

        self.pmacs = {}
        for mac_entry_kit in self.mac_entries:
            maca = mac_entry_kit["maca"].get().lower().strip("\r").strip("\n").strip(" ").strip("")
            macb = mac_entry_kit["macb"].get().lower().strip("\r").strip("\n").strip(" ").strip("")

            if maca in self.pmacs:
                if macb in self.pmacs[maca]:
                    continue
                else:
                    self.pmacs[maca].append(macb)
            elif maca:
                self.pmacs[maca] = [macb]

            if macb in self.pmacs:
                if maca in self.pmacs[macb]:
                    continue
                else:
                    self.pmacs[macb].append(maca)
            elif macb:
                self.pmacs[macb] = [maca]

        self.rinfo["pmacs"] = self.pmacs

        return self.rinfo

    def gen_stats_menu_list(self, stats_list):
        stats = {}
        columc = 0
        for item in stats_list:
            # 创建一个 StringVar 用于绑定 Entry 的内容
            stats[item] = tk.StringVar()
            stats[item].set("")
            entry_item = ttk.Entry(self.mframe, textvariable=stats[item], state="readonly")
            entry_item.grid(row=self.rows, column=columc, padx=self.widget_padx, pady=5,  sticky="we")
            self.widgets_all.append(entry_item)
            columc += 1

        return stats

    def on_text_change(self, macs, *args):
        entry_width = len(self.data_boxs[macs].get())
        if macs+"v" in self.data_boxs:
            self.data_boxs[macs+"v"].config(width=entry_width)

    def update_data(self, d, rate_db):
        # print(d)
        # print(rate_db)
        # update xlabel(time)
        if self.pt_pre == 0:
            self.pt_list.append(0)
            self.pt_pre = time.time()
        else:
            cur_diff = time.time() - self.pt_pre
            # self.pt_list.append(round(cur_diff, 2))
            self.pt_list.append(ceil(cur_diff))
            # self.pt_pre = time.time()

        for mac1 in d:
            for mac2 in d[mac1]:
                # print(mac2)
                # print(mac1, "->", mac2, d[mac1][mac2])
                macs = (mac1 + mac2).replace(":", "")
                sdata = d[mac1][mac2]

                # self.ptitle_fields = {"data_mgmt": 0, "ack": 1, "rts": 2, "cts": 3}
                # self.psub_fields = ["rssi", "counts", "retry"]

                if not macs in self.data_boxs:
                    # print(data[mac1][mac2])
                    if self.data_rows > 30:
                        continue
                    self.data_boxs[macs] = tk.StringVar()
                    self.data_boxs[macs].trace_add("write", lambda *args: self.on_text_change(macs, *args))
                    self.data_boxs[macs].set(mac1+"->"+mac2)
                    self.data_boxs[macs + "v"] = ttk.Entry(self.pdframe, textvariable=self.data_boxs[macs], state="readonly", width=32)
                    self.data_boxs[macs + "v"].grid(row=self.data_rows, column=self.pframe_start_col, padx=0, pady=5, sticky="ew")
                    self.data_boxs[macs + "r"] = self.data_rows
                    self.data_rows = self.data_rows + 1

                self.push_retry_plot_data(mac1, mac2, sdata)

                # print(sdata)
                # for pkt_filed in sdata:
                for pkt_filed in self.ptitle_fields:
                    # print(pkt_filed)
                    rssiv = macs + "rssi" + pkt_filed
                    rssiv_column = self.title_sub_start_column + self.ptitle_fields[pkt_filed] * len(self.psub_fields) + self.psub_fields.index("rssi")
                    # print("rssiv colum: ", rssiv_column)

                    if rssiv in self.data_boxs:
                        if pkt_filed in sdata and int(sdata[pkt_filed]["rssi_cnt"]) != 0:
                            self.data_boxs[rssiv].set(round(int(sdata[pkt_filed]["rssi"]) / int(sdata[pkt_filed]["rssi_cnt"]), 2))
                    else:
                        self.data_boxs[rssiv] = tk.StringVar()
                        # self.data_boxs[rssiv].set(round(int(data[mac1][mac2]["rssi"]) / int(data[mac1][mac2]["rssi_cnt"]), 2))
                        if pkt_filed in sdata and int(sdata[pkt_filed]["rssi_cnt"]) != 0:
                            self.data_boxs[rssiv].set(round(int(sdata[pkt_filed]["rssi"]) / int(sdata[pkt_filed]["rssi_cnt"]), 2))
                        else:
                            self.data_boxs[rssiv].set("")
                        self.data_boxs[rssiv + "v"] = ttk.Entry(self.pdframe, textvariable=self.data_boxs[rssiv], state="readonly", width=8, justify="center")
                        self.data_boxs[rssiv + "v"].grid(row=self.data_boxs[macs + "r"], column=rssiv_column, padx=0, pady=5, sticky="ew")

                    cntv = macs + "cnts" + pkt_filed
                    cntv_column = self.title_sub_start_column + self.ptitle_fields[pkt_filed] * len(self.psub_fields) + self.psub_fields.index("cnt")
                    # print("cntv_column: ", cntv_column)

                    if cntv in self.data_boxs:
                        if pkt_filed in sdata: 
                            self.data_boxs[cntv].set(int(sdata[pkt_filed]["cnt"]))
                    else:
                        self.data_boxs[cntv] = tk.StringVar()
                        if pkt_filed in sdata: 
                            self.data_boxs[cntv].set(int(sdata[pkt_filed]["cnt"]))
                        else:
                            self.data_boxs[cntv].set("")

                        self.data_boxs[cntv + "v"] = ttk.Entry(self.pdframe, textvariable=self.data_boxs[cntv], state="readonly", width=8, justify="center")
                        self.data_boxs[cntv + "v"].grid(row=self.data_boxs[macs + "r"],
                                                        column=cntv_column, padx=0, pady=5, sticky="ew")

                    retryv = macs + "retry" + pkt_filed
                    retryv_column = self.title_sub_start_column + self.ptitle_fields[pkt_filed] * len(self.psub_fields) + self.psub_fields.index("retry")
                    # print("retryv_column: ", retryv_column)

                    if retryv in self.data_boxs:
                        if pkt_filed in sdata: 
                            self.data_boxs[retryv].set(int(sdata[pkt_filed]["retry"]))
                    else:
                        self.data_boxs[retryv] = tk.StringVar()
                        if pkt_filed in sdata: 
                            self.data_boxs[retryv].set(int(sdata[pkt_filed]["retry"]))
                        else:
                            self.data_boxs[retryv].set("")
                        self.data_boxs[retryv + "v"] = ttk.Entry(self.pdframe, textvariable=self.data_boxs[retryv], state="readonly", width=8, justify="center")
                        self.data_boxs[retryv + "v"].grid(row=self.data_boxs[macs + "r"],
                                                            column=retryv_column, padx=0, pady=5, sticky="ew")

        self.update_plot()

        prate_frame = self.pfframe["prate_retry_frame"]
        self.update_bar(self.pfframe["root"], prate_frame["canvas"], prate_frame["plot"], "retry", rate_db)
        prate_frame = self.pfframe["prate_frame"]
        self.update_bar(self.pfframe["root"], prate_frame["canvas"], prate_frame["plot"], "cnts", rate_db)

    def plot_color_handle(self, method):
        if method == "RESET":
            self.prc_list = [
                (1, 0.5, 0, 1),             # 橙色
                (1, 1, 0, 1),               # 黄色
                (0.5, 0, 0.5, 1),           # 紫色
                (1, 0, 1, 1),               # 品红
                (0, 1, 1, 1),               # 青色
                (0.647, 0.165, 0.165, 1),   # 棕色
                (0, 0, 0.7, 1)              # 深蓝色
                ]
        elif method == "GET":
            return self.prc_list.pop() if len(self.prc_list) > 0 else None
        else:
            return len(self.prc_list)

    def fig_on_scroll_event(self, event):
        # print(event)
        zoom_factor = 1.2 if event.step > 0 else 1 / 1.2
        x, y = event.xdata, event.ydata
        if not x or not y:
            return

        pretry_frame = self.pfframe["pretry_frame"]
        new_xlim = [x - (x - pretry_frame["plot"].get_xlim()[0]) / zoom_factor,
                    x + (pretry_frame["plot"].get_xlim()[1] - x) / zoom_factor]
        new_ylim = [y - (y - pretry_frame["plot"].get_ylim()[0]) / zoom_factor,
                    y + (pretry_frame["plot"].get_ylim()[1] - y) / zoom_factor]
        pretry_frame["plot"].set_xlim(new_xlim)
        pretry_frame["plot"].set_ylim(new_ylim)

        # 重新绘制图形
        pretry_frame["canvas"].draw()

    def update_plot(self):
        # print(self.pr_list)
        pretry_frame = self.pfframe["pretry_frame"]
        pretry_frame["plot"].clear()
        for item in self.pr_list:
            # print(item, self.pr_list[item]["pdata"])
            # 清除当前图形并绘制新数据
            # pretry_frame["plot"].plot(self.pt_list, self.pr_list[item]["pdata"], c=self.pr_list[item]["color"], ls='-', marker='.', mec='b', mfc='w', label=item)
            pretry_frame["plot"].plot(self.pt_list, self.pr_list[item]["pdata"], c=self.pr_list[item]["color"], label=item)
            pretry_frame["plot"].set_title('Retry Counts Tendency Chart')
            pretry_frame["plot"].set_xlabel('time(s)')
            pretry_frame["plot"].set_ylabel('cnts(pkt)')
            pretry_frame["plot"].legend()

        # 在 Canvas 上重新绘制
        pretry_frame["canvas"].draw()
        self.pfframe["root"].update()
        # 在鼠标悬停时显示坐标值
        # mplcursors.cursor(hover=True)

    def push_retry_plot_data(self, mac1, mac2, data_info):
        '''
        plot data retry except mgmt, ctrol frame etc.
        '''
        # print(mac1, mac2)
        if not "data" in data_info:
            return

        if len(self.pt_list) == 0:
            return

        d = data_info["data"]

        if mac1.lower() == "none" or mac2.lower() == "none":
            return

        target = mac1.replace(":","")+"->"+mac2.replace(":","")
        # print(time.time(), target, data_info)

        # if not "plot" in self.pfframe:

        # print(target, self.pt_list, self.pr_list[target]["pdata"] if target in self.pr_list else "NEW")

        if not target in self.pr_list:
            if self.plot_color_handle(None) == 0:
                return

            pdata =  [0] * (len(self.pt_list) - 1)
            self.pr_list[target] = {}
            self.pr_list[target]["pdata"] = pdata
            self.pr_list[target]["color"] = self.plot_color_handle("GET")

        # print(target, self.pt_list, self.pr_list[target]["pdata"])

        # print(self.pt_list, self.pr_list)
        self.pr_list[target]["pdata"].append(d["retry"])
        # print(target, self.pt_list, self.pr_list[target]["pdata"])

    def update_bar(self, root, canvas, bar_ax, field, d):
        # 清空原有的图表数据
        bar_ax.clear()

        # 绘制两组柱状图，调整第二组柱状图的位置
        bar_width = 0.1
        categories = list(d.keys())
        bar_positions = range(len(categories))

        # list(set(list(a.keys()) + list(b.keys()))) 利用set去重
        macs_list = []

        for category in d:
            macs_list = macs_list + list(d[category].keys())

        # get all mac_pair group
        macs_list = list(set(macs_list))

        # {mac1mac2:[0(1mbps), 1(2mbps), 0, ...]}
        mac_rates_dict = {}
        for mac in macs_list:
            mac_rates_dict[mac] = [ 0 for _ in range(0, len(categories))]
            for category in d:
                if mac in d[category]:
                    mac_rates_dict[mac][categories.index(category)] = d[category][mac][field]
        
        mac_rates_mac_list = list(mac_rates_dict.keys())

        bars = []
        for mac in mac_rates_mac_list:
            i = mac_rates_mac_list.index(mac)
            bars.append(bar_ax.bar([j + i * bar_width for j in bar_positions], mac_rates_dict[mac], width=bar_width, label=mac, align='edge'))

        # 添加图例
        bar_ax.legend()

        # 设置横坐标刻度和标签
        bar_ax.set_xticks([i + (len(mac_rates_mac_list) - 1) * bar_width/2 for i in bar_positions])
        bar_ax.set_xticklabels(categories)

        # 在每个柱形上方添加具体值
        for _, group_bars in enumerate(bars):
            for bar in group_bars:
                yval = bar.get_height()
                bar_ax.text(bar.get_x() + bar.get_width()/2, yval, round(yval, 2), ha='center', va='bottom')


        # 配置 mplcursors
        cursor = mplcursors.cursor(hover=True)

        # # 在悬停时显示注释
        # @cursor.connect("add")
        # def on_add(sel):
        #     ind = sel.target.index
        #     x_val, y_val = line.get_data()
        #     label = f'Point {ind}: ({x_val[ind]:.2f}, {y_val[ind]:.2f})'
        #     sel.annotation.set_text(label)

        canvas.draw()
        root.update()

    def start_run(self):
        self.start_client()

    def start_client(self):
        if self.running:
            print("Already is running and please stop first!")
            messagebox.showinfo("Information", "Already is running and please stop first!")
            return

        self.client_button.configure(state="disabled")
        self.stop_button.configure(state="active")

        for item in self.data_boxs:
            if item + "v" in self.data_boxs:
                self.data_boxs[item + "v"].grid_forget()

        del self.data_boxs
        self.data_boxs = {}
        self.data_rows = 2

        self.stop_event.clear()
        if self.check_box_enable_iperf.get() == 1:
            self.client_thread = threading.Thread(target=self.run_client)
        self.pshark_thread = threading.Thread(target=self.run_pshark)
        self.running = True
        if self.check_box_enable_iperf.get() == 1:
            self.client_thread.start()
        self.pshark_thread.start()

    def run_pshark(self):
        msgbox_info = self.get_user_input()
        # print("---------------------><", msgbox_info)

        # print(msgbox_info)
        self.sharkd = rshark.Rshark(msgbox_info["type"],
                                    msgbox_info["ip"],
                                    msgbox_info["port"],
                                    msgbox_info["user"],
                                    msgbox_info["password"],
                                    msgbox_info["stores"],
                                    msgbox_info["interface"],
                                    msgbox_info["channel"],
                                    None,
                                    10,
                                    msgbox_info["pmacs"])
        sub_args = {"cb": self.update_data, "eloop": self.event_loop, "stores": msgbox_info["stores"]}
        self.sharkd.rshark_set_pshark_cb(sub_args)
        self.sharkd.rshark_sniffer()

    def run_client(self):
        # sniffer has to be started first
        while not hasattr(self, "sharkd") or not self.sharkd.input_running:
            time.sleep(0.1)

        print("Ready to send pkts...")
        ip = self.ip_entry.get()
        port = int(self.port_entry.get())
        rate = self.rate_select.get().strip("bps")

        client = NetTestClient(ip, port, rate, self.stats,self.protocol_var.get(), self.stop_event)

        client.start()

    def stop(self):
        if not self.running:
            return

        self.stop_event.set()
        # self.sharkd.rshark_store_pyshark_async_parse()
        self.sharkd.rshark_force_exit()
        self.running = False

        self.client_button.configure(state="active")
        self.stop_button.configure(state="disabled")

        self.pt_pre = 0
        self.pt_list = []
        self.pr_list = {}
        self.prc_list = []
        self.plot_color_handle("RESET")

    def __del__(self):
        self.running = False

class NetTestClient:
    def __init__(self, host, port, rate, widget, protocol, stop_event=None):
        self.host = host
        self.port = port
        self.rate = rate # 隔多少us发送一包
        self.stop_event = stop_event
        self.total_tx_cnts = 0
        self.stats = widget
        self.protocol = protocol
        self.start_time = 0

    def start(self):
        print(f"UDP Client sending to {self.host}:{self.port}. Starting bandwidth test.")
        # self.client_socket.sendto(data, (self.host, self.port))
        # print(self.rate)

        start_time = time.time()

        cmd = [IPERF_PATH]
        cmd.append("-c")
        cmd.append(str(self.host))
        cmd.append("-p")
        cmd.append(str(self.port))

        if self.protocol == "UDP":
            cmd.append("-u")

        cmd.append("-i")
        cmd.append("1")
        cmd.append("-t")
        cmd.append("10000000")
        cmd.append("-b")
        cmd.append(self.rate.replace(" ", ""))

        # print(cmd)
        try:
            self.cmd_handle = subprocess.Popen(cmd, stdout=subprocess.PIPE)

            while not self.stop_event.is_set():
                result = r"{}".format(self.cmd_handle.stdout.readline().decode("gbk").strip("\r\n "))
                # print(result)
                if not result.startswith("["):
                    continue

                if len(str(result).split(" sec")) < 2:
                    continue

                if self.start_time == 0:
                    self.start_time = time.time()

                nB = result.lower().split(" sec")[1].split("bytes")[0].strip(" ")
                # print("nB......", nB)
                rm = {"m": 1e6, "k":1e3, "g": 1e9, "d": 1}
                nBs = nB.split(" ")
                rv = nBs[0]
                if len(nBs) > 1:
                    ru = nBs[1]
                else:
                    ru = "d"
                # print(ru)
                # print(rv)
                if ru in rm:
                    self.total_tx_cnts = float(rv) * rm[ru] + self.total_tx_cnts
                else:
                    self.total_tx_cnts = int(rv) + self.total_tx_cnts

                self.stats["tx_rate"].set(str(result).split("Bytes")[1].strip(" "))
                self.stats["tx_cnts"].set(str(self.total_tx_cnts))
                self.stats["running_time"].set("{:.2f} s".format(round(time.time() - self.start_time), 2))

            print("Stop event captured in TG!")
            self.cmd_handle.kill()
            self.cmd_handle.communicate()
            self.cmd_handle.terminate()
            self.cmd_handle.wait(5)
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
        # messagebox.showerror("Connection Error", "Failed to connect to the server. Make sure the server is running.")

def rshark_toggle_pframe(pframe, pshow=False):
    parent = pframe.winfo_parent()
    parent = root.nametowidget(parent).winfo_parent()
    parent = root.nametowidget(parent)
    if pshow:
        # root.maxsize(width=gwidth, height=gheight + 10) 
        # root.minsize(width=gwidth, height=gheight + 10)
        parent.grid(row=0, column=1, padx=5, pady=0, sticky="wen")
        # root.geometry(str(gwidth)+"x"+str(gheight))
        # print("this is set show->", parent)

        # root.maxsize(width=gwidth, height=gheight + 10) 
        # root.minsize(width=gwidth, height=gheight + 10)
        notebook.grid(row=1, column=1, padx=0, pady=0, sticky="wen")
    else:
        # print("this is set disshow->", parent)
        # root.maxsize(width=gwidth_min, height=gheight_min + 10) 
        # root.minsize(width=gwidth_min, height=gheight_min + 10)
        parent.grid_forget()
        notebook.grid_forget()

    root.update()
    pframe.update()

def rshark_main():
    right_left_size = gwidth - 570

    # root.maxsize(width=gwidth_min, height=gheight_min + 10) 
    # root.minsize(width=gwidth_min, height=gheight_min + 10)

    root.resizable(False, False)

    root.title("Wi-Fi T/RX Analysis")

    # mframe = ttk.Frame(master=root, borderwidth=0, relief="solid", height=gheight, border=0)
    mframe = ttk.Frame(master=root, borderwidth=0, height=gheight, border=0)
    mframe.grid(row=0, column=0, rowspan=2, padx=5, pady=0, sticky="wen")

    # parse data frame
    # pdframe = tk.Frame(master=ppframe, borderwidth=1, relief="solid", height=gheight / 2)
    pdframe = ttk.Frame(master=root, borderwidth=1, relief="solid", width=right_left_size, height=gheight / 2)
    pdframe.grid(row=0, column=1, padx=0, pady=0, sticky="wen")

    # 必须放在frame声明grid之前，否则notebook会覆盖frame
    # notebook = ttk.Notebook(root)
    notebook.grid(row=1, column=1, padx=0, pady=0, sticky="wen")

    # parse frame(parse retry frame, parse rate cnt frame, parse rate retry frame)
    # parse retry frame
    pretry_frame = ttk.Frame(master=root, borderwidth=0, relief="solid", width=right_left_size, height=gheight / 2)
    pretry_frame.grid(row=1, column=1, padx=0, pady=0, sticky="wen")

    # parse rate cnt frame
    prate_cnt_frame = ttk.Frame(master=root, borderwidth=0, relief="solid", width=right_left_size, height=gheight / 2)
    prate_cnt_frame .grid(row=1, column=1, padx=0, pady=0, sticky="wen")

    # parse rate retry frame
    prate_retry_frame = ttk.Frame(master=root, borderwidth=0, relief="solid", width=right_left_size, height=gheight / 2)
    prate_retry_frame .grid(row=1, column=1, padx=0, pady=0, sticky="wen")

    # -----------------------------------------pdframe------------------------------------------
    # 接下来为数据分析窗口(pframe)创建画布，以方便实现滚动条
    # 画布上面创建内侧窗口(interior frame)，并将内侧窗口附着在画布上新创建的窗体(create_window)上
    # 最后将滚动条通过画布的configure方法添加至画布
    pdframe_canvas = tk.Canvas(pdframe, borderwidth=0, highlightthickness=0, width=right_left_size, height=(gheight + 6) / 2)
    pdframe_canvas.grid(row=0, column=1, padx=0, pady=0, sticky="wen")

    pdframe_canvas_scrollbar = ttk.Scrollbar(pdframe, orient="vertical", command=pdframe_canvas.yview)
    pdframe_canvas_scrollbar.grid(row=0, column=2, sticky="ns")

    pdframe_canvas.configure(yscrollcommand=pdframe_canvas_scrollbar.set)

    pdframe_interior_frame = ttk.Frame(pdframe_canvas)
    pdframe_canvas.create_window((0, 0), window=pdframe_interior_frame, anchor="nw")

    def update_scroll_region(event):
        pdframe_canvas.configure(scrollregion=pdframe_canvas.bbox("all"))

    pdframe_interior_frame.bind("<Configure>", update_scroll_region)
    # pdframe_canvas.bind("<Configure>", update_scroll_region)

    # -----------------------------------------pretry_frame------------------------------------------
    pretry_frame.update()
    pretry_frame_fig = Figure(figsize=(pretry_frame.winfo_width()/100, pretry_frame.winfo_height()/100), dpi=100)

    # (left, bottom, width, height)
    pretry_frame_ax = pretry_frame_fig.add_axes([0.07, 0.15, 0.9, 0.8])

    # 将 matplotlib 图形嵌入到 tkinter 窗口中
    pretry_frame_canvas = FigureCanvasTkAgg(pretry_frame_fig, master=pretry_frame)   
    pretry_frame_canvas.draw()
    # pretry_frame_canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)
    pretry_frame_canvas.get_tk_widget().grid(padx=0, pady=0, sticky="wens")

    # -----------------------------------------prate_cnt_frame------------------------------------------
    prate_cnt_frame.update()
    prate_frame_fig = Figure(figsize=(prate_cnt_frame.winfo_width()/100, prate_cnt_frame.winfo_height()/100), dpi=100)

    # (left, bottom, width, height)
    prate_frame_ax = prate_frame_fig.add_axes([0.07, 0.15, 0.9, 0.8])
    # 使用 bar 函数绘制柱状图
    # prframe_ax.bar(categories, values, color='blue')

    # 将 matplotlib 图形嵌入到 tkinter 窗口中
    prate_frame_canvas = FigureCanvasTkAgg(prate_frame_fig, master=prate_cnt_frame)
    prate_frame_canvas.draw()
    # pretry_frame_canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)
    prate_frame_canvas.get_tk_widget().grid(padx=0, pady=0, sticky="wens")

    # -----------------------------------------prate_retry_frame------------------------------------------
    prate_retry_frame.update()
    prate_retry_frame_fig = Figure(figsize=(prate_retry_frame.winfo_width()/100, prate_retry_frame.winfo_height()/100), dpi=100)

    # (left, bottom, width, height)
    prate_retry_frame_ax = prate_retry_frame_fig.add_axes([0.07, 0.15, 0.9, 0.8])
    # 使用 bar 函数绘制柱状图
    # prframe_ax.bar(categories, values, color='blue')

    # 将 matplotlib 图形嵌入到 tkinter 窗口中
    prate_retry_frame_canvas = FigureCanvasTkAgg(prate_retry_frame_fig, master=prate_retry_frame)
    prate_retry_frame_canvas.draw()
    prate_retry_frame_canvas.get_tk_widget().grid(padx=0, pady=0, sticky="wens")


    pframe_info = {"root":root,
                    "pretry_frame": {
                        "frame": pretry_frame,
                        "plot": pretry_frame_ax,
                        "canvas": pretry_frame_canvas
                     },
                     "prate_frame":{
                        "frame": prate_cnt_frame,
                        "plot": prate_frame_ax,
                        "canvas": prate_frame_canvas
                     },
                     "prate_retry_frame":{
                        "frame": prate_retry_frame,
                        "plot": prate_retry_frame_ax,
                        "canvas": prate_retry_frame_canvas
                     },
                     }

    notebook.add(pretry_frame, text="RetryTrend")
    notebook.add(prate_cnt_frame, text="RateCounts")
    notebook.add(prate_retry_frame, text="RateRetry")

    ntg = NetworkTestGUI(mframe, pdframe_interior_frame, pframe_info)

    pretry_frame_fig.canvas.mpl_connect('scroll_event', ntg.fig_on_scroll_event)
    # pfframe_fig.canvas.mpl_connect('button_press_event', ntg.fig_on_scroll_event)
    # 在鼠标悬停时显示坐标值
    # mplcursors.cursor(hover=True)



    # ntg.update_plot()
    rshark_toggle_pframe(pdframe_interior_frame, False)

    root.mainloop()

if __name__ == "__main__":
    #https://docs.python.org/zh-cn/3/library/argparse.html
    parse = argparse.ArgumentParser(description="Start sniffer with cli, target(openwrt) configure file can be store to openwrt/wireless or use inner static file")
    parse.add_argument("--conf", help="path to the config file", required=False, type=str)

    parse.add_argument("-u", "--user", help="remote sniffer host user name to login", required=False, type=str)
    parse.add_argument("-p", "--password", help="remote sniffer host password to login", required=False, type=str)
    parse.add_argument("-i", "--interface", help="wireless interface of remote sniffer host to use", required=False, type=str)
    parse.add_argument("-c", "--channel", help="wireless channel of remote sniffer host to use", required=False, type=int)
    parse.add_argument("--ip", help="remote sniffer host ip address", required=False, type=str)
    parse.add_argument("--port", help="remote sniffer host ssh port", required=False, default="22", type=str)
    parse.add_argument("--type", help="the type of remote target host, default: openwrt", choices=["openwrt", "ubuntu"], required=False, type=str)
    parse.add_argument("--dst", help="where to store the sniffer log, show start with: local://yourpath OR wireshark://.", default="wireshark://.", required=False, type=str)
    parse.add_argument("--macs", help="mac list with \',\' splited to filter the target", required=False, type=str)
    parse.add_argument("--timeout", help="time to wait for the remote host reponse(10s)", required=False, default=10, type=int)

    args = parse.parse_args()

    if (args.ip and args.type and args.user and args.password and args.dst and args.interface and args.channel):
        shark = rshark.Rshark(args.type, args.ip, args.port, args.user, args.password, args.dst, args.interface, args.channel, args.macs, args.timeout, None)
        shark.rshark_sniffer()
    elif args.conf and os.path.exists(args.conf):
        rshark.rshark_from_conf(args.conf, None)
        for item in rshark.conf_hosts:
            if item["usetunnel"]:
                args.ip = item["ip"]
                break

        if not args.ip:
            print("ERROR! remote ip address required and not configure file found!")
        else:
            print("WARNING! remote ip address required, use first one {}!".format(args.ip))
        shark = rshark.Rshark(args.type, args.ip, args.port, args.user, args.password, args.dst, args.interface, args.channel, args.macs, args.timeout, None)
        shark.rshark_sniffer()
    else:
        rshark_main()