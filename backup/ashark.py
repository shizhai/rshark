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

os_platform = sys.platform.lower()

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

        label = tk.Label(self.tooltip, text=self.text, background="#ffffe0", relief="solid", borderwidth=1)
        label.pack(ipadx=1)

    def hide_tooltip(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
        self.tooltip = None

class SnifferWin:
    def __init__(self, root, trigger_item, start_rows, rinfos):
        self.root = root
        self.pframe = pframe
        self.wrinfo = {}
        self.rinfos = rinfos
        self.rinfo = {}
        self.trigger_item = trigger_item
        self.start_row = start_rows
        self.rows = start_rows
        # self.rows = 0
        self.diff_rows = 0
        self.mac_entries = []
        self.pmacs = {}
        # self.root.title("Info to Rshark")

        first_info = self.rinfos[0]
        for item in first_info:
            if type(first_info[item]) == list:
                self.wrinfo["label" + item] = tk.Label(self.root, text=item + ": ", width=20)
                self.wrinfo["value" + item] = ttk.Combobox(self.root, width=20)
                self.wrinfo["value" + item]["value"] = first_info[item]
                self.wrinfo["value" + item].current(0)
            elif item == self.trigger_item:
                self.wrinfo["label" + item] = tk.Label(self.root, text=item + ": ", width=20)
                self.wrinfo["value" + item] = ttk.Combobox(self.root, width=20)
                info_trigger_items = []
                for item_each in self.rinfos:
                    info_trigger_items.append(item_each[self.trigger_item])

                self.wrinfo["value" + item]["value"] = info_trigger_items
                self.wrinfo["value" + item].current(0)
                self.wrinfo["value" + item].bind('<<ComboboxSelected>>', self.trigger_update_info)
            else:
                self.wrinfo["label" + item] = tk.Label(self.root, text=item + ": ", width=20)
                self.wrinfo["value" + item] = tk.Entry(self.root, width=20)
                self.wrinfo["value" + item].insert(0, first_info[item])

            self.wrinfo["label" + item].grid(row=self.rows, column=0, sticky="e", padx=10, pady=5)
            self.wrinfo["value" + item].grid(row=self.rows, column=1, sticky="w", padx=10, pady=5)
            _hide = tk.Label(self.root, text="", width=20)
            _hide.grid(row=len(self.mac_entries) + self.rows, column=2, sticky="w", padx=10, pady=5)
            self.rows = self.rows+ 1

        self.diff_rows = self.rows - self.start_row

        # 添加 "添加MAC地址" 按钮
        self.add_mac_button = tk.Button(self.root, text="Add MAC Group", command=self.add_mac_entry, width=15)
        self.add_mac_button.grid(row=self.rows, column=0, padx=10, pady=5, sticky="we")
        # self.add_mac_button.grid_forget()
        hide_mac_label1 = tk.Label(self.root, text="Addr.A", width=20)
        hide_mac_label1.grid(row=self.rows, column=1, sticky="we", padx=10, pady=5)
        hide_mac_label2 = tk.Label(self.root, text="Addr.B", width=20)
        hide_mac_label2.grid(row=self.rows, column=2, sticky="we", padx=10, pady=5)
        self.rows = self.rows+ 1

        self.root.update()

    def trigger_update_info(self, event):
        info_trigger_value = self.wrinfo["value" + self.trigger_item].get()
        for rinfo in self.rinfos:
            if rinfo[self.trigger_item] == info_trigger_value:
                for item in rinfo:
                    if type(rinfo[item]) == list:
                        self.wrinfo["value" + item]["value"] = []
                        self.wrinfo["value" + item]["value"] = rinfo[item]
                        self.wrinfo["value" + item].current(0)
                        self.root.update()
                    else:
                        self.wrinfo["value" + item].delete(0, 'end')
                        self.wrinfo["value" + item].insert(0, rinfo[item])
                break

    def remove_mac_entry(self, event):
        for item in self.mac_entries:
            if item["rmb"] == event.widget:
                event.widget.grid_forget()
                item["maca"].grid_forget()
                item["macb"].grid_forget()
                # self.rows = self.rows - 1
                self.mac_entries.remove(item)
                self.add_mac_button.configure(state="active")
                return

    def add_mac_entry(self):
        men = self.diff_rows if self.diff_rows < 3 else 3

        remove_mac_button = tk.Button(self.root, text="X", width=2)
        remove_mac_button.bind("<Button-1>", self.remove_mac_entry)
        remove_mac_button.grid(row=len(self.mac_entries) + self.rows, column=0, padx=10, pady=5, sticky="e")

        mac_entry1 = tk.Entry(self.root, width=20)
        mac_entry1.grid(row=len(self.mac_entries) + self.rows, column=1, padx=10, pady=5,sticky="we")
        # mac_entry1.insert(0, "FF:FF:FF:FF:FF:FF")
        mac_entry1.insert(0, "c2:95:73:53:a5:5e")
        HoverInfo(mac_entry1, "'-' means any mac")
        mac_entry2 = tk.Entry(self.root, width=20)
        mac_entry2.grid(row=len(self.mac_entries) + self.rows, column=2, padx=10, pady=5, sticky="we")
        # mac_entry2.insert(0, "FF:FF:FF:FF:FF:FF")
        mac_entry2.insert(0, "-")
        HoverInfo(mac_entry2, "'-' means any mac")

        self.mac_entries.append({"maca": mac_entry1, "macb": mac_entry2, "rmb": remove_mac_button})

        if (len(self.mac_entries) >= men):
            print("Max filter macs group added!")
            self.add_mac_button.configure(state="disabled")
            return

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

        # print("testtttttttttttttttttttttttttt_start")
        # print(input)
        # print(self.rinfos)
        # print(self.rinfo)
        # print("testtttttttttttttttttttttttttt_end")

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


class NetworkTestGUI:
    def __init__(self, mfrmae, pframe):
        self.running = False
        self.parse_on_time = True
        self.event_loop = asyncio.get_event_loop()
        self.client_thread = None
        self.pshark_thread = None
        self.root = mframe
        self.rows = 0
        # self.root.title("Network Performance Test")
        self.data_boxs={}

        # self.pmain_fields = {"data": 0, "mgmt": 1, "ack": 2, "rts": 3, "cts": 4, "ps-poll": 5, "ba": 6, "ba_req": 7}
        # self.ptitle_fields = {"data": 0, "mgmt": 1, "ack": 2, "rts": 3, "cts": 4}
        # self.psub_fields = ["src->dst", "rssi", "counts", "retry"]
        self.ptitle_fields = {"data": 0, "ack": 1, "rts": 2, "cts": 3}
        self.psub_fields = ["rssi", "cnt", "retry"]

        # 停止标志
        self.stop_event = threading.Event()

        self.content_label = tk.Label(self.root, text="/ " * 20 + "Iperf Info" + " /" * 20)
        self.content_label.grid(row=self.rows, column=0, columnspan=3, padx=5, pady=0, sticky="we")
        self.rows = self.rows + 1

        # IP 输入框和标签
        self.ip_label = tk.Label(self.root, text="IP Address:")
        self.ip_label.grid(row=self.rows, column=0, padx=5, pady=0, sticky="e")
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.insert(0, "192.168.1.102")
        self.ip_entry.grid(row=self.rows, column=1, padx=5, pady=0, sticky="w")
        self.rows = self.rows + 1

        # self.data_frame = ScrollableFrame(self.root)
        # self.data_frame.grid(row = self.rows, column=3, columnspan= len(self.ptitle_fields) * len(self.psub_fields) + 2, padx=0, pady=0, sticky="we")
        self.data_frame = pframe

        # self.pframe_start_row = 0
        # self.pframe_start_col = 3
        self.pframe_start_row = 0
        self.pframe_start_col = 0
        self.title_sub_start_column = self.pframe_start_col + 1
        self.data_rows = self.pframe_start_row

        ptitles = {}
        ptitles["tmenu"] = tk.StringVar()
        ptitles["tmenu"].set("src-->dst")
        ptitles["t_value_menu"] = tk.Entry(self.data_frame, textvariable=ptitles["tmenu"], state="readonly", justify="center")
        ptitles["t_value_menu"].grid(row=self.pframe_start_row, column=self.pframe_start_col, rowspan=2, padx=1, pady=0, sticky="we")

        if self.parse_on_time:
            ptitles = {}
            for ptitle in self.ptitle_fields:
                ptitles["t"+ptitle] = tk.StringVar()
                ptitles["t"+ptitle].set(ptitle)
                ptitles["t_value"+ptitle] = tk.Entry(self.data_frame,
                                                     textvariable=ptitles["t"+ptitle],
                                                     state="readonly",
                                                     justify="center",
                                                     width=8)
                ptitles["t_value"+ptitle].grid(row=self.pframe_start_row,
                                               column=self.title_sub_start_column + self.ptitle_fields[ptitle] * len(self.psub_fields),
                                               columnspan=len(self.psub_fields),
                                               padx=1, pady=0, sticky="we")

                # print(len(self.psub_fields))

            self.data_rows = self.data_rows + 1

            psubs = {}
            for idx in range(0, len(self.psub_fields) + 1, 1):
                for psub in self.psub_fields:
                    column=self.title_sub_start_column + self.psub_fields.index(psub) + idx * len(self.psub_fields)
                    psubs["t"+psub+str(idx)] = tk.StringVar()
                    psubs["t"+psub+str(idx)].set(psub)
                    psubs["t_value"+psub+str(idx)] = tk.Entry(self.data_frame,
                                                              textvariable=psubs["t"+psub+str(idx)],
                                                              state="readonly",
                                                              justify="center",
                                                              width=8)
                    psubs["t_value"+psub+str(idx)].grid(row=self.data_rows, column=column, padx=1, pady=0, sticky="we")
                    # print(idx, psub, column)

            self.data_rows = self.data_rows + 1
            # print(self.data_rows)

        # Port 输入框和标签
        self.port_label = tk.Label(self.root, text="Port:")
        self.port_label.grid(row=self.rows, column=0, padx=5, pady=5, sticky="e")
        self.port_entry = tk.Entry(self.root)
        self.port_entry.insert(0, "5001")
        self.port_entry.grid(row=self.rows, column=1, padx=5, pady=5, sticky="w")
        self.rows = self.rows + 1

        # Protocol 输入框和标签
        self.protocol_label = tk.Label(self.root, text="Protocol:")
        self.protocol_label.grid(row=self.rows, column=0, padx=5, pady=5, sticky="e")
        self.protocol_var = tk.StringVar()
        self.protocol_var.set("UDP")
        self.protocol_menu = tk.OptionMenu(self.root, self.protocol_var, "TCP", "UDP")
        self.protocol_menu.grid(row=self.rows, column=1, padx=5, pady=5, sticky="w")
        self.rows = self.rows + 1

        # 发送速率选择
        self.rate_label = tk.Label(self.root, text="Rate:")
        self.rate_label.grid(row=self.rows, column=0, padx=5, pady=5, sticky="e")
        self.rate_select = ttk.Combobox(self.root)
        self.rate_select["value"] = [ str(v) + " Mbps" for v in range(5, 80, 5) ]
        self.rate_select.current(4)
        self.rate_select.grid(row=self.rows, column=1, padx=5, pady=5, sticky="w")
        self.rows = self.rows + 1
        # self.rate_select.bind('<<ComboboxSelected>>', self.trigger_show_mac_button)

        self.check_box_enable_iperf = tk.IntVar()
        self.check_box_enable_iperf_w = tk.Checkbutton(self.root, text = "Enable Iperf",
                                                       variable = self.check_box_enable_iperf, onvalue = 1, offvalue = 0, width = 20)
        self.check_box_enable_iperf_w.grid(row=self.rows, column=1, padx=5, pady=5, sticky="we")
        self.rows = self.rows + 1

        self.content_label = tk.Label(self.root, text="/ " * 20 + "Sniffer Info" + " /" * 20)
        self.content_label.grid(row=self.rows, column=0, columnspan=3, padx=5, pady=5, sticky="we")
        self.rows = self.rows + 1

        hosts_out = []
        rshark.rshark_from_conf("./clients", hosts_out=hosts_out)
        # print(hosts_out)
        # msgbox_info = rshark_msgbox_info() 
        rinfos = []
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
            rinfos.append(rinfo)

        # rinfo = {"user": "root", "password": "12345678", "ip": "10.17.7.28", "port": "22", "channel": list(range(1, 13)), "interface": "wlan0mon",
        #          "type": ["ubuntu", "openwrt"], "stores":["pshark://."]}
        self.sw = SnifferWin(self.root, "ip", self.rows, rinfos)
        # print("cur rows {}, {}".format(self.rows, self.sw.rows))
        self.rows = self.rows + self.sw.rows

        self.client_button = tk.Button(self.root, text="Start", command=self.start_run, width=15)
        self.client_button.grid(row=self.rows, column=0, padx=10, pady = 5, sticky="we")
        self.rows = self.rows + 1

        # 停止按钮
        self.stop_button = tk.Button(self.root, text="Stop", command=self.stop, width=15)
        self.stop_button.grid(row=self.rows, column=0, padx=10, pady=5, sticky="we")
        self.rows = self.rows + 1

        # print("cur rows {}".format(self.rows))
        # 统计
        stats_list = ["tx_rate", "tx_cnts", "running_time"]
        self.stats = self.gen_stats_menu_list(stats_list)
        self.root.update()
        self.root.update_idletasks()

    def gen_stats_menu_list(self, stats_list):
        stats = {}
        for item in stats_list:
            # 创建一个 StringVar 用于绑定 Entry 的内容
            stats[item] = tk.StringVar()
            stats[item].set("")
            entry_item = tk.Entry(self.root, textvariable=stats[item], state="readonly", width=15)
            entry_item.grid(row=self.rows, column=0, padx=10, pady=5, sticky="we")
            self.rows = self.rows + 1

        return stats

    def on_text_change(self, macs, *args):
        entry_width = len(self.data_boxs[macs].get())
        if macs+"v" in self.data_boxs:
            self.data_boxs[macs+"v"].config(width=entry_width)

    def update_data(self, d):
        # print(d)
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
                    if self.data_rows > 100:
                        continue
                    self.data_boxs[macs] = tk.StringVar()
                    self.data_boxs[macs].trace_add("write", lambda *args: self.on_text_change(macs, *args))
                    self.data_boxs[macs].set(mac1+"->"+mac2)
                    self.data_boxs[macs + "v"] = tk.Entry(self.data_frame, textvariable=self.data_boxs[macs], state="readonly", width=32)
                    self.data_boxs[macs + "v"].grid(row=self.data_rows, column=self.pframe_start_col, padx=1, pady=5, sticky="ew")
                    self.data_boxs[macs + "r"] = self.data_rows
                    self.data_rows = self.data_rows + 1

                # print(sdata)
                # for pkt_filed in sdata:
                for pkt_filed in self.ptitle_fields:
                    # print(pkt_filed)
                    rssiv = macs + "rssi" + pkt_filed
                    rssiv_column = self.title_sub_start_column + self.ptitle_fields[pkt_filed] * (len(self.ptitle_fields) - 1) + self.psub_fields.index("rssi")
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
                        self.data_boxs[rssiv + "v"] = tk.Entry(self.data_frame, textvariable=self.data_boxs[rssiv], state="readonly", width=8, justify="center")
                        self.data_boxs[rssiv + "v"].grid(row=self.data_boxs[macs + "r"], column=rssiv_column, padx=1, pady=5, sticky="ew")


                    cntv = macs + "cnts" + pkt_filed
                    cntv_column = self.title_sub_start_column + self.ptitle_fields[pkt_filed] * (len(self.ptitle_fields) - 1)+ self.psub_fields.index("cnt")
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

                        self.data_boxs[cntv + "v"] = tk.Entry(self.data_frame, textvariable=self.data_boxs[cntv], state="readonly", width=8, justify="center")
                        self.data_boxs[cntv + "v"].grid(row=self.data_boxs[macs + "r"],
                                                        column=cntv_column, padx=1, pady=5, sticky="ew")

                    retryv = macs + "retry" + pkt_filed
                    retryv_column = self.title_sub_start_column + self.ptitle_fields[pkt_filed] * (len(self.ptitle_fields) - 1) + self.psub_fields.index("retry")
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
                        self.data_boxs[retryv + "v"] = tk.Entry(self.data_frame, textvariable=self.data_boxs[retryv], state="readonly", width=8, justify="center")
                        self.data_boxs[retryv + "v"].grid(row=self.data_boxs[macs + "r"],
                                                            column=retryv_column, padx=1, pady=5, sticky="ew")


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
        msgbox_info = self.sw.get_user_input()
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

        self.client_button.configure(state="active")
        self.stop_button.configure(state="disabled")

        self.stop_event.set()
        # self.sharkd.rshark_store_pyshark_async_parse()
        self.sharkd.rshark_force_exit()
        self.running = False

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

if __name__ == "__main__":
    root = tk.Tk()

    width = 1680
    height = 815

    root.maxsize(width=width, height=height + 10) 
    root.minsize(width=width, height=height + 10)

    mframe = tk.Frame(master=root, borderwidth=1, relief="solid", height=height)
    mframe.grid(row=0, column=0, padx=5, pady=0, sticky="wen")

    pframe = tk.Frame(master=root, borderwidth=1, relief="solid")
    pframe.grid(row=0, column=1, padx=5, pady=0, sticky="wen")

    # 接下来为数据分析窗口(pframe)创建画布，以方便实现滚动条
    # 画布上面创建内侧窗口(interior frame)，并将内侧窗口附着在画布上新创建的窗体(create_window)上
    # 最后将滚动条通过画布的configure方法添加至画布
    pframe_canvas = tk.Canvas(pframe, borderwidth=0, highlightthickness=0, width=width - 570, height=height + 6)
    pframe_canvas.grid(row=0, column=1, padx=5, pady=0, sticky="wen")

    pframe_canvas_scrollbar = tk.Scrollbar(pframe, orient="vertical", command=pframe_canvas.yview)
    pframe_canvas_scrollbar.grid(row=0, column=2, sticky="ns")

    pframe_canvas.configure(yscrollcommand=pframe_canvas_scrollbar.set)

    pframe_interior_frame = tk.Frame(pframe_canvas)
    pframe_canvas.create_window((0, 0), window=pframe_interior_frame, anchor="nw")

    def update_scroll_region(event):
        pframe_canvas.configure(scrollregion=pframe_canvas.bbox("all"))

    def _on_mousewheel(event):
        pframe_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    pframe_interior_frame.bind("<Configure>", update_scroll_region)
    pframe_canvas.bind("<Configure>", update_scroll_region)
    pframe_canvas.bind_all("<MouseWheel>", _on_mousewheel)

    app = NetworkTestGUI(mframe, pframe_interior_frame)

    # root.geometry("1580x810")

    root.mainloop()