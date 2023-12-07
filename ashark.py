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

os_platform = sys.platform.lower()

IPERF_PATH=None
if os_platform.startswith("win"):
    IPERF_PATH="./files/iperf/iperf.exe"
else:
    IPERF_PATH="iperf"

import tkinter as tk
from tkinter import ttk

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
        self.wrinfo = {}
        self.rinfos = rinfos
        self.rinfo = {}
        self.trigger_item = trigger_item
        self.start_row = start_rows
        self.rows = start_rows
        self.diff_rows = 0
        self.mac_entries = []
        self.pmacs = {}
        self.root.title("Info to Rshark")

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
        hide_mac_label1 = tk.Label(self.root, text="Addr1", width=20)
        hide_mac_label1.grid(row=self.rows, column=1, sticky="we", padx=10, pady=5)
        hide_mac_label2 = tk.Label(self.root, text="Addr2", width=20)
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
        mac_entry1.insert(0, "FF:FF:FF:FF:FF:FF")
        HoverInfo(mac_entry1, "'-' means any mac")
        mac_entry2 = tk.Entry(self.root, width=20)
        mac_entry2.grid(row=len(self.mac_entries) + self.rows, column=2, padx=10, pady=5, sticky="we")
        mac_entry2.insert(0, "FF:FF:FF:FF:FF:FF")
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
    def __init__(self, root):
        self.running = False
        self.parse_on_time = False
        self.event_loop = asyncio.get_event_loop()
        self.client_thread = None
        self.pshark_thread = None
        self.root = root
        self.rows = 0
        self.root.title("Network Performance Test")
        self.data_boxs={}
        self.data_rows = 0

        # 停止标志
        self.stop_event = threading.Event()

        self.content_label = tk.Label(self.root, text="/ " * 20 + "Iperf Info" + " /" * 20)
        self.content_label.grid(row=self.rows, column=0, columnspan=3, padx=5, pady=5, sticky="we")
        self.rows = self.rows + 1

        # IP 输入框和标签
        self.ip_label = tk.Label(self.root, text="IP Address:")
        self.ip_label.grid(row=self.rows, column=0, padx=5, pady=5, sticky="e")
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.insert(0, "192.168.3.255")
        self.ip_entry.grid(row=self.rows, column=1, padx=5, pady=5, sticky="w")
        self.rows = self.rows + 1

        if self.parse_on_time:
            boxs_title = {}
            boxs_title["title1"] = tk.StringVar()
            boxs_title["title1"].set("src->dst")
            boxs_title["title1_value"] = tk.Entry(self.root, textvariable=boxs_title["title1"], state="readonly", justify="center")
            boxs_title["title1_value"].grid(row=0, column=3, padx=5, pady=5, sticky="we")

            boxs_title["title2"] = tk.StringVar()
            boxs_title["title2"].set("rssi")
            boxs_title["title2_value"] = tk.Entry(self.root, textvariable=boxs_title["title2"], state="readonly", justify="center")
            boxs_title["title2_value"].grid(row=0, column=4, padx=5, pady=5, sticky="ew")

            boxs_title["title3"] = tk.StringVar()
            boxs_title["title3"].set("counts")
            boxs_title["title3_value"] = tk.Entry(self.root, textvariable=boxs_title["title3"], state="readonly", justify="center")
            boxs_title["title3_value"].grid(row=0, column=5, padx=5, pady=5, sticky="ew")

            boxs_title["title4"] = tk.StringVar()
            boxs_title["title4"].set("retry")
            boxs_title["title4_value"] = tk.Entry(self.root, textvariable=boxs_title["title4"], state="readonly", justify="center")
            boxs_title["title4_value"].grid(row=0, column=6, padx=5, pady=5, sticky="ew")
            self.data_rows = self.data_rows + 1

        # Port 输入框和标签
        self.port_label = tk.Label(self.root, text="Port:")
        self.port_label.grid(row=self.rows, column=0, padx=5, pady=5, sticky="e")
        self.port_entry = tk.Entry(self.root)
        self.port_entry.insert(0, "12345")
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
            # rinfo["stores"] = ["wireshark://.", "local://./", "pshark://."]
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
        for data in d:
            for mac1 in data:
                for mac2 in data[mac1]:
                    macs = (mac1 + mac2).replace(":", "")
                    if not macs in self.data_boxs:
                        # print(data[mac1][mac2])

                        if self.data_rows > 10:
                            # print("overvlow!!!!!!!!!!!!!!!")
                            return

                        self.data_boxs[macs] = tk.StringVar()
                        self.data_boxs[macs].trace_add("write", lambda *args: self.on_text_change(macs, *args))
                        self.data_boxs[macs].set(mac1+"->"+mac2)
                        self.data_boxs[macs + "v"] = tk.Entry(self.root, textvariable=self.data_boxs[macs], state="readonly")
                        self.data_boxs[macs + "v"].grid(row=self.data_rows, column=3, padx=5, pady=5, sticky="ew")

                        rssiv = macs + "rssi"
                        self.data_boxs[rssiv] = tk.StringVar()
                        self.data_boxs[rssiv].set(round(int(data[mac1][mac2]["rssi"]) / int(data[mac1][mac2]["rssi_cnt"]), 2))
                        self.data_boxs[rssiv + "v"] = tk.Entry(self.root, textvariable=self.data_boxs[rssiv], state="readonly")
                        self.data_boxs[rssiv + "v"].grid(row=self.data_rows, column=4, padx=5, pady=5, sticky="ew")

                        cntv = macs + "cnts"
                        self.data_boxs[cntv] = tk.StringVar()
                        self.data_boxs[cntv].set(int(data[mac1][mac2]["cnt"]))
                        self.data_boxs[cntv + "v"] = tk.Entry(self.root, textvariable=self.data_boxs[cntv], state="readonly")
                        self.data_boxs[cntv + "v"].grid(row=self.data_rows, column=5, padx=5, pady=5, sticky="ew")

                        retryv = macs + "retry"
                        self.data_boxs[retryv] = tk.StringVar()
                        self.data_boxs[retryv].set(int(data[mac1][mac2]["retry"]))
                        self.data_boxs[retryv + "v"] = tk.Entry(self.root, textvariable=self.data_boxs[retryv], state="readonly")
                        self.data_boxs[retryv + "v"].grid(row=self.data_rows, column=6, padx=5, pady=5, sticky="ew")

                        self.data_rows = self.data_rows + 1
                    else:
                        self.data_boxs[macs].set(mac1+"->"+mac2)
                        self.data_boxs[macs + "rssi"].set(round(int(data[mac1][mac2]["rssi"]) / int(data[mac1][mac2]["rssi_cnt"]), 2))
                        self.data_boxs[macs + "cnts"].set(data[mac1][mac2]["cnt"])
                        self.data_boxs[macs + "retry"].set(data[mac1][mac2]["retry"])

    def start_run(self):
        self.start_client()

    def start_client(self):
        for item in self.data_boxs:
            if item + "v" in self.data_boxs:
                self.data_boxs[item + "v"].grid_forget()

        del self.data_boxs
        self.data_boxs = {}
        self.data_rows = 1

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
        sub_args = {"cb": self.update_data, "eloop": self.event_loop}
        self.sharkd.rshark_set_pshark_cb(sub_args)
        self.sharkd.rshark_sniffer()

    def run_client(self):
        while not hasattr(self, "sharkd") or self.sharkd.rshark_get_tcpdump_pid() == 0:
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
    # root.geometry(str(root.winfo_width()) + "x800")
    root.maxsize(height=800) 
    app = NetworkTestGUI(root)
    root.mainloop()