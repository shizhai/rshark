import tkinter as tk
from tkinter import ttk

class InformationEntryWindow:
    def __init__(self, root, rinfo, trigger_list, trigger_item):
        self.root = root
        self.trigger_list = trigger_list
        self.trigger_item = trigger_item
        self.wrinfo = {}
        self.rinfo = rinfo
        self.rows = 0
        self.mac_entries = []
        self.pmacs = {}
        self.root.title("Info to Rshark")

        for item in self.rinfo:
            if type(self.rinfo[item]) == list:
                self.wrinfo["label" + item] = tk.Label(self.root, text=item + ": ")
                self.wrinfo["value" + item] = ttk.Combobox(self.root)
                self.wrinfo["value" + item]["value"] = self.rinfo[item]
                self.wrinfo["value" + item].current(0)
                if item == self.trigger_list:
                    self.wrinfo["value" + item].bind('<<ComboboxSelected>>', self.trigger_show_mac_button)
            else:
                self.wrinfo["label" + item] = tk.Label(self.root, text=item + ": ")
                self.wrinfo["value" + item] = tk.Entry(self.root)
                self.wrinfo["value" + item].insert(0, self.rinfo[item])

            self.wrinfo["label" + item].grid(row=self.rows, column=0, sticky="e", padx=10, pady=5)
            self.wrinfo["value" + item].grid(row=self.rows, column=1, sticky="w", padx=10, pady=5)
            self.rows = self.rows+ 1


        # 添加 "添加MAC地址" 按钮
        self.add_mac_button = tk.Button(self.root, text="Add MAC Group", command=self.add_mac_entry, width=15)
        self.add_mac_button.grid(row=self.rows, column=0, padx=10, pady=5)
        self.add_mac_button.grid_forget()
        self.hide_mac_label = tk.Label(self.root, text="")
        self.hide_mac_label.grid(row=self.rows, column=1, sticky="w", padx=10, pady=5)

        # 添加 "OK" 按钮
        # print(self.add_mac_button.winfo_reqwidth())
        # print(self.add_mac_button.winfo_width())
        self.ok_button = tk.Button(self.root, text="OK", command=self.print_user_input, width=15)
        self.ok_button.grid(row=(self.rows + 1), column=0, pady=10, padx=0)
        self.hide_ok_label = tk.Label(self.root, text="")
        self.hide_ok_label.grid(row=(self.rows + 1), column=1, sticky="w", padx=10, pady=5)
        self.root.update()

    def trigger_show_mac_button(self, event):
        if self.wrinfo["value" + self.trigger_list].get() == self.trigger_item:
            self.add_mac_button.grid(row=self.rows, column=0, padx=10, pady=5)

    def add_mac_entry(self):
        hide_mac_entry_label = tk.Label(self.root, text="")
        hide_mac_entry_label.grid(row=len(self.mac_entries) + self.rows, column=0, sticky="w", padx=10, pady=5)
        mac_entry1 = tk.Entry(self.root)
        mac_entry1.grid(row=len(self.mac_entries) + self.rows, column=1, padx=10, pady=5)
        mac_entry1.insert(0, "FF:FF:FF:FF:FF:FF")
        dir_mac_entry_label = tk.Label(self.root, text="<-->")
        dir_mac_entry_label.grid(row=len(self.mac_entries) + self.rows, column=2, sticky="w", padx=10, pady=5)
        mac_entry2 = tk.Entry(self.root)
        mac_entry2.grid(row=len(self.mac_entries) + self.rows, column=3, padx=10, pady=5)
        mac_entry2.insert(0, "FF:FF:FF:FF:FF:FF")

        self.mac_entries.append({"maca": mac_entry1, "macb": mac_entry2})

    def print_user_input(self):
        for item in self.rinfo:
            input = self.wrinfo["value" + item].get()
            if not input or self.rinfo[item] == input:
                continue
            else:
                self.rinfo[item] = input

        for mac_entry_kit in self.mac_entries:
            maca = mac_entry_kit["maca"].get()
            macb = mac_entry_kit["macb"].get()

            if maca in self.pmacs:
                if macb in self.pmacs[maca]:
                    continue
                else:
                    self.pmacs[maca].append(macb)
            else:
                self.pmacs[maca] = [macb]

            if macb in self.pmacs:
                if maca in self.pmacs[macb]:
                    continue
                else:
                    self.pmacs[macb].append(maca)
            else:
                self.pmacs[macb] = [maca]

        self.rinfo["pmacs"] = self.pmacs

        print(self.rinfo)

        self.root.destroy()

# if __name__ == "__main__":
def rshark_rmsgbox(rinfo):
    root = tk.Tk()

    # rinfo = {"user": "root", "password": "12345678", "ip": "192.168.8.1", "port": "22", "channel": list(range(1, 13)), "interface": "mon1",
    #          "type": ["openwrt", "ubuntu"], "stores":["wireshark://.", "local://.", "pshark://."]}

    app = InformationEntryWindow(root, rinfo, "stores", rinfo["stores"][2])

    root.update()

    root.mainloop()

    return app.rinfo
