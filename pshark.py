#!/usr/bin/env python3

import os
import sys
import argparse

from pyshark.capture.pipe_capture import PipeCapture

class Pshark():
    def rshark_store_addb(self, tx, rx, rssi, type, retry):
        found = False
        if self.pmacs and not "-" in self.pmacs:
            if tx not in self.pmacs or rx not in self.pmacs:
                return

            if rx not in self.pmacs[tx]:
                return

        for item in self.data_cache:
            if tx in item and rx in item[tx]:
                item_tx = item[tx]
                item_tx_rx = item_tx[rx]
                item_tx_rx_type = item_tx_rx[type]
                item_tx_rx_type["rssi"] = item_tx_rx_type["rssi"] + int(rssi)
                item_tx_rx_type["rssi_cnt"] = item_tx_rx_type["rssi_cnt"] + 1 if int(rssi) != 0 else item_tx_rx_type["rssi_cnt"]
                item_tx_rx_type["cnt"] = item_tx_rx_type["cnt"] + 1 if not retry else item_tx_rx_type["cnt"]
                item_tx_rx_type["retry"] = item_tx_rx_type["retry"] + 1 if retry else item_tx_rx_type["retry"]
                found = True
                break
        if not found:
            item_insert = {}
            item_tx_rx_type = {}
            item_tx_rx_type["rssi"] = int(rssi)
            item_tx_rx_type["rssi_cnt"] = 1 if int(rssi) != 0 else 0
            item_tx_rx_type["cnt"] = 1
            item_tx_rx_type["retry"] = 1 if retry else 0
            item_tx_rx = {}
            item_tx_rx[type] = item_tx_rx_type
            item_tx = {}
            item_tx[rx] = item_tx_rx
            item_rx = {}
            item_rx = item_tx
            item_insert[tx] = item_rx
            self.data_cache.append(item_insert)
            pshark_data_cache.append(item_insert)
            print(self.data_cache)

    def rshark_store_pyshark(self, arg, inputd):
        self.parse_win = Tk()
        pipc = PipeCapture(pipe=inputd)
        # print(pipc.get_parameters()) 
        pkts = pipc._packets_from_tshark_sync()
        for pkt in pkts:
            if not hasattr(pkt, 'wlan') or not hasattr(pkt.wlan, 'fc_type') or pkt.wlan.fc_type == 1:
                continue

            frame_type = "mgmt" if pkt.wlan.fc_type == 0 else "data"

            retry = True if hasattr(pkt.wlan, "flags") and int(pkt.wlan.flags, 16) & 0x8 == 0x8 else False

            # if retry:
            #     print(type(pkt.wlan_radio))
            #     print(pkt.wlan_radio.field_names)
            #     sys.exit()

            rssi = 0
            if hasattr(pkt, 'wlan_radio') and hasattr(pkt.wlan_radio, 'signal_dbm'):
                rssi = pkt.wlan_radio.signal_dbm
                # print(pkt.wlan_radio.signal_dbm)

            # frame_subtype = pkt.wlan.fc_subtype
            # print(pkt)

            ra = pkt.wlan.ra if hasattr(pkt.wlan, "ra") else "None"
            ta = pkt.wlan.ta if hasattr(pkt.wlan, "ta") else "None"
            # print(frame_type, frame_subtype, ra, ta)
            self.rshark_store_addb(ta, ra, rssi, frame_type, retry)
