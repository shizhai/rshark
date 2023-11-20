import socket
import sys
import queue
import os
import select
import socket
import logging
logging.basicConfig(filename='asrd.log', level=logging.DEBUG)
import os
import sys

#refer: https://www.cnblogs.com/lxmhhy/p/6091730.html

class Asrd_socket:
    def __init__(self, type="unix", ipaddr="0.0.0.0", port=8989, path="/tmp/asrd_ubus", max=5, buf_size=2048):
        self.type = type
        self.ipaddr = ipaddr
        self.port = port
        self.path = path
        self.max = max
        self.buf_size = buf_size
        self.timeout = 10
        self.inputs = []
        self.msg_queues = {}
        self.client_info = {}
        self.cbs = [] # recver, sender, data
        pass
    def __asrd_unlink_domain(self):
        try:
            os.unlink(self.path)
        except OSError:
            if os.path.exists(self.path):
                raise

    def __asrd_close(self):
        if self.type.casefold() != "unix".casefold():
            for s in self.inputs:
                s.close()
        elif self.type.casefold() == "unix".casefold():
            self.__asrd_unlink_domain()

    def __asrd_docket_buf_handle(self, data, s, sender):
        print("recv data: {}@len:{}".format(data.decode(), len(data.decode())))
        self.sender("ok".encode())
        if len(self.cb) > 0:
            for cb in self.cbs:
                cb(sender, data)
        else:
            self.msg_queues[s].put(data)

    def __asrd_socket_udp_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) #keepalive
        s.bind((self.ipaddr, self.port))
        logging.info("bind on {}@{}".format(self.ipaddr, self.port))
        return s

    def __asrd_socket_tcp_server(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) #keepalive
        s.bind((self.ipaddr, self.port))
        s.listen(self.max)
        logging.info("listening on {}@{}".format(self.ipaddr, self.port))
        return s

    def __asrd_socket_domain_server(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.__asrd_unlink_domain()
        s.bind(self.path)
        s.listen(self.max)
        logging.info("listening on {}".format(self.path))
        return s

    def asrd_get_msg_queue(self):
        return self.msg_queues

    def asrd_socket_add_cb(self, cb):
        self.cbs.append(cb)

    def asrd_socket_remove_cb(self, cb):
        self.cbs.remove(cb)

    def run(self):
        '''
        1. this is new connection from peer device
        2. handle data from client if connect exist
        '''
        while True:
            r, w, e = select.select(self.inputs, [], self.inputs, self.timeout)
            if not (r or w or e):
                continue

            for s in r:
                if s is self.server:
                    conn, ip = s.accept()
                    conn.setblocking(False)
                    self.inputs.append(conn)
                    self.client_info[conn] = str(ip)
                    self.msg_queues[conn] = queue.Queue()
                else:
                    if self.type.casefold() == "udp".casefold():
                        data = s.recvfrom(self.buf_size)
                        self.__asrd_docket_buf_handle(data, s, s.sendto)
                    else:
                        data = s.recv(self.buf_size)
                        self.__asrd_docket_buf_handle(data, s, s.sendall)


    def asrd_socket_server_start(self):
        if self.type.casefold() == "unix".casefold():
            s = self.__asrd_socket_domain_server()
        elif self.type.casefold() == "udp".casefold():
            s = self.__asrd_socket_udp_server()
        elif self.type.casefold() == "tcp".casefold():
            s = self.__asrd_socket_tcp_server()
        else:
            logging.error("no socket type matched!")
            return

        s.setblocking(False)
        self.inputs.append(s)
        self.server = s
        self.run()

    def __del__(self):
        self.__asrd_close()

if __name__ == "__main__":
    socket_obj = Asrd_socket(type="tcp")
    socket_obj.asrd_socket_server_start()