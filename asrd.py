#!/usr/bin/env python3

import logging
import subprocess
import threading
import json
import os
import argparse
import copy
import queue
import rshark
import http.server

from functools import partial

#refer: https://blog.51cto.com/u_16175447/7201469

http_const = {
    "ok" : {"code": 200, "data": {"status": "OK", "msg": None}},
    "error" : {"code": 404, "data": {"status": "ERROR", "msg": None}}
    }

msg_queue = {}
asrd_http_responser = {}

# send: http --> host
def asrd_h2s_write(data):
    msg_queue["h2s"].put(data)

# send: host--> http
def asrd_s2h_write(data):
    msg_queue["s2h"].put(data)

# recv: host<--http
def asrd_h2s_read():
    return msg_queue["h2s"].get(block=True, timeout=120)

# recv: http<--host
def asrd_s2h_read():
    return msg_queue["s2h"].get(block=True, timeout=120)

def asrd_http_response(key, data):
    r = {}
    r.update(http_const[key])
    rsp = r["data"]
    rsp["msg"] = data
    asrd_s2h_write(r)

class RequestHandlerImpl(http.server.BaseHTTPRequestHandler):
    """
    自定义一个 HTTP 请求处理器
    """

    def do_response(self, data):
        print(data)
        #print("++++++++++++++++++++++++++++++++")
        # 1. 发送响应code
        self.send_response(data["code"])

        # 2. 发送响应头
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        # 3. 发送响应内容（此处流不需要关闭）
        self.wfile.write(json.dumps(data["data"]).encode("utf-8"))
        #self.wfile.write(json.dumps(data["data"], sort_keys=True, indent=4, separators=(',', ': ')).encode("utf-8"))

    def do_GET(self):
        """
        处理 GET 请求, 处理其他请求需实现对应的 do_XXX() 方法
        """
        #print(self.server)                # HTTPServer 实例
        #print(self.client_address)        # 客户端地址和端口: (host, port)
        #print(self.requestline)           # 请求行, 例如: "GET / HTTP/1.1"
        #print(self.command)               # 请求方法, "GET"/"POST"等
        #print(self.path)                  # 请求路径, Host 后面部分
        #print(self.headers)               # 请求头, 通过 headers["header_name"] 获取值
        #self.rfile                        # 请求输入流
        #self.wfile                        # 响应输出流

        #print(self.path)
        req = str(self.path).lstrip("/").lstrip("?").split("&")
        request = {}

        for item in req:
            r = item.split("=")
            if len(r) < 2:
                continue

            request[str(r[0])] = str(r[1])

        if not request:
            self.do_response(http_const["error"])

        asrd_h2s_write(request)
        # print("send queue:{}".format(request))

        try:
            r = asrd_s2h_read()
            self.do_response(r)
        except queue.Empty:
            self.do_response(http_const["error"])

    def do_POST(self):
        """
        处理 POST 请求
        """
        # 0. 获取请求Body中的内容（需要指定读取长度, 不指定会阻塞）
        req_body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        print("req_body: " + req_body)

        # 1. 发送响应code
        self.send_response(200)

        # 2. 发送响应头
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        # 3. 发送响应内容（此处流不需要关闭）
        self.wfile.write(("Hello World: " + req_body + "\n").encode("utf-8"))

class httpThread(threading.Thread):
    def __init__(self, name, server_address):
        super(httpThread, self).__init__()
        # 创建一个 HTTP 服务器（Web服务器）, 指定绑定的地址/端口 和 请求处理器
        self.httpd = http.server.HTTPServer(server_address, RequestHandlerImpl)

    def run(self):
        # 循环等待客户端请求
        self.httpd.serve_forever()

class httpFThread(threading.Thread):
    def __init__(self, name, server_address, dir):
        super(httpFThread, self).__init__()
        # 创建一个 HTTP 服务器（Web服务器）, 指定绑定的地址/端口 和 请求处理器
        self.httpfd = http.server.HTTPServer(server_address, partial(http.server.SimpleHTTPRequestHandler, directory=dir))

    def run(self):
        # 循环等待客户端请求
        self.httpfd.serve_forever()

class SrvThread(threading.Thread):
    def __init__(self, name, args):
        super(SrvThread, self).__init__()
        self.name = name
        self.args = args

        macs = self.args["macs"] if "macs" in self.args else None
        timeout = self.args["timeout"] if "timeout" in self.args else 10
        self.shark = rshark.Rshark(self.args["type"], self.args["ip"], self.args["port"], self.args["user"], \
                              self.args["password"], self.args["dst"], self.args["interface"], self.args["channel"], macs, timeout)
    
    def run(self):
        self.shark.rshark_sniffer()

class Asrd():
    def __init__(self, conf):
        self.ostype = os.name
        # 服务器绑定的地址和端口
        server_address = ("", 8000)
        self.httpd = httpThread("http_server", server_address)

        # print(os.path.split(os.path.realpath(__file__)))

        if self.ostype != "posix":
            stores_path = os.path.split(os.path.realpath(__file__))[0] + "\stores"
        else:
            stores_path = os.path.split(os.path.realpath(__file__))[0] + "/stores"

        # print(stores_path)

        server_address_file = ("", 80)
        if not os.path.exists(stores_path):
            os.makedirs(stores_path)
        self.httpfd = httpFThread("http_server_file", server_address_file, stores_path)

        # [{"thread": "thread_id", "args": arg}, ]
        self.threads = []
        rshark.rshark_conf_init(conf)

        self.queues = {
            "start": self.asrd_start_sniffer,
            "stop": self.asrd_stop_sniffer,
            "list": self.asrd_list_running,
            "terms": self.asrd_list_terms,
                       }
        if self.ostype != "posix":
            get_ip_cmd = "netsh interface ip show address | findstr \"IP Address\""
        else:
            get_ip_cmd = "ip addr show dev $(route -n | awk '/UG/{print $8}' | head -n 1) | grep 'inet ' | awk '{print $2}' | awk -F/ '{print $1}'"
        print(get_ip_cmd)
        gic = subprocess.Popen(get_ip_cmd, stdout=subprocess.PIPE, shell=True)
        if self.ostype != "posix":
            self.hostip = gic.stdout.readline().decode("gbk").split(":")[1].strip("\r\n ")
        else:
            self.hostip = gic.stdout.readline().decode("utf-8").strip("\n ")

    def asrd_start_sniffer_thread(self, args):
        r = len(self.threads)
        running = {}
        running["name"] = "sniffer" + str(r)
        running["ip"] = args["ip"]
        running["interface"] = args["interface"]
        running["id"] = SrvThread(running["name"], args)
        running["obj"] = running["id"].shark
        self.threads.append(running)

        del r
        running["id"].start()

        file = running["obj"].start_eventq.get(block=True, timeout=60)

        r = {}
        r["name"] = running["name"]
        r["ip"] = running["ip"]
        r["interface"] = running["interface"]

        if file:
            f = "http://" + self.hostip +"/" + running["ip"] + "/" + str(file)
        else:
            f = "-"

        r["access"] = f

        asrd_http_response("ok", r)

        del r

    def asrd_start_sniffer(self, args):
        lhost = {}

        if not "ip" in args:
            asrd_http_response("error", "Remote ip address needed!")
            return

        lhost = rshark.rshark_lookup_hosts(args["ip"], True, False)

        # 远程没有可以使用的接口
        if len(lhost["interface"]) < 1:
            asrd_http_response("error", "Remote interface not found!")
            return


        if not "interface" in args :
            asrd_http_response("error", "Remote interface should be defined!")
            return

        # 远程不支持的接口
        if "interface" in args and not args["interface"] in lhost["interface"]:
            asrd_http_response("error", "Remote interface {} not support!".format(args["interface"]))
            return

        # 远程接口已经在使用
        for item in self.threads:
            if item["ip"] == args["ip"]:
                if not "interface" in args and len(lhost["interface"]) <= 1:
                    asrd_http_response("error", "Remote interface {} is using!".format(lhost["interface"]))
                    return

                if "interface" in args and args["interface"] == item["interface"]:
                    asrd_http_response("error", "Remote interface {} is using!".format(args["interface"]))
                    return

        if not ("type" in args and "user" in args and "password" in args and "dst" in args and "interface" in args and "channel" in args and "port" in args):
            if not lhost:
                asrd_http_response("error", "Remote ip address not found in configure file as not enough info in the param!")
                return

            args["type"] = lhost["type"] if not "type" in args else args["type"]
            args["user"] = lhost["user"] if not "user" in args else args["user"]
            args["password"] = lhost["password"] if not "password" in args else args["password"]
            args["interface"] = lhost["interface"][0] if not "interface" in args else args["interface"]
            args["channel"] = lhost["channel"] if not "channel" in args else args["channel"]
            args["dst"] = lhost["dst"] if not "dst" in args else args["dst"]
            args["port"] = lhost["port"] if not "port" in args else args["port"]

        self.asrd_start_sniffer_thread(args)

    def asrd_stop_sniffer(self, args):
        if not "ip" in args or not "interface" in args:
            asrd_http_response("error",
                               "ip:{} or interface:{} needed!".format(args["ip"] if "ip" in args else "null", args["interface"] if "interface" in args else "null"))
            return
        for item in self.threads:
            if item["ip"] == args["ip"]:
                item["obj"].rshark_force_exit()
                self.threads.remove(item)
                item["id"].join()

        asrd_http_response("ok", args)

    def asrd_list_running(self, args):
        print(self.threads)
        r = []
        for t in self.threads:
            r.append(copy.copy(t))

        #print(r)
        #print("before:", self.threads)
        #print("id(threads)", id(self.threads))
        #print("id(r)", id(r))
        # 忽略无法编码的字段
        for thread in r:
            thread.pop("id")
            thread.pop("obj")
        #print("after:", self.threads)
        asrd_http_response("ok", r)
        del r
    
    def asrd_list_terms(self, args):
        lhost = rshark.rshark_get_hosts(False)
        asrd_http_response("ok", lhost)

    def asrd_run(self):
        while True:
            try:
                args = asrd_h2s_read()
            except queue.Empty:
                continue
            print(args)
            if "cmd" in args and args["cmd"] in self.queues:
                print(args)
                self.queues[args["cmd"]](args)
                pass
            else:
                #print(args)
                asrd_http_response("error", "CMD {} Not found!".format(args["cmd"] if "cmd" in args else "Null"))

if __name__ == "__main__":
    # queue use for msg comunication to asrd threads
    parse = argparse.ArgumentParser()
    parse.add_argument("-c", "--conf", help="host conf file", required=False, type=str)
    args = parse.parse_args()

    if not args.conf:
        if os.path.exists("./clients"):
            args.conf = "./clients"
            print("no parameter input but find local conf file clients, use it!")
        else:
            print("no parameter input!")
            os.exit()

    msg_queue["h2s"] = queue.Queue()
    msg_queue["s2h"] = queue.Queue()

    A = Asrd(args.conf)
    A.httpd.start()
    A.httpfd.start()

    A.asrd_run()

    for r in A.threads:
        r["id"].join()

    A.httpd.join()
    A.httpfd.join()
