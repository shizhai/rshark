#!/usr/bin/python
# -*- coding: UTF-8 -*-

import argparse
import os
import sys
import posixpath
try:
    from html import escape
except ImportError:
    from cgi import escape
import shutil
import mimetypes
import re
import signal
from io import StringIO, BytesIO
from functools import partial

if sys.version_info.major == 3:
    # Python3
    from urllib.parse import quote
    from urllib.parse import unquote
    from http.server import HTTPServer
    from http.server import SimpleHTTPRequestHandler
else:
    # Python2
    from urllib import quote
    from urllib import unquote
    from BaseHTTPServer import HTTPServer
    from BaseHTTPServer import BaseHTTPRequestHandler


class SimpleHFS(SimpleHTTPRequestHandler):
    """Simple HTTP request handler with GET/HEAD/POST commands.
    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method. And can receive file uploaded
    by client.
    The GET/HEAD/POST requests are identical except that the HEAD
    request omits the actual contents of the file.
    """

    # server_version = "simple_http_server/" + __version__
    server_version = "simple_http_server/v1"

    def __init__(self, *args, dir=None, **kwargs):
        self.directory = dir
        super().__init__(*args, directory=dir, **kwargs)

    def do_GET(self):
        """Serve a GET request."""
        fd = self.send_head()
        if fd:
            shutil.copyfileobj(fd, self.wfile)
            fd.close()

    def do_HEAD(self):
        """Serve a HEAD request."""
        fd = self.send_head()
        if fd:
            fd.close()

    def do_POST(self):
        """Serve a POST request."""
        r, info = self.deal_post_data()
        print(r, info, "by: ", self.client_address)
        f = BytesIO()
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<html>\n<title>Upload Result Page</title>\n")
        f.write(b"<body>\n<h2>Upload Result Page</h2>\n")
        f.write(b"<hr>\n")
        if r:
            f.write(b"<strong>Success:</strong>")
        else:
            f.write(b"<strong>Failed:</strong>")
        f.write(info.encode('ascii'))
        f.write(b"<br><a href=\"%s\">back</a>" % self.headers['referer'].encode('ascii'))
        f.write(b"<hr><small>Powered By: Sampson.Yang, check new version at ")
        f.write(b"<a href=\"https://github.com/\">")
        f.write(b"here</a>.</small></body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        if f:
            shutil.copyfileobj(f, self.wfile)
            f.close()

    def deal_post_data(self):
        boundary = self.headers["Content-Type"].split("=")[1].encode('ascii')
        remain_bytes = int(self.headers['content-length'])
        line = self.rfile.readline()
        remain_bytes -= len(line)
        if boundary not in line:
            return False, "Content NOT begin with boundary"
        line = self.rfile.readline()
        remain_bytes -= len(line)
        fn = re.findall(r'Content-Disposition.*name="file"; filename="(.*)"', str(line))
        if not fn:
            return False, "Can't find out file name..."
        path = super().translate_path(self.path)
        fn = os.path.join(path, fn[0])
        while os.path.exists(fn):
            fn += "_"
        line = self.rfile.readline()
        remain_bytes -= len(line)
        line = self.rfile.readline()
        remain_bytes -= len(line)
        try:
            out = open(fn, 'wb')
        except IOError:
            return False, "Can't create file to write, do you have permission to write?"

        pre_line = self.rfile.readline()
        remain_bytes -= len(pre_line)
        while remain_bytes > 0:
            line = self.rfile.readline()
            remain_bytes -= len(line)
            if boundary in line:
                pre_line = pre_line[0:-1]
                if pre_line.endswith(b'\r'):
                    pre_line = pre_line[0:-1]
                out.write(pre_line)
                out.close()
                return True, "File '%s' upload success!" % fn
            else:
                out.write(pre_line)
                pre_line = line
        return False, "Unexpect Ends of data."

    def send_head(self):
        """Common code for GET and HEAD commands.
        This sends the response code and MIME headers.
        Return value is either a file object (which has to be copied
        to the output file by the caller unless the command was HEAD,
        and must be closed by the caller under all circumstances), or
        None, in which case the caller has nothing further to do.
        """
        print("send head1: "+self.path)
        path = super().translate_path(self.path)
        print("send head2: "+path)
        if os.path.isdir(path):
            if not self.path.endswith('/'):
                # redirect browser - doing basically what apache does
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in "index.html", "index.htm":
                index = os.path.join(path, index)
                if os.path.exists(index):
                    path = index
                    break
            else:
                return self.list_directory(path)
        content_type = self.guess_type(path)
        try:
            # Always read in binary mode. Opening files in text mode may cause
            # newline translations, making the actual size of the content
            # transmitted *less* than the content-length!
            f = open(path, 'rb')
        except IOError:
            self.send_error(404, "File not found")
            return None, 0
        self.send_response(200)
        self.send_header("Content-type", content_type)
        fs = os.fstat(f.fileno())
        self.send_header("Content-Length", str(fs[6]))
        self.send_header("Last-Modified", self.date_time_string(fs.st_mtime))
        self.end_headers()
        return f, fs.st_mtime

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).
        Return value is either a file object, or None (indicating an
        error). In either case, the headers are sent, making the
        interface the same as for send_head().
        """
        try:
            list_dir = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list_dir.sort(key=lambda a: a.lower())
        f = BytesIO()
        display_path = escape(unquote(self.path))
        f.write(b'<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
        f.write(b"<html>\n<title>Directory listing for %s</title>\n" % display_path.encode('ascii'))
        f.write(b"<body>\n<h2>Directory listing for %s</h2>\n" % display_path.encode('ascii'))
        f.write(b"<hr>\n")
        f.write(b"<form ENCTYPE=\"multipart/form-data\" method=\"post\">")
        f.write(b"<input name=\"file\" type=\"file\"/>")
        f.write(b"<input type=\"submit\" value=\"upload\"/></form>\n")
        f.write(b"<hr>\n")

        for name in list_dir:
            fullname = os.path.join(path, name)
            display_name = linkname = name
            # Append / for directories or @ for symbolic links
            if os.path.isdir(fullname):
                display_name = name + "/"
                linkname = name + "/"
            if os.path.islink(fullname):
                display_name = name + "@"
                # Note: a link to a directory displays with @ and links with /
            modified_time = os.path.getmtime(fullname)
            formatted_time = self.date_time_string(modified_time)
            f.write(b'<div style="display: flex; align-items: center;"><span style="flex-grow: 1; margin-left: 20px;"><a href="%s">%s</a></span><span style="margin-right: 80px;">%s</span></div>\n' %
                    (quote(linkname).encode('ascii'), escape(display_name).encode('ascii'), formatted_time.encode('ascii')))

        f.write(b"<hr>\n</body>\n</html>\n")
        length = f.tell()
        f.seek(0)
        self.send_response(200)
        self.send_header("Content-type", "text/html;charset=utf-8")
        self.send_header("Content-Length", str(length))
        self.end_headers()
        return f

    def guess_type(self, path):
        """Guess the type of a file.
        Argument is a PATH (a filename).
        Return value is a string of the form type/subtype,
        usable for a MIME Content-type header.
        The default implementation looks the file's extension
        up in the table self.extensions_map, using application/octet-stream
        as a default; however it would be permissible (if
        slow) to look inside the data to make a better guess.
        """

        base, ext = posixpath.splitext(path)
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        ext = ext.lower()
        if ext in self.extensions_map:
            return self.extensions_map[ext]
        else:
            return self.extensions_map['']

    if not mimetypes.inited:
        mimetypes.init()  # try to read system mime.types
    extensions_map = mimetypes.types_map.copy()
    extensions_map.update({
        '': 'application/octet-stream',  # Default
        '.py': 'text/plain',
        '.c': 'text/plain',
        '.h': 'text/plain',
    })


def signal_handler(signal, frame):
    print("You choose to stop me.")
    exit()


def main():
    parse = argparse.ArgumentParser()
    parse.add_argument("-p", "--port", help="phfs port running on", required=False, default=8000, type=int)
    parse.add_argument("-d", "--dir", help="phfs root directory", required=False, default=".", type=str)
    args = parse.parse_args()

    print(args.dir)

    server_address = ('', args.port)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    httpd = HTTPServer(server_address, partial(SimpleHFS, dir=args.dir))
    server = httpd.socket.getsockname()
    print("server_version: " + SimpleHTTPRequestHandler.server_version + ", python_version: " + SimpleHTTPRequestHandler.sys_version)
    print("Serving HTTP on: " + str(server[0]) + ", port: " + str(server[1]) + " ...")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == '__main__':
    main()
