#!/usr/bin/env python
#
# Copyright 2015-2015 breakwa11
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging
import binascii
import struct
import base64
import datetime
import random

from shadowsocks import common
from shadowsocks.obfsplugin import plain
from shadowsocks.common import to_bytes, to_str, ord, chr

def create_simple_obfs_http_obfs(method):
    return simple_obfs_http(method)

obfs_map = {
        'simple_obfs_http': (create_simple_obfs_http_obfs,),
        'simple_obfs_http_compatible': (create_simple_obfs_http_obfs,),
}

def match_begin(str1, str2):
    if len(str1) >= len(str2):
        if str1[:len(str2)] == str2:
            return True
    return False

class simple_obfs_http(plain.plain):
    def __init__(self, method):
        self.method = method
        self.has_sent_header = False
        self.has_recv_header = False
        self.host = None
        self.port = 0
        self.recv_buffer = b''

        self.curl_version = b"7." + common.to_bytes(str(random.randint(0, 51))) + b"." + common.to_bytes(str(random.randint(0, 2)))
        self.nginx_version = b"1." + common.to_bytes(str(random.randint(0, 11))) + b"." + common.to_bytes(str(random.randint(0, 12)))

    def encode_head(self, buf):
        hexstr = binascii.hexlify(buf)
        chs = []
        for i in range(0, len(hexstr), 2):
            chs.append(b"%" + hexstr[i:i+2])
        return b''.join(chs)

    def client_encode(self, buf):
        raise Exception('Need to finish')
        if self.has_sent_header:
            return buf
        port = b''
        if self.server_info.port != 80:
            port = b':' + to_bytes(str(self.server_info.port))
        hosts = (self.server_info.obfs_param or self.server_info.host)
        pos = hosts.find("#")
        if pos >= 0:
            body = hosts[pos + 1:].replace("\\n", "\r\n")
            hosts = hosts[:pos]
        hosts = hosts.split(',')
        host = random.choice(hosts)
        http_head = b"GET /" + b" HTTP/1.1\r\n"
        http_head += b"Host: " + to_bytes(host) + port + b"\r\n"
        http_head += b"User-Agent: curl/" + self.curl_version + b"\r\n"
        http_head += b"Upgrade: websocket\r\n"
        http_head += b"Connection: Upgrade\r\n"
        http_head += b"Sec-WebSocket-Key: " + common.to_bytes(common.random_base64_str(64)) + b"\r\n"
        http_head += b"Content-Length: " + len(buf) + b"\r\n"
        http_head += b"\r\n"
        self.has_sent_header = True
        return http_head + buf

    def client_decode(self, buf):
        raise Exception('Need to finish')
        if self.has_recv_header:
            return (buf, False)
        pos = buf.find(b'\r\n\r\n')
        if pos >= 0:
            self.has_recv_header = True
            return (buf[pos + 4:], False)
        else:
            return (b'', False)

    def server_encode(self, buf):
        if self.has_sent_header:
            return buf

        header = b'HTTP/1.1 101 Switching Protocols\r\n'
        header += b'Server: nginx/' + self.nginx_version + b'\r\n'
        header += b'Date: ' + to_bytes(datetime.datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
        header += b'\r\n'
        header += b'Upgrade: websocket\r\n'
        header += b'Connection: Upgrade\r\n'
        header += b'Sec-WebSocket-Accept: ' + common.to_bytes(common.random_base64_str(64)) + b'\r\n'
        header += b'\r\n'
        self.has_sent_header = True
        return header + buf

    def get_host_from_http_header(self, buf):
        ret_buf = b''
        lines = buf.split(b'\r\n')
        if lines and len(lines) > 1:
            for line in lines:
                if match_begin(line, b"Host: "):
                    return common.to_str(line[6:])

    def not_match_return(self, buf):
        self.has_sent_header = True
        self.has_recv_header = True
        if self.method == 'simple_obfs_http':
            return (b'E'*2048, False, False)
        return (buf, True, False)

    def server_decode(self, buf):
        if self.has_recv_header:
            return (buf, True, False)

        self.recv_buffer += buf
        buf = self.recv_buffer
        if len(buf) > 4:
            if match_begin(buf, b'GET /') or match_begin(buf, b'POST /'):
                if len(buf) > 65536:
                    self.recv_buffer = None
                    logging.warn('simple_obfs_http: over size')
                    return self.not_match_return(buf)
            else: #not http header, run on original protocol
                self.recv_buffer = None
                logging.debug('simple_obfs_http: not match begin')
                return self.not_match_return(buf)
        else:
            return (b'', True, False)

        if b'\r\n\r\n' in buf:
            if b'Upgrade: websocket' not in buf:
                self.recv_buffer = None
                logging.debug('simple_obfs_http: protocol error')
                return self.not_match_return(buf)
            datas = buf.split(b'\r\n\r\n', 1)
            host = self.get_host_from_http_header(buf)
            if host and self.server_info.obfs_param:
                pos = host.find(":")
                if pos >= 0:
                    host = host[:pos]
                hosts = self.server_info.obfs_param.split(b',')
                if common.to_bytes(host) not in hosts:
                    return self.not_match_return(buf)
            if len(datas) > 1:
                self.has_recv_header = True
                return (datas[1], True, False, host)
            return self.not_match_return(buf)
        else:
            return (b'', True, False)
