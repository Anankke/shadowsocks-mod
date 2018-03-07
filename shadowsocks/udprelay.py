#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 clowwindy
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

# SOCKS5 UDP Request
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# SOCKS5 UDP Response
# +----+------+------+----------+----------+----------+
# |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +----+------+------+----------+----------+----------+
# | 2  |  1   |  1   | Variable |    2     | Variable |
# +----+------+------+----------+----------+----------+

# shadowsocks UDP Request (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Response (before encrypted)
# +------+----------+----------+----------+
# | ATYP | DST.ADDR | DST.PORT |   DATA   |
# +------+----------+----------+----------+
# |  1   | Variable |    2     | Variable |
# +------+----------+----------+----------+

# shadowsocks UDP Request and Response (after encrypted)
# +-------+--------------+
# |   IV  |    PAYLOAD   |
# +-------+--------------+
# | Fixed |   Variable   |
# +-------+--------------+

# HOW TO NAME THINGS
# ------------------
# `dest`    means destination server, which is from DST fields in the SOCKS5
#           request
# `local`   means local server of shadowsocks
# `remote`  means remote server of shadowsocks
# `client`  means UDP clients that connects to other servers
# `server`  means the UDP server that handles user requests

from __future__ import absolute_import, division, print_function, \
    with_statement

import time
import socket
import logging
import struct
import errno
import random
import binascii
import traceback

from shadowsocks import encrypt, obfs, eventloop, lru_cache, common, shell
from shadowsocks.common import pre_parse_header, parse_header, pack_addr, IPNetwork, PortRange

# for each handler, we have 2 stream directions:
#    upstream:    from client to server direction
#                 read local and write to remote
#    downstream:  from server to client direction
#                 read remote and write to local

STREAM_UP = 0
STREAM_DOWN = 1

# for each stream, it's waiting for reading, or writing, or both
WAIT_STATUS_INIT = 0
WAIT_STATUS_READING = 1
WAIT_STATUS_WRITING = 2
WAIT_STATUS_READWRITING = WAIT_STATUS_READING | WAIT_STATUS_WRITING

BUF_SIZE = 65536
DOUBLE_SEND_BEG_IDS = 16
POST_MTU_MIN = 500
POST_MTU_MAX = 1400
SENDING_WINDOW_SIZE = 8192

STAGE_INIT = 0
STAGE_RSP_ID = 1
STAGE_DNS = 2
STAGE_CONNECTING = 3
STAGE_STREAM = 4
STAGE_DESTROYED = -1

CMD_CONNECT = 0
CMD_RSP_CONNECT = 1
CMD_CONNECT_REMOTE = 2
CMD_RSP_CONNECT_REMOTE = 3
CMD_POST = 4
CMD_SYN_STATUS = 5
CMD_POST_64 = 6
CMD_SYN_STATUS_64 = 7
CMD_DISCONNECT = 8

CMD_VER_STR = b"\x08"

RSP_STATE_EMPTY = b""
RSP_STATE_REJECT = b"\x00"
RSP_STATE_CONNECTED = b"\x01"
RSP_STATE_CONNECTEDREMOTE = b"\x02"
RSP_STATE_ERROR = b"\x03"
RSP_STATE_DISCONNECT = b"\x04"
RSP_STATE_REDIRECT = b"\x05"

def client_key(source_addr, server_af):
    # notice this is server af, not dest af
    return '%s:%s:%d' % (source_addr[0], source_addr[1], server_af)

class UDPRelay(object):

    def __init__(
            self,
            config,
            dns_resolver,
            is_local,
            stat_callback=None,
            stat_counter=None):
        self._config = config
        if config.get('connect_verbose_info', 0) > 0:
            common.connect_log = logging.info

        if config.get('connect_hex_data', 0) > 0:
            self._connect_hex_data = True
        else:
            self._connect_hex_data = False

        if is_local:
            self._listen_addr = config['local_address']
            self._listen_port = config['local_port']
            self._remote_addr = config['server']
            self._remote_port = config['server_port']
        else:
            self._listen_addr = config['server']
            self._listen_port = config['server_port']
            self._remote_addr = None
            self._remote_port = None
        self._dns_resolver = dns_resolver
        self._password = common.to_bytes(config['password'])
        self._method = config['method']
        self._timeout = config['timeout']
        self._is_local = is_local
        self._udp_cache_size = config['udp_cache']
        self._cache = lru_cache.LRUCache(
            timeout=config['udp_timeout'],
            close_callback=self._close_client_pair)
        self._cache_dns_client = lru_cache.LRUCache(
            timeout=10, close_callback=self._close_client_pair)
        self._client_fd_to_server_addr = {}
        #self._dns_cache = lru_cache.LRUCache(timeout=1800)
        self._eventloop = None
        self._closed = False
        self.server_transfer_ul = 0
        self.server_transfer_dl = 0

        self.connected_iplist = []
        self.wrong_iplist = {}
        self.detect_log_list = []

        self.is_cleaning_connected_iplist = False
        self.is_cleaning_wrong_iplist = False
        self.is_cleaning_detect_log = False
        self.is_cleaning_mu_detect_log_list = False
        self.is_cleaning_mu_connected_iplist = False

        if 'users_table' in self._config:
            self.multi_user_table = self._config['users_table']

        self.mu_server_transfer_ul = {}
        self.mu_server_transfer_dl = {}
        self.mu_connected_iplist = {}
        self.mu_detect_log_list = {}

        self.is_pushing_detect_hex_list = False
        self.is_pushing_detect_text_list = False
        self.detect_hex_list = self._config['detect_hex_list'].copy()
        self.detect_text_list = self._config['detect_text_list'].copy()

        self.protocol_data = obfs.obfs(config['protocol']).init_data()
        self._protocol = obfs.obfs(config['protocol'])
        server_info = obfs.server_info(self.protocol_data)
        server_info.host = self._listen_addr
        server_info.port = self._listen_port
        if 'users_table' in self._config:
            server_info.users = self.multi_user_table
        else:
            server_info.users = {}
        server_info.is_multi_user = config["is_multi_user"]
        server_info.protocol_param = config['protocol_param']
        server_info.obfs_param = ''
        server_info.iv = b''
        server_info.recv_iv = b''
        server_info.key_str = common.to_bytes(config['password'])
        try:
            server_info.key = encrypt.encrypt_key(self._password, self._method)
        except Exception:
            logging.error("UDP: method not support")
            server_info.key = b''
        server_info.head_len = 30
        server_info.tcp_mss = 1452
        server_info.buffer_size = BUF_SIZE
        server_info.overhead = 0
        self._protocol.set_server_info(server_info)

        self._sockets = set()
        self._fd_to_handlers = {}
        self._reqid_to_hd = {}
        self._data_to_write_to_server_socket = []

        self._timeouts = []  # a list for all the handlers
        # we trim the timeouts once a while
        self._timeout_offset = 0   # last checked position for timeout
        self._handler_to_timeouts = {}  # key: handler value: index in timeouts

        self._bind = config.get('out_bind', '')
        self._bindv6 = config.get('out_bindv6', '')
        self._ignore_bind_list = config.get('ignore_bind', [])

        if 'forbidden_ip' in config:
            self._forbidden_iplist = IPNetwork(config['forbidden_ip'])
        else:
            self._forbidden_iplist = None
        if 'forbidden_port' in config:
            self._forbidden_portset = PortRange(config['forbidden_port'])
        else:
            self._forbidden_portset = None
        if 'disconnect_ip' in config:
            self._disconnect_ipset = IPNetwork(config['disconnect_ip'])
        else:
            self._disconnect_ipset = None

        self._relay_rules = self._config['relay_rules'].copy()
        self._is_pushing_relay_rules = False

        addrs = socket.getaddrinfo(self._listen_addr, self._listen_port, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" %
                            (self._listen_addr, self._listen_port))
        af, socktype, proto, canonname, sa = addrs[0]
        server_socket = socket.socket(af, socktype, proto)
        server_socket.bind((self._listen_addr, self._listen_port))
        server_socket.setblocking(False)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024 * 1024)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        self._server_socket = server_socket
        self._stat_callback = stat_callback

    def _get_a_server(self):
        server = self._config['server']
        server_port = self._config['server_port']
        if isinstance(server_port, list):
            server_port = random.choice(server_port)
        if isinstance(server, list):
            server = random.choice(server)
        logging.debug('chosen server: %s:%d', server, server_port)
        return server, server_port

    def add_transfer_u(self, user, transfer):
        if ((user is None or user == 0) and self._config["is_multi_user"] != 0) or self._config["is_multi_user"] == 0:
            self.server_transfer_ul += transfer
        else:
            if user not in self.mu_server_transfer_ul:
                self.mu_server_transfer_ul[user] = 0
            self.mu_server_transfer_ul[
                user] += transfer + self.server_transfer_ul
            self.server_transfer_ul = 0

    def add_transfer_d(self, user, transfer):
        if ((user is None or user == 0) and self._config["is_multi_user"] != 0) or self._config["is_multi_user"] == 0:
            self.server_transfer_dl += transfer
        else:
            if user not in self.mu_server_transfer_dl:
                self.mu_server_transfer_dl[user] = 0
            self.mu_server_transfer_dl[
                user] += transfer + self.server_transfer_dl
            self.server_transfer_dl = 0

    def _close_client_pair(self, client_pair):
        client, uid = client_pair
        self._close_client(client)

    def _close_client(self, client):
        if hasattr(client, 'close'):
            if not self._is_local:
                if client.fileno() in self._client_fd_to_server_addr:
                    logging.debug(
                        'close_client: %s' %
                        (self._client_fd_to_server_addr[
                            client.fileno()],))
                else:
                    client.info('close_client')
            self._sockets.remove(client.fileno())
            self._eventloop.remove(client)
            del self._client_fd_to_server_addr[client.fileno()]
            client.close()
        else:
            # just an address
            client.info('close_client pass %s' % client)
            pass

    def _pre_parse_udp_header(self, data):
        if data is None:
            return
        datatype = common.ord(data[0])
        if datatype == 0x8:
            if len(data) >= 8:
                crc = binascii.crc32(data) & 0xffffffff
                if crc != 0xffffffff:
                    logging.warn('uncorrect CRC32, maybe wrong password or '
                                 'encryption method')
                    return None
                cmd = common.ord(data[1])
                request_id = struct.unpack('>H', data[2:4])[0]
                data = data[4:-4]
                return (cmd, request_id, data)
            elif len(data) >= 6 and common.ord(data[1]) == 0x0:
                crc = binascii.crc32(data) & 0xffffffff
                if crc != 0xffffffff:
                    logging.warn('uncorrect CRC32, maybe wrong password or '
                                 'encryption method')
                    return None
                cmd = common.ord(data[1])
                data = data[2:-4]
                return (cmd, 0, data)
            else:
                logging.warn('header too short, maybe wrong password or '
                             'encryption method')
                return None
        return data

    def _pack_rsp_data(self, cmd, request_id, data):
        _rand_data = b"123456789abcdefghijklmnopqrstuvwxyz" * 2
        reqid_str = struct.pack(">H", request_id)
        return b''.join([CMD_VER_STR, common.chr(cmd), reqid_str, data, _rand_data[
                        :random.randint(0, len(_rand_data))], reqid_str])

    def _handel_protocol_error(self, client_address, ogn_data):
        #raise Exception('can not parse header')
        logging.warn(
            "Protocol ERROR, UDP ogn data %s from %s:%d" %
            (binascii.hexlify(ogn_data), client_address[0], client_address[1]))
        if client_address[0] not in self.wrong_iplist and client_address[
                0] != 0 and self.is_cleaning_wrong_iplist == False:
            self.wrong_iplist[client_address[0]] = time.time()

    def _get_relay_host(self, client_address, ogn_data):
        for id in self._relay_rules:
            if self._relay_rules[id]['port'] == 0:
                port = self._listen_port
            else:
                port = self._relay_rules[id]['port']
            return (self._relay_rules[id]['dist_ip'], int(port))
        return (None, None)

    def _handel_normal_relay(self, client_address, ogn_data):
        host, port = self._get_relay_host(client_address, ogn_data)
        self._encrypt_correct = False
        if port is None:
            raise Exception('can not parse header')
        data = b"\x03" + common.to_bytes(common.chr(len(host))) + \
            common.to_bytes(host) + struct.pack('>H', port)
        return (data + ogn_data, True)

    def _get_mu_relay_host(self, ogn_data, uid):

        if not uid:
            return (None, None)

        for id in self._relay_rules:
            if (self._relay_rules[id]['user_id'] == 0 and uid !=
                    0) or self._relay_rules[id]['user_id'] == uid:
                has_higher_priority = False
                for priority_id in self._relay_rules:
                    if (
                        (
                            self._relay_rules[priority_id]['priority'] > self._relay_rules[id]['priority'] and self._relay_rules[id]['id'] != self._relay_rules[priority_id]['id']) or (
                            self._relay_rules[priority_id]['priority'] == self._relay_rules[id]['priority'] and self._relay_rules[id]['id'] > self._relay_rules[priority_id]['id'])) and (
                            self._relay_rules[priority_id]['user_id'] == uid or self._relay_rules[priority_id]['user_id'] == 0):
                        has_higher_priority = True
                        continue

                if has_higher_priority:
                    continue
					
                if self._relay_rules[id]['dist_ip'] == '0.0.0.0':
                    continue

                if self._relay_rules[id]['port'] == 0:
                    port = self._listen_port
                else:
                    port = self._relay_rules[id]['port']

                return (self._relay_rules[id]['dist_ip'], int(port))
        return (None, None)

    def _handel_mu_relay(self, client_address, ogn_data, uid):
        host, port = self._get_mu_relay_host(ogn_data, uid)
        if host is None:
            return (ogn_data, False)
        self._encrypt_correct = False
        if port is None:
            raise Exception('can not parse header')
        data = b"\x03" + common.to_bytes(common.chr(len(host))) + \
            common.to_bytes(host) + struct.pack('>H', port)
        return (data + ogn_data, True)

    def _is_relay(self, client_address, ogn_data, uid):
        if self._config['is_multi_user'] == 0:
            if self._get_relay_host(client_address, ogn_data) == (None, None):
                return False
        else:
            if self._get_mu_relay_host(ogn_data, uid) == (None, None):
                return False
        return True

    def _socket_bind_addr(self, sock, af, is_relay):
        bind_addr = ''
        if self._bind and af == socket.AF_INET:
            bind_addr = self._bind
        elif self._bindv6 and af == socket.AF_INET6:
            bind_addr = self._bindv6

        bind_addr = bind_addr.replace("::ffff:", "")
        if bind_addr in self._ignore_bind_list:
            bind_addr = None

        if is_relay:
            bind_addr = None

        if bind_addr:
            local_addrs = socket.getaddrinfo(
                bind_addr, 0, 0, socket.SOCK_STREAM, socket.SOL_TCP)
            if local_addrs[0][0] == af:
                logging.debug("bind %s" % (bind_addr,))
                sock.bind((bind_addr, 0))

    def _handle_server(self):
        server = self._server_socket
        data, r_addr = server.recvfrom(BUF_SIZE)
        ogn_data = data
        if not data:
            logging.debug('UDP handle_server: data is empty')
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))
        uid = None
        if self._is_local:
            frag = common.ord(data[2])
            if frag != 0:
                logging.warn('drop a message since frag is not 0')
                return
            else:
                data = data[3:]
        else:
            try:
                data, key, ref_iv = encrypt.decrypt_all(self._password,
                                                    self._method,
                                                    data)
            except Exception:
                logging.debug('UDP handle_server: decrypt data failed')
                return

            # decrypt data
            if not data:
                logging.debug('UDP handle_server: data is empty after decrypt')
                return
            ref_iv = [0]
            self._protocol.obfs.server_info.recv_iv = ref_iv[0]
            data, uid = self._protocol.server_udp_post_decrypt(data)

            if self._config['is_multi_user'] != 0 and data:
                if uid:
                    if uid not in self.mu_server_transfer_ul:
                        self.mu_server_transfer_ul[uid] = 0
                    if uid not in self.mu_server_transfer_dl:
                        self.mu_server_transfer_dl[uid] = 0
                    if uid not in self.mu_connected_iplist:
                        self.mu_connected_iplist[uid] = []
                    if uid not in self.mu_detect_log_list:
                        self.mu_detect_log_list[uid] = []

                    if common.getRealIp(r_addr[0]) not in self.mu_connected_iplist[uid]:
                        self.mu_connected_iplist[uid].append(common.getRealIp(r_addr[0]))

                else:
                    raise Exception(
                        'This port is multi user in single port only,so The connection has been rejected, when connect from %s:%d via port %d' %
                        (r_addr[0], r_addr[1], self._listen_port))

        is_relay = False

        #logging.info("UDP data %s" % (binascii.hexlify(data),))
        if not self._is_local:

            if not self._is_relay(r_addr, ogn_data, uid):
                data = pre_parse_header(data)

                data = self._pre_parse_udp_header(data)
                if data is None:
                    return

                if isinstance(data, tuple):
                    return
                    # return self._handle_tcp_over_udp(data, r_addr)
            else:
                if self._config["is_multi_user"] == 0:
                    data, is_relay = self._handel_normal_relay(r_addr, ogn_data)
                else:
                    data, is_relay = self._handel_mu_relay(r_addr, ogn_data, uid)

        try:
            header_result = parse_header(data)
        except:
            self._handel_protocol_error(r_addr, ogn_data)
            return

        if header_result is None:
            self._handel_protocol_error(r_addr, ogn_data)
            return
        connecttype, addrtype, dest_addr, dest_port, header_length = header_result

        if self._is_local:
            addrtype = 3
            server_addr, server_port = self._get_a_server()
        else:
            server_addr, server_port = dest_addr, dest_port

        if (addrtype & 7) == 3:
            af = common.is_ip(server_addr)
            if af == False:
                handler = common.UDPAsyncDNSHandler((data, r_addr, uid, header_length, is_relay))
                handler.resolve(self._dns_resolver, (server_addr, server_port), self._handle_server_dns_resolved)
            else:
                self._handle_server_dns_resolved("", (server_addr, server_port), server_addr, (data, r_addr, uid, header_length, is_relay))
        else:
            self._handle_server_dns_resolved("", (server_addr, server_port), server_addr, (data, r_addr, uid, header_length, is_relay))

    def _handle_server_dns_resolved(self, error, remote_addr, server_addr, params):
        if error:
            return
        data, r_addr, uid, header_length, is_relay = params
        if uid is None:
            is_mu = False
            user_id = self._listen_port
        else:
            is_mu = True
            user_id = uid
        try:
            server_port = remote_addr[1]
            addrs = socket.getaddrinfo(server_addr, server_port, 0,
                                        socket.SOCK_DGRAM, socket.SOL_UDP)
            if not addrs: # drop
                return
            af, socktype, proto, canonname, sa = addrs[0]
            server_addr = sa[0]
            key = client_key(r_addr, af)
            client_pair = self._cache.get(key, None)
            if client_pair is None:
                client_pair = self._cache_dns_client.get(key, None)
            if client_pair is None:
                if self._forbidden_iplist:
                    if common.to_str(sa[0]) in self._forbidden_iplist:
                        logging.debug('IP %s is in forbidden list, drop' % common.to_str(sa[0]))
                        # drop
                        return
                if self._disconnect_ipset:
                    if common.to_str(sa[0]) in self._disconnect_ipset:
                        logging.debug('IP %s is in disconnect list, drop' % common.to_str(sa[0]))
                        # drop
                        return
                if self._forbidden_portset:
                    if sa[1] in self._forbidden_portset:
                        logging.debug('Port %d is in forbidden list, reject' % sa[1])
                        # drop
                        return

                if is_mu:
                    if self.multi_user_table[uid]['_forbidden_iplist']:
                        if common.to_str(sa[0]) in self.multi_user_table[uid]['_forbidden_iplist']:
                            logging.debug('IP %s is in forbidden list, drop' % common.to_str(sa[0]))
                            # drop
                            return
                    if self.multi_user_table[uid]['_disconnect_ipset']:
                        if common.to_str(sa[0]) in self.multi_user_table[uid]['_disconnect_ipset']:
                            logging.debug('IP %s is in disconnect list, drop' % common.to_str(sa[0]))
                            # drop
                            return
                    if self.multi_user_table[uid]['_forbidden_portset']:
                        if sa[1] in self.multi_user_table[uid]['_forbidden_portset']:
                            logging.debug('Port %d is in forbidden list, reject' % sa[1])
                            # drop
                            return

                client = socket.socket(af, socktype, proto)
                client_uid = uid
                client.setblocking(False)
                self._socket_bind_addr(client, af, is_relay)
                is_dns = False
                if len(data) > header_length + 13 and data[header_length + 4 : header_length + 12] == b"\x00\x01\x00\x00\x00\x00\x00\x00":
                    is_dns = True
                else:
                    pass
                if sa[1] == 53 and is_dns: #DNS
                    logging.debug("DNS query %s from %s:%d" % (common.to_str(sa[0]), r_addr[0], r_addr[1]))
                    self._cache_dns_client[key] = (client, uid)
                else:
                    self._cache[key] = (client, uid)
                self._client_fd_to_server_addr[client.fileno()] = (r_addr, af)

                self._sockets.add(client.fileno())
                self._eventloop.add(client, eventloop.POLL_IN, self)

                logging.debug('UDP port %5d sockets %d' % (self._listen_port, len(self._sockets)))

                if not self.is_pushing_detect_text_list:
                    for id in self.detect_text_list:
                        if common.match_regex(
                                self.detect_text_list[id]['regex'],
                                str(data)):
                            if self._config['is_multi_user'] != 0 and uid != 0:
                                if self.is_cleaning_mu_detect_log_list == False and id not in self.mu_detect_log_list[
                                        uid]:
                                    self.mu_detect_log_list[uid].append(id)
                            else:
                                if self.is_cleaning_detect_log == False and id not in self.detect_log_list:
                                    self.detect_log_list.append(id)
                            raise Exception(
                                'This connection match the regex: id:%d was reject,regex: %s ,connecting %s:%d from %s:%d via port %d' %
                                (self.detect_text_list[id]['id'],
                                 self.detect_text_list[id]['regex'],
                                    common.to_str(server_addr),
                                    server_port,
                                    r_addr[0],
                                    r_addr[1],
                                    self._listen_port))
                if not self.is_pushing_detect_hex_list:
                    for id in self.detect_hex_list:
                        if common.match_regex(
                                self.detect_hex_list[id]['regex'],
                                binascii.hexlify(data)):
                            if self._config['is_multi_user'] != 0 and uid != 0:
                                if self.is_cleaning_mu_detect_log_list == False and id not in self.mu_detect_log_list[
                                        uid]:
                                    self.mu_detect_log_list[uid].append(id)
                            else:
                                if self.is_cleaning_detect_log == False and id not in self.detect_log_list:
                                    self.detect_log_list.append(id)
                            raise Exception(
                                'This connection match the regex: id:%d was reject,regex: %s ,connecting %s:%d from %s:%d via port %d' %
                                (self.detect_hex_list[id]['id'],
                                 self.detect_hex_list[id]['regex'],
                                    common.to_str(server_addr),
                                    server_port,
                                    r_addr[0],
                                    r_addr[1],
                                    self._listen_port))
                if not self._connect_hex_data:
                    common.connect_log('UDP data to %s:%d from %s:%d via port %d' %
                                       (common.to_str(server_addr), server_port,
                                        r_addr[0], r_addr[1], self._listen_port))
                else:
                    common.connect_log(
                        'UDP data to %s:%d from %s:%d via port %d,hex data : %s' %
                        (common.to_str(server_addr),
                         server_port,
                         r_addr[0],
                            r_addr[1],
                            self._listen_port,
                            binascii.hexlify(data)))
                if self._config['is_multi_user'] != 2:
                    if common.to_str(r_addr[0]) in self.wrong_iplist and r_addr[
                            0] != 0 and self.is_cleaning_wrong_iplist == False:
                        del self.wrong_iplist[common.to_str(r_addr[0])]
                    if common.getRealIp(r_addr[0]) not in self.connected_iplist and r_addr[
                            0] != 0 and self.is_cleaning_connected_iplist == False:
                        self.connected_iplist.append(common.getRealIp(r_addr[0]))
            else:
                client, client_uid = client_pair
            self._cache.clear(self._udp_cache_size)
            self._cache_dns_client.clear(16)

            if self._is_local:
                try:
                    key, ref_iv, m = encrypt.gen_key_iv(self._password, self._method)
                    self._protocol.obfs.server_info.iv = ref_iv[0]
                    data = self._protocol.client_udp_pre_encrypt(data)
                    #logging.debug("%s" % (binascii.hexlify(data),))
                    data = encrypt.encrypt_all_m(key, ref_iv, m, self._method, data)
                except Exception:
                    logging.debug("UDP handle_server: encrypt data failed")
                    return
                if not data:
                    return
            else:
                data = data[header_length:]
            if not data:
                return
        except Exception as e:
            shell.print_exception(e)
            if self._config['verbose']:
                traceback.print_exc()
            logging.error("exception from user %d" % (user_id,))

        try:
            client.sendto(data, (server_addr, server_port))
            self.add_transfer_u(client_uid, len(data))
            if client_pair is None: # new request
                addr, port = client.getsockname()[:2]
                common.connect_log('UDP data to %s(%s):%d from %s:%d by user %d' %
                        (common.to_str(remote_addr[0]), common.to_str(server_addr), server_port, addr, port, user_id))
        except IOError as e:
            err = eventloop.errno_from_exception(e)
            logging.warning('IOError sendto %s:%d by user %d' % (server_addr, server_port, user_id))
            if err in (errno.EINPROGRESS, errno.EAGAIN):
                pass
            else:
                shell.print_exception(e)

    def _handle_client(self, sock):
        data, r_addr = sock.recvfrom(BUF_SIZE)
        if not data:
            logging.debug('UDP handle_client: data is empty')
            return
        if self._stat_callback:
            self._stat_callback(self._listen_port, len(data))

        client_addr = self._client_fd_to_server_addr.get(sock.fileno())
        client_uid = None
        if client_addr:
            key = client_key(client_addr[0], client_addr[1])
            client_pair = self._cache.get(key, None)
            client_dns_pair = self._cache_dns_client.get(key, None)
            if client_pair:
                client, client_uid = client_pair
            elif client_dns_pair:
                client, client_uid = client_dns_pair

        if not self._is_local:
            addrlen = len(r_addr[0])
            if addrlen > 255:
                # drop
                return

            origin_data = data[:]

            data = pack_addr(r_addr[0]) + struct.pack('>H', r_addr[1]) + data
            try:
                ref_iv = [encrypt.encrypt_new_iv(self._method)]
                self._protocol.obfs.server_info.iv = ref_iv[0]
                data = self._protocol.server_udp_pre_encrypt(data, client_uid)
                response = encrypt.encrypt_all(self._password,
                                               self._method, data)
            except Exception:
                logging.debug("UDP handle_client: encrypt data failed")
                return
            if not response:
                return
        else:
            try:
                data, key, ref_iv = encrypt.decrypt_all(self._password,
                                                    self._method, data)
            except Exception:
                logging.debug('UDP handle_client: decrypt data failed')
                return
            if not data:
                return
            self._protocol.obfs.server_info.recv_iv = ref_iv[0]
            data = self._protocol.client_udp_post_decrypt(data)
            header_result = parse_header(data)
            if header_result is None:
                return
            #connecttype, dest_addr, dest_port, header_length = header_result
            #logging.debug('UDP handle_client %s:%d to %s:%d' % (common.to_str(r_addr[0]), r_addr[1], dest_addr, dest_port))

            response = b'\x00\x00\x00' + data

        if client_addr:
            if client_uid:
                self.add_transfer_d(client_uid, len(response))
            else:
                self.server_transfer_dl += len(response)

            if self._is_relay(r_addr, origin_data, client_uid):
                response = origin_data

            self.write_to_server_socket(response, client_addr[0])
            if client_dns_pair:
                logging.debug(
                    "remove dns client %s:%d" %
                    (client_addr[0][0], client_addr[0][1]))
                del self._cache_dns_client[key]
                self._close_client(client_dns_pair[0])
        else:
            # this packet is from somewhere else we know
            # simply drop that packet
            pass

    def write_to_server_socket(self, data, addr):
        uncomplete = False
        retry = 0
        try:
            self._server_socket.sendto(data, addr)
            data = None
            while self._data_to_write_to_server_socket:
                data_buf = self._data_to_write_to_server_socket[0]
                retry = data_buf[1] + 1
                del self._data_to_write_to_server_socket[0]
                data, addr = data_buf[0]
                self._server_socket.sendto(data, addr)
        except (OSError, IOError) as e:
            error_no = eventloop.errno_from_exception(e)
            uncomplete = True
            if error_no in (errno.EWOULDBLOCK,):
                pass
            else:
                shell.print_exception(e)
                return False
        # if uncomplete and data is not None and retry < 3:
        #    self._data_to_write_to_server_socket.append([(data, addr), retry])
        #'''

    def add_to_loop(self, loop):
        if self._eventloop:
            raise Exception('already add to loop')
        if self._closed:
            raise Exception('already closed')
        self._eventloop = loop

        server_socket = self._server_socket
        self._eventloop.add(server_socket,
                            eventloop.POLL_IN | eventloop.POLL_ERR, self)
        loop.add_periodic(self.handle_periodic)

    def remove_handler(self, handler):
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
            del self._handler_to_timeouts[hash(handler)]

    def update_activity(self, handler):
        # set handler to active
        now = int(time.time())
        if now - handler.last_activity < eventloop.TIMEOUT_PRECISION:
            # thus we can lower timeout modification frequency
            return
        handler.last_activity = now
        index = self._handler_to_timeouts.get(hash(handler), -1)
        if index >= 0:
            # delete is O(n), so we just set it to None
            self._timeouts[index] = None
        length = len(self._timeouts)
        self._timeouts.append(handler)
        self._handler_to_timeouts[hash(handler)] = length

    def _sweep_timeout(self):
        # tornado's timeout memory management is more flexible than we need
        # we just need a sorted last_activity queue and it's faster than heapq
        # in fact we can do O(1) insertion/remove so we invent our own
        if self._timeouts:
            logging.log(shell.VERBOSE_LEVEL, 'sweeping timeouts')
            now = time.time()
            length = len(self._timeouts)
            pos = self._timeout_offset
            while pos < length:
                handler = self._timeouts[pos]
                if handler:
                    if now - handler.last_activity < self._timeout:
                        break
                    else:
                        if handler.remote_address:
                            logging.debug('timed out: %s:%d' %
                                          handler.remote_address)
                        else:
                            logging.debug('timed out')
                        handler.destroy()
                        handler.destroy_local()
                        self._timeouts[pos] = None  # free memory
                        pos += 1
                else:
                    pos += 1
            if pos > TIMEOUTS_CLEAN_SIZE and pos > length >> 1:
                # clean up the timeout queue when it gets larger than half
                # of the queue
                self._timeouts = self._timeouts[pos:]
                for key in self._handler_to_timeouts:
                    self._handler_to_timeouts[key] -= pos
                pos = 0
            self._timeout_offset = pos

    def handle_event(self, sock, fd, event):
        if sock == self._server_socket:
            if event & eventloop.POLL_ERR:
                logging.error('UDP server_socket err')
            try:
                self._handle_server()
            except Exception as e:
                shell.print_exception(e)
                if self._config['verbose']:
                    traceback.print_exc()
        elif sock and (fd in self._sockets):
            if event & eventloop.POLL_ERR:
                logging.error('UDP client_socket err')
            try:
                self._handle_client(sock)
            except Exception as e:
                shell.print_exception(e)
                if self._config['verbose']:
                    traceback.print_exc()
        else:
            if sock:
                handler = self._fd_to_handlers.get(fd, None)
                if handler:
                    handler.handle_event(sock, event)
            else:
                logging.warn('poll removed fd')

    def handle_periodic(self):
        if self._closed:
            self._cache.clear(0)
            self._cache_dns_client.clear(0)
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            if self._server_socket:
                self._server_socket.close()
                self._server_socket = None
                logging.info('closed UDP port %d', self._listen_port)
        else:
            before_sweep_size = len(self._sockets)
            self._cache.sweep()
            self._cache_dns_client.sweep()
            if before_sweep_size != len(self._sockets):
                logging.debug(
                    'UDP port %5d sockets %d' %
                    (self._listen_port, len(
                        self._sockets)))
            self._sweep_timeout()

    def connected_iplist_clean(self):
        self.is_cleaninglist = True
        del self.connected_iplist[:]
        self.is_cleaning_connected_iplist = False

    def mu_connected_iplist_clean(self):
        self.is_cleaning_mu_connected_iplist = True
        for id in self.mu_connected_iplist:
            del self.mu_connected_iplist[id][:]
        self.is_cleaning_mu_connected_iplist = False

    def wrong_iplist_clean(self):
        self.is_cleaning_wrong_iplist = True

        temp_new_list = {}
        for key in self.wrong_iplist:
            if self.wrong_iplist[key] > time.time() - 60:
                temp_new_list[key] = self.wrong_iplist[key]

        self.wrong_iplist = temp_new_list.copy()

        self.is_cleaning_wrong_iplist = True

    def detect_log_list_clean(self):
        self.is_cleaning_detect_log = True
        del self.detect_log_list[:]
        self.is_cleaning_detect_log = False

    def mu_detect_log_list_clean(self):
        self.is_cleaning_mu_detect_log_list = True
        for id in self.mu_detect_log_list:
            del self.mu_detect_log_list[id][:]
        self.is_cleaning_mu_detect_log_list = False

    def reset_single_multi_user_traffic(self, user_id):
        if user_id in self.mu_server_transfer_ul:
            self.mu_server_transfer_ul[user_id] = 0
        if user_id in self.mu_server_transfer_dl:
            self.mu_server_transfer_dl[user_id] = 0

    def modify_detect_text_list(self, new_list):
        self.is_pushing_detect_text_list = True
        self.detect_text_list = new_list.copy()
        self.is_pushing_detect_text_list = False

    def modify_detect_hex_list(self, new_list):
        self.is_pushing_detect_hex_list = True
        self.detect_hex_list = new_list.copy()
        self.is_pushing_detect_hex_list = False

    def modify_multi_user_table(self, new_table):
        self.multi_user_table = new_table.copy()
        self.multi_user_host_table = {}

        self._protocol.obfs.server_info.users = self.multi_user_table

        for id in self.multi_user_table:
            self.multi_user_host_table[common.get_mu_host(
                id, self.multi_user_table[id]['md5'])] = id
            if self.multi_user_table[id]['forbidden_ip'] is not None:
                self.multi_user_table[id]['_forbidden_iplist'] = IPNetwork(
                    str(self.multi_user_table[id]['forbidden_ip']))
            else:
                self.multi_user_table[id][
                    '_forbidden_iplist'] = IPNetwork(str(""))
            if self.multi_user_table[id]['disconnect_ip'] is not None:
                self.multi_user_table[id]['_disconnect_ipset'] = IPNetwork(
                    str(self.multi_user_table[id]['disconnect_ip']))
            else:
                self.multi_user_table[id]['_disconnect_ipset'] = None
            if self.multi_user_table[id]['forbidden_port'] is not None:
                self.multi_user_table[id]['_forbidden_portset'] = PortRange(
                    str(self.multi_user_table[id]['forbidden_port']))
            else:
                self.multi_user_table[id][
                    '_forbidden_portset'] = PortRange(str(""))

    def push_relay_rules(self, rules):
        self._is_pushing_relay_rules = True
        self._relay_rules = rules.copy()
        self._is_pushing_relay_rules = False

    def close(self, next_tick=False):
        logging.debug('UDP close')
        self._closed = True
        if not next_tick:
            if self._eventloop:
                self._eventloop.remove_periodic(self.handle_periodic)
                self._eventloop.remove(self._server_socket)
            self._server_socket.close()
            self._cache.clear(0)
            self._cache_dns_client.clear(0)
