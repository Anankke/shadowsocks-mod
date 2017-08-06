#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import configloader
import importloader
import socket
import re
import platform
import fcntl
from shadowsocks import common, shell


class AutoBlock(object):

    def __init__(self):
        import threading
        self.event = threading.Event()
        self.start_line = self.file_len("/etc/hosts.deny")
        self.has_stopped = False

    def get_ip(self, text):
        if common.match_ipv4_address(text) is not None:
            return common.match_ipv4_address(text)
        else:
            if common.match_ipv6_address(text) is not None:
                return common.match_ipv6_address(text)
        return None

    def file_len(self, fname):
        return sum(1 for line in open(fname))

    def auto_block_thread(self):
        global webapi
        server_ip = socket.gethostbyname(
            configloader.get_config().MYSQL_HOST)

        if configloader.get_config().API_INTERFACE == 'modwebapi':
            # 读取节点IP
            # SELECT * FROM `ss_node`  where `node_ip` != ''
            node_ip_list = []
            data = webapi.getApi('nodes')
            for node in data:
                temp_list = node['node_ip'].split(',')
                node_ip_list.append(temp_list[0])
        else:
            import cymysql
            if configloader.get_config().MYSQL_SSL_ENABLE == 1:
                conn = cymysql.connect(
                    host=configloader.get_config().MYSQL_HOST,
                    port=configloader.get_config().MYSQL_PORT,
                    user=configloader.get_config().MYSQL_USER,
                    passwd=configloader.get_config().MYSQL_PASS,
                    db=configloader.get_config().MYSQL_DB,
                    charset='utf8',
                    ssl={
                        'ca': configloader.get_config().MYSQL_SSL_CA,
                        'cert': configloader.get_config().MYSQL_SSL_CERT,
                        'key': configloader.get_config().MYSQL_SSL_KEY})
            else:
                conn = cymysql.connect(
                    host=configloader.get_config().MYSQL_HOST,
                    port=configloader.get_config().MYSQL_PORT,
                    user=configloader.get_config().MYSQL_USER,
                    passwd=configloader.get_config().MYSQL_PASS,
                    db=configloader.get_config().MYSQL_DB,
                    charset='utf8')
            conn.autocommit(True)

            # 读取节点IP
            # SELECT * FROM `ss_node`  where `node_ip` != ''
            node_ip_list = []
            cur = conn.cursor()
            cur.execute(
                "SELECT `node_ip` FROM `ss_node`  where `node_ip` != ''")
            for r in cur.fetchall():
                temp_list = str(r[0]).split(',')
                node_ip_list.append(temp_list[0])
            cur.close()

        deny_file = open('/etc/hosts.deny')
        fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
        deny_lines = deny_file.readlines()
        deny_file.close()

        logging.info("Read hosts.deny from line " + str(self.start_line))
        real_deny_list = deny_lines[self.start_line:]

        denyed_ip_list = []
        data = []
        for line in real_deny_list:
            if self.get_ip(line) and line.find('#') != 0:
                ip = self.get_ip(line)

                if str(ip).find(str(server_ip)) != -1:
                    i = 0

                    for line in deny_lines:
                        if line.find(ip) != -1:
                            del deny_lines[i]
                        i = i + 1

                    deny_file = open("/etc/hosts.deny", "w+")
                    fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
                    for line in deny_lines:
                        deny_file.write(line)
                    deny_file.close()

                    continue

                has_match_node = False
                for node_ip in node_ip_list:
                    if str(ip).find(node_ip) != -1:
                        i = 0

                        for line in deny_lines:
                            if line.find(ip) != -1:
                                del deny_lines[i]
                            i = i + 1

                        deny_file = open("/etc/hosts.deny", "w+")
                        fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
                        for line in deny_lines:
                            deny_file.write(line)
                        deny_file.close()

                        has_match_node = True
                        continue

                if has_match_node:
                    continue

                if configloader.get_config().API_INTERFACE == 'modwebapi':
                    data.append({'ip': ip})
                    logging.info("Block ip:" + str(ip))
                else:
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT * FROM `blockip` where `ip` = '" + str(ip) + "'")
                    rows = cur.fetchone()
                    cur.close()

                    if rows is not None:
                        continue

                    cur = conn.cursor()
                    cur.execute(
                        "INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '" +
                        str(
                            configloader.get_config().NODE_ID) +
                        "', '" +
                        str(ip) +
                        "', unix_timestamp())")
                    cur.close()

                    logging.info("Block ip:" + str(ip))

                    denyed_ip_list.append(ip)

        if configloader.get_config().API_INTERFACE == 'modwebapi':
            webapi.postApi(
                'func/block_ip', {'node_id': configloader.get_config().NODE_ID}, {'data': data})

        if configloader.get_config().API_INTERFACE == 'modwebapi':
            rows = webapi.getApi('func/block_ip')
        else:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM `blockip` where `datetime`>unix_timestamp()-60")
            rows = cur.fetchall()
            cur.close()

        deny_str = ""
        deny_str_at = ""

        for row in rows:
            if configloader.get_config().API_INTERFACE == 'modwebapi':
                node = row['nodeid']
                ip = self.get_ip(row['ip'])
            else:
                node = row[1]
                ip = self.get_ip(row[2])

            if ip is not None:

                if str(node) == str(configloader.get_config().NODE_ID):
                    if configloader.get_config().ANTISSATTACK == 1 and configloader.get_config(
                    ).CLOUDSAFE == 1 and ip not in denyed_ip_list:
                        if common.is_ip(ip):
                            if common.is_ip(ip) == socket.AF_INET:
                                os.system(
                                    'route add -host %s gw 127.0.0.1' % str(ip))
                                deny_str = deny_str + "\nALL: " + str(ip)
                            else:
                                os.system(
                                    'ip -6 route add ::1/128 via %s/128' % str(ip))
                                deny_str = deny_str + \
                                    "\nALL: [" + str(ip) + "]/128"

                        logging.info("Remote Block ip:" + str(ip))
                else:
                    if common.is_ip(ip):
                        if common.is_ip(ip) == socket.AF_INET:
                            os.system(
                                'route add -host %s gw 127.0.0.1' % str(ip))
                            deny_str = deny_str + "\nALL: " + str(ip)
                        else:
                            os.system(
                                'ip -6 route add ::1/128 via %s/128' %
                                str(ip))
                            deny_str = deny_str + \
                                "\nALL: [" + str(ip) + "]/128"
                    logging.info("Remote Block ip:" + str(ip))

        deny_file = open('/etc/hosts.deny', 'a')
        fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
        deny_file.write(deny_str)
        deny_file.close()

        if configloader.get_config().ANTISSATTACK == 1 and configloader.get_config().CLOUDSAFE == 1:
            deny_file = open('/etc/hosts.deny', 'a')
            fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
            deny_file.write(deny_str_at)
            deny_file.close()

        if configloader.get_config().API_INTERFACE == 'modwebapi':
            rows = webapi.getApi('func/unblock_ip')
        else:
            cur = conn.cursor()
            cur.execute(
                "SELECT * FROM `unblockip` where `datetime`>unix_timestamp()-60")
            rows = cur.fetchall()
            cur.close()
            conn.close()

        deny_file = open('/etc/hosts.deny')
        fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
        deny_lines = deny_file.readlines()
        deny_file.close()

        i = 0

        for line in deny_lines:
            for row in rows:
                if configloader.get_config().API_INTERFACE == 'modwebapi':
                    ip = str(row['ip'])
                else:
                    ip = str(row[1])
                if line.find(ip) != -1:
                    del deny_lines[i]
                    if common.is_ip(ip):
                        if common.is_ip(ip) == socket.AF_INET:
                            os.system(
                                'route del -host %s gw 127.0.0.1' % str(ip))
                        else:
                            os.system(
                                'ip -6 route del ::1/128 via %s/128' %
                                str(ip))
                    logging.info("Unblock ip:" + str(ip))
            i = i + 1

        deny_file = open("/etc/hosts.deny", "w+")
        fcntl.flock(deny_file.fileno(), fcntl.LOCK_EX)
        for line in deny_lines:
            deny_file.write(line)
        deny_file.close()

        self.start_line = self.file_len("/etc/hosts.deny")

    @staticmethod
    def thread_db(obj):
        if configloader.get_config().CLOUDSAFE == 0 or platform.system() != 'Linux':
            return

        if configloader.get_config().API_INTERFACE == 'modwebapi':
            import webapi_utils
            global webapi
            webapi = webapi_utils.WebApi()

        global db_instance
        db_instance = obj()

        try:
            while True:
                try:
                    db_instance.auto_block_thread()
                except Exception as e:
                    import traceback
                    trace = traceback.format_exc()
                    logging.error(trace)
                    #logging.warn('db thread except:%s' % e)
                if db_instance.event.wait(60):
                    break
                if db_instance.has_stopped:
                    break
        except KeyboardInterrupt as e:
            pass
        db_instance = None

    @staticmethod
    def thread_db_stop():
        global db_instance
        db_instance.has_stopped = True
        db_instance.event.set()
