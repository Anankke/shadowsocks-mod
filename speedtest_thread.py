#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import configloader
import importloader
from speedtest import speedtest
from shadowsocks import common, shell
import cymysql


def speedtest_thread():
	hour = configloader.get_config().SPEEDTEST
	if hour == 0:
		return

	time.sleep(600)

	while True :

		try:
			logging.info("Speedtest starting...")
			CTid = 0
			speedtest_ct = speedtest.Speedtest()
			speedtest_ct.get_servers()
			servers_list = []
			for _, servers in sorted(speedtest_ct.servers.items()):
				for server in servers:
					if server['country'].find('China') != -1 and server['sponsor'].find('Telecom') != -1:
						servers_list.append(server)
			speedtest_ct.get_best_server(servers_list)
			results_ct = speedtest_ct.results
			CTPing = str(results_ct.server['latency']) + ' ms'
			speedtest_ct.download()
			CTDLSpeed = str(round((results_ct.download / 1000 / 1000), 2)) + " Mbit/s"
			speedtest_ct.upload()
			CTUpSpeed = str(round((results_ct.upload / 1000 / 1000), 2)) + " Mbit/s"




			CUid = 0
			speedtest_cu = speedtest.Speedtest()
			speedtest_cu.get_servers()
			servers_list = []
			for _, servers in sorted(speedtest_cu.servers.items()):
				for server in servers:
					if server['country'].find('China') != -1 and server['sponsor'].find('Unicom') != -1:
						servers_list.append(server)
			speedtest_cu.get_best_server(servers_list)
			results_cu = speedtest_cu.results
			CUPing = str(results_cu.server['latency']) + ' ms'
			speedtest_cu.download()
			CUDLSpeed = str(round((results_cu.download / 1000 / 1000), 2)) + " Mbit/s"
			speedtest_cu.upload()
			CUUpSpeed = str(round((results_cu.upload / 1000 / 1000), 2)) + " Mbit/s"


			CMid = 0
			speedtest_cm = speedtest.Speedtest()
			speedtest_cm.get_servers()
			servers_list = []
			for _, servers in sorted(speedtest_cm.servers.items()):
				for server in servers:
					if server['country'].find('China') != -1 and server['sponsor'].find('Mobile') != -1:
						servers_list.append(server)
			speedtest_cm.get_best_server(servers_list)
			results_cm = speedtest_cm.results
			CMPing = str(results_cu.server['latency']) + ' ms'
			speedtest_cm.download()
			CMDLSpeed = str(round((results_cm.download / 1000 / 1000), 2)) + " Mbit/s"
			speedtest_cm.upload()
			CMUpSpeed = str(round((results_cm.upload / 1000 / 1000), 2)) + " Mbit/s"

			if configloader.get_config().MYSQL_SSL_ENABLE == 1:
				conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
											passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8',ssl={'ca':configloader.get_config().MYSQL_SSL_CA,'cert':configloader.get_config().MYSQL_SSL_CERT,'key':configloader.get_config().MYSQL_SSL_KEY})
			else:
				conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
											passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8')
			conn.autocommit(True)
			cur = conn.cursor()
			cur.execute("INSERT INTO `speedtest` (`id`, `nodeid`, `datetime`, `telecomping`, `telecomeupload`, `telecomedownload`, `unicomping`, `unicomupload`, `unicomdownload`, `cmccping`, `cmccupload`, `cmccdownload`) VALUES (NULL, '" + str(configloader.get_config().NODE_ID) + "', unix_timestamp(), '" + CTPing + "', '" + CTDLSpeed + "', '" + CTUpSpeed + "', '" + CUPing + "', '" + CUDLSpeed + "', '" + CUUpSpeed + "', '" + CMPing + "', '" + CMDLSpeed + "', '" + CMUpSpeed + "')")
			cur.close()
			conn.close()

			logging.info("Speedtest finished")
		except Exception as e:
			shell.print_exception(e)
			logging.error("Speedtest error")


		time.sleep(hour * 3600)
