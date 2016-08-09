#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import configloader
import importloader
import gnupg
import thread
import cymysql
import commands
import socket
import re
import platform
import fcntl




def file_len(fname):
	with open(fname) as f:
		for i, l in enumerate(f):
			pass
	return i + 1
	
def get_ip(text):
	reip = re.compile(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])')
	for ip in reip.findall(text):
		return ip
	return None

def auto_block_thread():
	if configloader.get_config().CLOUDSAFE == 0 or platform.system() != 'Linux':
		return
	
	start_line = file_len("/etc/hosts.deny")
	
	
	
	while True:
		time.sleep(60)
		try:
			server_ip = socket.gethostbyname(configloader.get_config().MYSQL_HOST)
			
			if configloader.get_config().MYSQL_SSL_ENABLE == 1:
				conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
											passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8',ssl={'ca':configloader.get_config().MYSQL_SSL_CA,'cert':configloader.get_config().MYSQL_SSL_CERT,'key':configloader.get_config().MYSQL_SSL_KEY})
			else:
				conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
											passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8')
			conn.autocommit(True)
			
			
			deny_file = open('/etc/hosts.deny')
			fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
			deny_lines = deny_file.readlines()
			deny_file.close()
			
			logging.info("Read hosts.deny from line " + str(start_line))
			real_deny_list = deny_lines[start_line:]
			
			denyed_ip_list = []
			for line in real_deny_list:
				if get_ip(line) and line.find('#') != 0: 
					ip = get_ip(line)
					
					if ip == server_ip:
						i = 0
						
						for line in deny_lines:
							if line.find(ip) != -1:
								del deny_lines[i]
							i = i + 1
						
						deny_file = file("/etc/hosts.deny", "w+")
						fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
						for line in deny_lines:
							deny_file.write(line)
						deny_file.write("\n")
						deny_file.close()
						
						continue
					
					cur = conn.cursor()
					cur.execute("SELECT * FROM `blockip` where `ip` = '" + str(ip) + "'")
					rows = cur.fetchone()
					cur.close()
					
					if rows != None:
						continue
					
					cur = conn.cursor()
					cur.execute("INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '" + str(configloader.get_config().NODE_ID) + "', '" + str(ip) + "', unix_timestamp())")
					cur.close()
					
					logging.info("Block ip:" + str(ip))
					
					denyed_ip_list.append(ip)
					
			cur = conn.cursor()
			cur.execute("SELECT * FROM `blockip` where `datetime`>unix_timestamp()-60")
			rows = cur.fetchall()
			cur.close()
			
			deny_str = "";
			deny_str_at = "";
			
			for row in rows:
				node = row[1]
				ip = get_ip(row[2])
				
				if ip != None:
				
					if str(node) == str(configloader.get_config().NODE_ID):
						if configloader.get_config().ANTISSATTACK == 1 and configloader.get_config().CLOUDSAFE == 1 and ip not in denyed_ip_list:
							deny_str_at = deny_str_at + "\nALL: " + str(ip)
							os.system('route add -host %s gw 127.0.0.1' % str(ip))
							logging.info("Remote Block ip:" + str(ip))
					else:
						deny_str = deny_str + "\nALL: " + str(ip)
						logging.info("Remote Block ip:" + str(ip))
						os.system('route add -host %s gw 127.0.0.1' % str(ip))
				
			
			deny_file=open('/etc/hosts.deny','a')
			fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
			deny_file.write(deny_str + "\n")
			deny_file.close()
			
			if configloader.get_config().ANTISSATTACK == 1 and configloader.get_config().CLOUDSAFE == 1:
				deny_file=open('/etc/hosts.deny','a')
				fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
				deny_file.write(deny_str_at + "\n")
				deny_file.close()
				
					
			
			
			cur = conn.cursor()
			cur.execute("SELECT * FROM `unblockip` where `datetime`>unix_timestamp()-60")
			rows = cur.fetchall()
			cur.close()
			
			conn.close()
			
			deny_file = open('/etc/hosts.deny')
			fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
			deny_lines = deny_file.readlines()
			deny_file.close()
			
			i = 0
			
			for line in deny_lines:
				for row in rows:
					ip = str(row[1])
					if line.find(ip) != -1:
						del deny_lines[i]
						os.system('route del -host %s gw 127.0.0.1' % str(ip))
						logging.info("Unblock ip:" + str(ip))
				i = i + 1
			
			deny_file = file("/etc/hosts.deny", "w+")
			fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
			for line in deny_lines:
				deny_file.write(line)
			deny_file.write("\n")
			deny_file.close()
				
		except BaseException:
			logging.error("Auto block thread error")
		
		start_line = file_len("/etc/hosts.deny")
	
