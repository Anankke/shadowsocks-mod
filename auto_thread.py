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
import platform

def run_command(command,id):
	value = commands.getoutput(command)
	conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
								passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8')
	conn.autocommit(True)
	cur = conn.cursor()
	cur.execute("INSERT INTO `auto` (`id`, `value`, `sign`, `datetime`,`type`) VALUES (NULL, 'NodeID:" + str(configloader.get_config().NODE_ID) + " Result:\n" + str(value) + "', 'NOT', unix_timestamp(),'2')")
	rows = cur.fetchall()
	cur.close()
	conn.close()

def auto_thread():
	if configloader.get_config().AUTOEXEC == 0 or platform.system() != 'Linux' :
		return
	
	gpg = gnupg.GPG("/tmp/ssshell")
	key_data = open('ssshell.asc').read()
	import_result = gpg.import_keys(key_data)
	public_keys = gpg.list_keys()
	
	while True:
		time.sleep(60)
		
		try:
			if configloader.get_config().MYSQL_SSL_ENABLE == 1:
				conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
											passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8',ssl={'ca':configloader.get_config().MYSQL_SSL_CA,'cert':configloader.get_config().MYSQL_SSL_CERT,'key':configloader.get_config().MYSQL_SSL_KEY})
			else:
				conn = cymysql.connect(host=configloader.get_config().MYSQL_HOST, port=configloader.get_config().MYSQL_PORT, user=configloader.get_config().MYSQL_USER,
											passwd=configloader.get_config().MYSQL_PASS, db=configloader.get_config().MYSQL_DB, charset='utf8')
			conn.autocommit(True)
			cur = conn.cursor()
			cur.execute("SELECT * FROM `auto` where `datetime`>unix_timestamp()-60 AND `type`=1")
			rows = cur.fetchall()
			cur.close()
			
			for row in rows:
				id = row[0]
				data = row[2]
				sign = row[3]
				verify_data = "-----BEGIN PGP SIGNED MESSAGE-----\n" + \
				"Hash: SHA256\n" + \
				"\n" + \
				data + "\n" + \
				"-----BEGIN PGP SIGNATURE-----\n" + \
				"Version: GnuPG v2\n" + \
				"\n" + \
				sign + "\n" + \
				"-----END PGP SIGNATURE-----\n"
				
				verified = gpg.verify(verify_data)
				is_verified = 0
				for key in public_keys:
					if key['keyid'] == verified.key_id:
						is_verified = 1
						break
						
				if is_verified == 1:
					cur = conn.cursor()
					cur.execute("SELECT * FROM `auto`  where `sign`='" + str(configloader.get_config().NODE_ID) + "-" + str(id) + "'")
					if cur.fetchone() == None :
						cur_c = conn.cursor()
						cur_c.execute("INSERT INTO `auto` (`id`, `value`, `sign`, `datetime`,`type`) VALUES (NULL, 'NodeID:" + str(configloader.get_config().NODE_ID) + " Exec Command ID:" + str(configloader.get_config().NODE_ID) + " Starting....', '" + str(configloader.get_config().NODE_ID) + "-" + str(id) + "', unix_timestamp(),'2')")
						cur_c.close()
						
						logging.info("Running the command:" + data)
						thread.start_new_thread(run_command,(data,id))
					cur.close()
				else:
					logging.info("Running the command:" + data)
				
				cur = conn.cursor()
				cur.execute("SELECT * FROM `auto` where `datetime`>unix_timestamp()-60 AND `type`=1")
				rows = cur.fetchall()
				cur.close()
					
			conn.commit()
			conn.close()
		except BaseException:
			logging.error("Auto exec thread error")
	
