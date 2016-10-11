#!/usr/bin/python
# -*- coding: UTF-8 -*-

import logging
import time
import sys
import os
import socket
from server_pool import ServerPool
import traceback
from shadowsocks import common, shell, lru_cache
from configloader import load_config, get_config
import importloader
import platform
import datetime
import fcntl


switchrule = None
db_instance = None

class DbTransfer(object):
	def __init__(self):
		import threading
		self.last_update_transfer = {}
		self.event = threading.Event()
		self.port_uid_table = {}
		self.uid_port_table = {}
		self.old_md5_users = {}
		self.node_speedlimit = 0.00
		self.traffic_rate = 0.0

		self.detect_text_list = {}
		self.detect_text_ischanged = False

		self.detect_hex_list = {}
		self.detect_hex_ischanged = False

	def update_all_user(self, dt_transfer):
		import cymysql
		update_transfer = {}

		query_head = 'UPDATE user'
		query_sub_when = ''
		query_sub_when2 = ''
		query_sub_in = None

		alive_user_count = 0
		bandwidth_thistime = 0

		if get_config().MYSQL_SSL_ENABLE == 1:
			conn = cymysql.connect(host=get_config().MYSQL_HOST, port=get_config().MYSQL_PORT, user=get_config().MYSQL_USER,
										passwd=get_config().MYSQL_PASS, db=get_config().MYSQL_DB, charset='utf8',ssl={'ca':get_config().MYSQL_SSL_CA,'cert':get_config().MYSQL_SSL_CERT,'key':get_config().MYSQL_SSL_KEY})
		else:
			conn = cymysql.connect(host=get_config().MYSQL_HOST, port=get_config().MYSQL_PORT, user=get_config().MYSQL_USER,
										passwd=get_config().MYSQL_PASS, db=get_config().MYSQL_DB, charset='utf8')

		conn.autocommit(True)

		for id in dt_transfer.keys():
			if dt_transfer[id][0] == 0 and dt_transfer[id][1] == 0:
				continue

			query_sub_when += ' WHEN %s THEN u+%s' % (id, dt_transfer[id][0] * self.traffic_rate)
			query_sub_when2 += ' WHEN %s THEN d+%s' % (id, dt_transfer[id][1] * self.traffic_rate)
			update_transfer[id] = dt_transfer[id]

			alive_user_count = alive_user_count + 1

			cur = conn.cursor()
			cur.execute("INSERT INTO `user_traffic_log` (`id`, `user_id`, `u`, `d`, `Node_ID`, `rate`, `traffic`, `log_time`) VALUES (NULL, '" + str(self.port_uid_table[id]) + "', '" + str(dt_transfer[id][0]) +"', '" + str(dt_transfer[id][1]) + "', '" + str(get_config().NODE_ID) + "', '" + str(self.traffic_rate) + "', '" + self.trafficShow((dt_transfer[id][0]+dt_transfer[id][1]) * self.traffic_rate) + "', unix_timestamp()); ")
			cur.close()


			bandwidth_thistime = bandwidth_thistime + ((dt_transfer[id][0] + dt_transfer[id][1]) * self.traffic_rate)

			if query_sub_in is not None:
				query_sub_in += ',%s' % id
			else:
				query_sub_in = '%s' % id
		if query_sub_when != '':
			query_sql = query_head + ' SET u = CASE port' + query_sub_when + \
						' END, d = CASE port' + query_sub_when2 + \
						' END, t = unix_timestamp() ' + \
						' WHERE port IN (%s)' % query_sub_in

			cur = conn.cursor()
			cur.execute(query_sql)
			cur.close()

		cur = conn.cursor()
		cur.execute("UPDATE `ss_node` SET `node_heartbeat`=unix_timestamp(),`node_bandwidth`=`node_bandwidth`+'" + str(bandwidth_thistime) + "' WHERE `id` = " +  str(get_config().NODE_ID) + " ; ")
		cur.close()

		cur = conn.cursor()
		cur.execute("INSERT INTO `ss_node_online_log` (`id`, `node_id`, `online_user`, `log_time`) VALUES (NULL, '" + str(get_config().NODE_ID) + "', '" + str(alive_user_count) + "', unix_timestamp()); ")
		cur.close()


		cur = conn.cursor()
		cur.execute("INSERT INTO `ss_node_info` (`id`, `node_id`, `uptime`, `load`, `log_time`) VALUES (NULL, '" + str(get_config().NODE_ID) + "', '" + str(self.uptime()) + "', '" + str(self.load()) + "', unix_timestamp()); ")
		cur.close()

		online_iplist = ServerPool.get_instance().get_servers_iplist()
		for id in online_iplist.keys():
			for ip in online_iplist[id]:
				cur = conn.cursor()
				cur.execute("INSERT INTO `alive_ip` (`id`, `nodeid`,`userid`, `ip`, `datetime`) VALUES (NULL, '" + str(get_config().NODE_ID) + "','" + str(self.port_uid_table[id]) + "', '" + str(ip) + "', unix_timestamp())")
				cur.close()

		detect_log_list = ServerPool.get_instance().get_servers_detect_log()
		for port in detect_log_list.keys():
			for rule_id in detect_log_list[port]:
				cur = conn.cursor()
				cur.execute("INSERT INTO `detect_log` (`id`, `user_id`, `list_id`, `datetime`, `node_id`) VALUES (NULL, '" + str(self.port_uid_table[port]) + "', '" + str(rule_id) + "', UNIX_TIMESTAMP(), '" + str(get_config().NODE_ID) + "')")
				cur.close()


		deny_str = ""
		if platform.system() == 'Linux' and get_config().ANTISSATTACK == 1 :
			wrong_iplist = ServerPool.get_instance().get_servers_wrong()
			server_ip = socket.gethostbyname(get_config().MYSQL_HOST)
			for id in wrong_iplist.keys():
				for ip in wrong_iplist[id]:
					realip = ""
					is_ipv6 = False
					if common.is_ip(ip) != False:
						if(common.is_ip(ip) == socket.AF_INET):
							realip = ip
						else:
							if common.match_ipv4_address(ip) != None:
								realip = common.match_ipv4_address(ip)
							else:
								is_ipv6 = True
								realip = ip
					else:
						continue

					if str(realip) == str(server_ip):
						continue

					cur = conn.cursor()
					cur.execute("SELECT * FROM `blockip` where `ip` = '" + str(realip) + "'")
					rows = cur.fetchone()
					cur.close()


					if rows != None:
						continue
					if get_config().CLOUDSAFE == 1:
						cur = conn.cursor()
						cur.execute("INSERT INTO `blockip` (`id`, `nodeid`, `ip`, `datetime`) VALUES (NULL, '" + str(get_config().NODE_ID) + "', '" + str(realip) + "', unix_timestamp())")
						cur.close()
					else:
						if is_ipv6 == False:
							os.system('route add -host %s gw 127.0.0.1' % str(realip))
							deny_str = deny_str + "\nALL: " + str(realip)
						else:
							os.system('ip -6 route add ::1/128 via %s/128' % str(realip))
							deny_str = deny_str + "\nALL: [" + str(realip) +"]/128"

						logging.info("Local Block ip:" + str(realip))
				if get_config().CLOUDSAFE == 0:
					deny_file=open('/etc/hosts.deny','a')
					fcntl.flock(deny_file.fileno(),fcntl.LOCK_EX)
					deny_file.write(deny_str + "\n")
					deny_file.close()
		conn.close()
		return update_transfer

	def uptime(self):
		with open('/proc/uptime', 'r') as f:
			return float(f.readline().split()[0])

	def load(self):
		import os
		return os.popen("cat /proc/loadavg | awk '{ print $1\" \"$2\" \"$3 }'").readlines()[0]

	def trafficShow(self,Traffic):
		if Traffic<1024 :
			return str(round((Traffic),2))+"B";

		if Traffic<1024*1024 :
			return str(round((Traffic/1024),2))+"KB";

		if Traffic<1024*1024*1024 :
			return str(round((Traffic/1024/1024),2))+"MB";

		return str(round((Traffic/1024/1024/1024),2))+"GB";

	def push_db_all_user(self):
		#更新用户流量到数据库
		last_transfer = self.last_update_transfer
		curr_transfer = ServerPool.get_instance().get_servers_transfer()
		#上次和本次的增量
		dt_transfer = {}
		for id in curr_transfer.keys():
			if id in last_transfer:
				if curr_transfer[id][0] + curr_transfer[id][1] - last_transfer[id][0] - last_transfer[id][1] <= 0:
					continue
				if last_transfer[id][0] <= curr_transfer[id][0] and \
						last_transfer[id][1] <= curr_transfer[id][1]:
					dt_transfer[id] = [curr_transfer[id][0] - last_transfer[id][0],
										curr_transfer[id][1] - last_transfer[id][1]]
				else:
					dt_transfer[id] = [curr_transfer[id][0], curr_transfer[id][1]]
			else:
				if curr_transfer[id][0] + curr_transfer[id][1] <= 0:
					continue
				dt_transfer[id] = [curr_transfer[id][0], curr_transfer[id][1]]
		update_transfer = self.update_all_user(dt_transfer)
		for id in update_transfer.keys():
			last = self.last_update_transfer.get(id, [0,0])
			self.last_update_transfer[id] = [last[0] + update_transfer[id][0], last[1] + update_transfer[id][1]]

	def pull_db_all_user(self):
		import cymysql
		#数据库所有用户信息
		try:
			switchrule = importloader.load('switchrule')
			keys = switchrule.getKeys()
		except Exception as e:
			keys = ['id' , 'port', 'u', 'd', 'transfer_enable', 'passwd', 'enable' ,'method','protocol','protocol_param','obfs','obfs_param','node_speedlimit','forbidden_ip','forbidden_port','disconnect_ip','is_multi_user']

		if get_config().MYSQL_SSL_ENABLE == 1:
			conn = cymysql.connect(host=get_config().MYSQL_HOST, port=get_config().MYSQL_PORT, user=get_config().MYSQL_USER,
										passwd=get_config().MYSQL_PASS, db=get_config().MYSQL_DB, charset='utf8',ssl={'ca':get_config().MYSQL_SSL_CA,'cert':get_config().MYSQL_SSL_CERT,'key':get_config().MYSQL_SSL_KEY})
		else:
			conn = cymysql.connect(host=get_config().MYSQL_HOST, port=get_config().MYSQL_PORT, user=get_config().MYSQL_USER,
										passwd=get_config().MYSQL_PASS, db=get_config().MYSQL_DB, charset='utf8')
		conn.autocommit(True)

		cur = conn.cursor()

		cur.execute("SELECT `node_group`,`node_class`,`node_speedlimit`,`traffic_rate` FROM ss_node where `id`='" + str(get_config().NODE_ID) + "' AND (`node_bandwidth`<`node_bandwidth_limit` OR `node_bandwidth_limit`=0)")
		nodeinfo = cur.fetchone()

		if nodeinfo == None :
			rows = []
			cur.close()
			conn.commit()
			conn.close()
			return rows

		cur.close()

		self.node_speedlimit = float(nodeinfo[2])
		self.traffic_rate = float(nodeinfo[3])

		if nodeinfo[0] == 0 :
			node_group_sql = ""
		else:
			node_group_sql = "AND `node_group`=" + str(nodeinfo[0])

		cur = conn.cursor()
		cur.execute("SELECT " + ','.join(keys) + " FROM user WHERE `class`>="+ str(nodeinfo[1]) +" "+node_group_sql+" AND`enable`=1 AND `expire_in`>now() AND `transfer_enable`>`u`+`d`")
		rows = []
		for r in cur.fetchall():
			d = {}
			for column in range(len(keys)):
				d[keys[column]] = r[column]
			rows.append(d)
		cur.close()

		#读取审计规则,数据包匹配部分
		keys_detect = ['id','regex']

		cur = conn.cursor()
		cur.execute("SELECT " + ','.join(keys_detect) + " FROM detect_list where `type` = 1")

		exist_id_list = []

		for r in cur.fetchall():
			id = long(r[0])
			exist_id_list.append(id)
			if r[0] not in self.detect_text_list:
				d = {}
				d['id'] = id
				d['regex'] = r[1]
				self.detect_text_list[id] = d
				self.detect_text_ischanged = True
			else:
				if r[1] != self.detect_text_list[r[0]]['regex']:
					del self.detect_text_list[id]
					d = {}
					d['id'] = r[0]
					d['regex'] = r[1]
					self.detect_text_list[id] = d
					self.detect_text_ischanged = True

		deleted_id_list = []
		for id in self.detect_text_list:
			if id not in exist_id_list:
				deleted_id_list.append(id)
				self.detect_text_ischanged = True


		for id in deleted_id_list:
			del self.detect_text_list[id]


		cur = conn.cursor()
		cur.execute("SELECT " + ','.join(keys_detect) + " FROM detect_list where `type` = 2")

		exist_id_list = []

		for r in cur.fetchall():
			id = long(r[0])
			exist_id_list.append(id)
			if r[0] not in self.detect_hex_list:
				d = {}
				d['id'] = id
				d['regex'] = r[1]
				self.detect_hex_list[id] = d
				self.detect_hex_ischanged = True
			else:
				if r[1] != self.detect_hex_list[r[0]]['regex']:
					del self.detect_hex_list[id]
					d = {}
					d['id'] = r[0]
					d['regex'] = r[1]
					self.detect_hex_list[id] = d
					self.detect_hex_ischanged = True

		deleted_id_list = []
		for id in self.detect_hex_list:
			if id not in exist_id_list:
				deleted_id_list.append(id)
				self.detect_hex_ischanged = True


		for id in deleted_id_list:
			del self.detect_hex_list[id]

		cur.close()
		conn.close()
		return rows

	def cmp(self, val1, val2):
		if type(val1) is bytes:
			val1 = common.to_str(val1)
		if type(val2) is bytes:
			val2 = common.to_str(val2)
		return val1 == val2

	def del_server_out_of_bound_safe(self, last_rows, rows):
		#停止超流量的服务
		#启动没超流量的服务
		#需要动态载入switchrule，以便实时修改规则


		try:
			switchrule = importloader.load('switchrule')
		except Exception as e:
			logging.error('load switchrule.py fail')
		cur_servers = {}
		new_servers = {}

		md5_users = {}
		md5_changed = False

		for row in rows:
			md5_users[row['id']] = row.copy()
			del md5_users[row['id']]['u']
			del md5_users[row['id']]['d']
			if md5_users[row['id']]['disconnect_ip'] == None:
				md5_users[row['id']]['disconnect_ip'] = ''

			if md5_users[row['id']]['forbidden_ip'] == None:
				md5_users[row['id']]['forbidden_ip'] = ''

			if md5_users[row['id']]['forbidden_port'] == None:
				md5_users[row['id']]['forbidden_port'] = ''
			md5_users[row['id']]['md5'] = common.get_md5(str(row['id']) + row['passwd'] + row['method'] + row['obfs'] + row['protocol'])

			if row['id'] in self.old_md5_users:
				for key in md5_users[row['id']]:
					if not self.cmp(self.old_md5_users[row['id']][key], md5_users[row['id']][key]):
						md5_changed = True

		for old_user in self.old_md5_users:
			if old_user not in md5_users:
				md5_changed = True

		for row in rows:
			try:
				allow = switchrule.isTurnOn(row) and row['enable'] == 1 and row['u'] + row['d'] < row['transfer_enable']
			except Exception as e:
				allow = False

			port = row['port']
			passwd = common.to_bytes(row['passwd'])
			cfg = {'password': passwd}

			self.port_uid_table[row['port']] = row['id']
			self.uid_port_table[row['id']] = row['port']

			read_config_keys = ['method', 'obfs','obfs_param' , 'protocol', 'protocol_param' ,'forbidden_ip', 'forbidden_port' , 'node_speedlimit','forbidden_ip','forbidden_port','disconnect_ip','is_multi_user']

			for name in read_config_keys:
				if name in row and row[name]:
					cfg[name] = row[name]



			merge_config_keys = ['password'] + read_config_keys
			for name in cfg.keys():
				if hasattr(cfg[name], 'encode'):
					cfg[name] = cfg[name].encode('utf-8')

			if 'node_speedlimit' in cfg:
				if float(self.node_speedlimit) > 0.0 or float(cfg['node_speedlimit']) > 0.0 :
					cfg['node_speedlimit'] = max(float(self.node_speedlimit),float(cfg['node_speedlimit']))
			else:
				cfg['node_speedlimit'] = max(float(self.node_speedlimit),float(0.00))

			if 'disconnect_ip' not in cfg:
				cfg['disconnect_ip'] = ''

			if 'forbidden_ip' not in cfg:
				cfg['forbidden_ip'] = ''

			if 'forbidden_port' not in cfg:
				cfg['forbidden_port'] = ''

			if 'protocol_param' not in cfg:
				cfg['protocol_param'] = ''

			if 'obfs_param' not in cfg:
				cfg['obfs_param'] = ''

			if 'is_multi_user' not in cfg:
				cfg['is_multi_user'] = 0

			if port not in cur_servers:
				cur_servers[port] = passwd
			else:
				logging.error('more than one user use the same port [%s]' % (port,))
				continue

			if get_config().MULTI_THREAD == 0:
				cfg['node_speedlimit'] = 0.00

			cfg['detect_text_list'] = self.detect_text_list.copy()
			cfg['detect_hex_list'] = self.detect_hex_list.copy()

			cfg['users_table'] = md5_users.copy()


			if ServerPool.get_instance().server_is_run(port) > 0:
				if not allow:
					logging.info('db stop server at port [%s]' % (port,))
					ServerPool.get_instance().cb_del_server(port)
					if port in self.last_update_transfer:
						del self.last_update_transfer[port]
				else:
					cfgchange = False
					if self.detect_text_ischanged == True or self.detect_hex_ischanged == True:
						cfgchange = True
					if md5_changed == True and row['is_multi_user'] == 1:
						logging.info('Multi user-port info changed,notify changing.....mu port %d' % (port))
						if port in ServerPool.get_instance().tcp_servers_pool:
							ServerPool.get_instance().tcp_servers_pool[port].modify_multi_user_table(md5_users)
						if port in ServerPool.get_instance().tcp_ipv6_servers_pool:
							ServerPool.get_instance().tcp_ipv6_servers_pool[port].modify_multi_user_table(md5_users)
						if port in ServerPool.get_instance().udp_servers_pool:
							ServerPool.get_instance().udp_servers_pool[port].modify_multi_user_table(md5_users)
						if port in ServerPool.get_instance().udp_ipv6_servers_pool:
							ServerPool.get_instance().udp_ipv6_servers_pool[port].modify_multi_user_table(md5_users)

					if port in ServerPool.get_instance().tcp_servers_pool:
						relay = ServerPool.get_instance().tcp_servers_pool[port]
						for name in merge_config_keys:
							if name in cfg and not self.cmp(cfg[name], relay._config[name]):
								cfgchange = True
								break;
					if not cfgchange and port in ServerPool.get_instance().tcp_ipv6_servers_pool:
						relay = ServerPool.get_instance().tcp_ipv6_servers_pool[port]
						for name in merge_config_keys:
							if name in cfg and not self.cmp(cfg[name], relay._config[name]):
								cfgchange = True
								break;
					#config changed
					if cfgchange:
						logging.info('db stop server at port [%s] reason: config changed!' % (port))
						ServerPool.get_instance().cb_del_server(port)
						if port in self.last_update_transfer:
							del self.last_update_transfer[port]
						new_servers[port] = (passwd, cfg)

			elif allow and ServerPool.get_instance().server_run_status(port) is False:
				#new_servers[port] = passwd
				protocol = cfg.get('protocol', ServerPool.get_instance().config.get('protocol', 'origin'))
				obfs = cfg.get('obfs', ServerPool.get_instance().config.get('obfs', 'plain'))
				logging.info('db start server at port [%s] pass [%s] protocol [%s] obfs [%s]' % (port, passwd, protocol, obfs))
				ServerPool.get_instance().new_server(port, cfg)

		ServerPool.get_instance().push_uid_port_table(self.uid_port_table)

		for row in last_rows:
			if row['port'] in cur_servers:
				pass
			else:
				logging.info('db stop server at port [%s] reason: port not exist' % (row['port']))
				ServerPool.get_instance().cb_del_server(row['port'])
				if row['port'] in self.last_update_transfer:
					del self.last_update_transfer[row['port']]
				del self.port_uid_table[row['port']]

		if len(new_servers) > 0:
			from shadowsocks import eventloop
			self.event.wait(eventloop.TIMEOUT_PRECISION + eventloop.TIMEOUT_PRECISION / 2)
			for port in new_servers.keys():
				passwd, cfg = new_servers[port]
				protocol = cfg.get('protocol', ServerPool.get_instance().config.get('protocol', 'origin'))
				obfs = cfg.get('obfs', ServerPool.get_instance().config.get('obfs', 'plain'))
				logging.info('db start server at port [%s] pass [%s] protocol [%s] obfs [%s]' % (port, passwd, protocol, obfs))
				ServerPool.get_instance().new_server(port, cfg)

		self.old_md5_users = md5_users.copy()

	@staticmethod
	def del_servers():
		global db_instance
		for port in [v for v in ServerPool.get_instance().tcp_servers_pool.keys()]:
			if ServerPool.get_instance().server_is_run(port) > 0:
				ServerPool.get_instance().cb_del_server(port)
				if port in db_instance.last_update_transfer:
					del db_instance.last_update_transfer[port]
		for port in [v for v in ServerPool.get_instance().tcp_ipv6_servers_pool.keys()]:
			if ServerPool.get_instance().server_is_run(port) > 0:
				ServerPool.get_instance().cb_del_server(port)
				if port in db_instance.last_update_transfer:
					del db_instance.last_update_transfer[port]

	@staticmethod
	def thread_db(obj):
		import socket
		import time
		global db_instance
		timeout = 60
		socket.setdefaulttimeout(timeout)
		last_rows = []
		db_instance = obj()

		shell.log_shadowsocks_version()
		import resource
		logging.info('current process RLIMIT_NOFILE resource: soft %d hard %d'  % resource.getrlimit(resource.RLIMIT_NOFILE))
		try:
			while True:
				load_config()
				try:
					db_instance.push_db_all_user()
					rows = db_instance.pull_db_all_user()
					db_instance.del_server_out_of_bound_safe(last_rows, rows)
					db_instance.detect_text_ischanged = False
					db_instance.detect_hex_ischanged = False
					last_rows = rows
				except Exception as e:
					trace = traceback.format_exc()
					logging.error(trace)
					#logging.warn('db thread except:%s' % e)
				if db_instance.event.wait(get_config().MYSQL_UPDATE_TIME) or not db_instance.is_all_thread_alive():
					break
		except KeyboardInterrupt as e:
			pass
		db_instance.del_servers()
		ServerPool.get_instance().stop()
		db_instance = None

	@staticmethod
	def thread_db_stop():
		global db_instance
		db_instance.event.set()

	def is_all_thread_alive(self):
		for port in ServerPool.get_instance().thread_pool:
			if not ServerPool.get_instance().thread_pool[port].is_alive():
				return False
		if not ServerPool.get_instance().thread.is_alive():
			return False
		return True

class MuJsonTransfer(DbTransfer):
	def __init__(self):
		super(MuJsonTransfer, self).__init__()

	def update_all_user(self, dt_transfer):
		import json
		rows = None

		config_path = get_config().MUDB_FILE
		with open(config_path, 'rb+') as f:
			rows = json.loads(f.read().decode('utf8'))
			for row in rows:
				if "port" in row:
					port = row["port"]
					if port in dt_transfer:
						row["u"] += dt_transfer[port][0]
						row["d"] += dt_transfer[port][1]

		if rows:
			output = json.dumps(rows, sort_keys=True, indent=4, separators=(',', ': '))
			with open(config_path, 'r+') as f:
				f.write(output)
				f.truncate()

	def pull_db_all_user(self):
		import json
		rows = None

		config_path = get_config().MUDB_FILE
		with open(config_path, 'rb+') as f:
			rows = json.loads(f.read().decode('utf8'))
			for row in rows:
				try:
					if 'forbidden_ip' in row:
						row['forbidden_ip'] = common.IPNetwork(row['forbidden_ip'])
				except Exception as e:
					logging.error(e)
				try:
					if 'forbidden_port' in row:
						row['forbidden_port'] = common.PortRange(row['forbidden_port'])
				except Exception as e:
					logging.error(e)
				try:
					if 'disconnect_ip' in row:
						row['disconnect_ip'] = common.IPNetwork(row['disconnect_ip'])
				except Exception as e:
					logging.error(e)

		return rows
