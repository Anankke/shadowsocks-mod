#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os
import logging
import time
from shadowsocks import shell, eventloop, tcprelay, udprelay, asyncdns, common
import threading
import sys
from socket import *
from configloader import load_config, get_config

class MainThread(threading.Thread):
	def __init__(self, params):
		threading.Thread.__init__(self)
		self.params = params

	def run(self):
		ServerPool._loop(*self.params)

class ServerPool(object):

	instance = None

	def __init__(self):
		shell.check_python()
		self.config = shell.get_config(False)
		self.dns_resolver = asyncdns.DNSResolver()
		if not self.config.get('dns_ipv6', False):
			asyncdns.IPV6_CONNECTION_SUPPORT = False

		self.mgr = None #asyncmgr.ServerMgr()

		self.eventloop_pool = {}
		self.thread_pool = {}
		self.dns_resolver_pool = {}

		self.dns_resolver = asyncdns.DNSResolver()

		self.loop = eventloop.EventLoop()
		self.thread = MainThread( (self.loop, self.dns_resolver, self.mgr) )
		self.thread.start()
		
		self.tcp_servers_pool = {}
		self.tcp_ipv6_servers_pool = {}
		self.udp_servers_pool = {}
		self.udp_ipv6_servers_pool = {}
		self.stat_counter = {}
		
		self.uid_port_table = {}

	@staticmethod
	def get_instance():
		if ServerPool.instance is None:
			ServerPool.instance = ServerPool()
		return ServerPool.instance

	def stop(self):
		for port in self.eventloop_pool:
			self.eventloop_pool[port].stop()
		self.loop.stop()

	@staticmethod
	def _loop(loop, dns_resolver, mgr):
		try:
			if mgr is not None:
				mgr.add_to_loop(loop)
			dns_resolver.add_to_loop(loop)
			loop.run()
		except (KeyboardInterrupt, IOError, OSError) as e:
			logging.error(e)
			import traceback
			traceback.print_exc()
			os.exit(0)
		except Exception as e:
			logging.error(e)
			import traceback
			traceback.print_exc()

	def server_is_run(self, port):
		port = int(port)
		ret = 0
		if port in self.tcp_servers_pool:
			ret = 1
		if port in self.tcp_ipv6_servers_pool:
			ret |= 2
		return ret

	def server_run_status(self, port):
		if 'server' in self.config:
			if port not in self.tcp_servers_pool:
				return False
		if 'server_ipv6' in self.config:
			if port not in self.tcp_ipv6_servers_pool:
				return False
		return True

	def new_server(self, port, user_config):
		ret = True
		port = int(port)
		ipv6_ok = False

		if user_config['node_speedlimit'] == 0.00:
			if 'server_ipv6' in self.config:
				if port in self.tcp_ipv6_servers_pool:
					logging.info("server already at %s:%d" % (self.config['server_ipv6'], port))
					return 'this port server is already running'
				else:
					a_config = self.config.copy()
					a_config.update(user_config)
					if len(a_config['server_ipv6']) > 2 and a_config['server_ipv6'][0] == "[" and a_config['server_ipv6'][-1] == "]":
						a_config['server_ipv6'] = a_config['server_ipv6'][1:-1]
					a_config['server'] = a_config['server_ipv6']
					a_config['server_port'] = port
					a_config['max_connect'] = 128
					a_config['method'] = common.to_str(a_config['method'])
					try:
						logging.info("starting server at [%s]:%d" % (common.to_str(a_config['server']), port))

						tcp_server = tcprelay.TCPRelay(a_config, self.dns_resolver, False, stat_counter=self.stat_counter)
						tcp_server.add_to_loop(self.loop)
						self.tcp_ipv6_servers_pool.update({port: tcp_server})

						udp_server = udprelay.UDPRelay(a_config, self.dns_resolver, False, stat_counter=self.stat_counter)
						udp_server.add_to_loop(self.loop)
						self.udp_ipv6_servers_pool.update({port: udp_server})

						if common.to_str(a_config['server_ipv6']) == "::":
							ipv6_ok = True
					except Exception as e:
						logging.warn("IPV6 %s " % (e,))

			if 'server' in self.config:
				if port in self.tcp_servers_pool:
					logging.info("server already at %s:%d" % (common.to_str(self.config['server']), port))
					return 'this port server is already running'
				else:
					a_config = self.config.copy()
					a_config.update(user_config)
					a_config['server_port'] = port
					a_config['max_connect'] = 128
					a_config['method'] = common.to_str(a_config['method'])
					try:
						logging.info("starting server at %s:%d" % (common.to_str(a_config['server']), port))

						tcp_server = tcprelay.TCPRelay(a_config, self.dns_resolver, False)
						tcp_server.add_to_loop(self.loop)
						self.tcp_servers_pool.update({port: tcp_server})

						udp_server = udprelay.UDPRelay(a_config, self.dns_resolver, False)
						udp_server.add_to_loop(self.loop)
						self.udp_servers_pool.update({port: udp_server})

					except Exception as e:
						if not ipv6_ok:
							logging.warn("IPV4 %s " % (e,))
		else:
			self.dns_resolver_pool[port] = self.dns_resolver = asyncdns.DNSResolver()
			self.eventloop_pool[port] = eventloop.EventLoop()
			self.thread_pool[port] = MainThread( (self.eventloop_pool[port], self.dns_resolver_pool[port], self.mgr) )
			self.thread_pool[port].start()
		
		
			if 'server_ipv6' in self.config:
				if port in self.tcp_ipv6_servers_pool:
					logging.info("server already at %s:%d" % (self.config['server_ipv6'], port))
					return 'this port server is already running'
				else:
					a_config = self.config.copy()
					a_config.update(user_config)
					if len(a_config['server_ipv6']) > 2 and a_config['server_ipv6'][0] == "[" and a_config['server_ipv6'][-1] == "]":
						a_config['server_ipv6'] = a_config['server_ipv6'][1:-1]
					a_config['server'] = a_config['server_ipv6']
					a_config['server_port'] = port
					a_config['max_connect'] = 128
					a_config['method'] = common.to_str(a_config['method'])
					try:
						logging.info("starting server at [%s]:%d" % (common.to_str(a_config['server']), port))

						tcp_server = tcprelay.TCPRelay(a_config, self.dns_resolver_pool[port], False, stat_counter=self.stat_counter)
						tcp_server.add_to_loop(self.eventloop_pool[port])
						self.tcp_ipv6_servers_pool.update({port: tcp_server})

						udp_server = udprelay.UDPRelay(a_config, self.dns_resolver_pool[port], False, stat_counter=self.stat_counter)
						udp_server.add_to_loop(self.eventloop_pool[port])
						self.udp_ipv6_servers_pool.update({port: udp_server})

						if common.to_str(a_config['server_ipv6']) == "::":
							ipv6_ok = True
					except Exception as e:
						logging.warn("IPV6 %s " % (e,))

			if 'server' in self.config:
				if port in self.tcp_servers_pool:
					logging.info("server already at %s:%d" % (common.to_str(self.config['server']), port))
					return 'this port server is already running'
				else:
					a_config = self.config.copy()
					a_config.update(user_config)
					a_config['server_port'] = port
					a_config['max_connect'] = 128
					a_config['method'] = common.to_str(a_config['method'])
					try:
						logging.info("starting server at %s:%d" % (common.to_str(a_config['server']), port))

						tcp_server = tcprelay.TCPRelay(a_config, self.dns_resolver_pool[port], False)
						tcp_server.add_to_loop(self.eventloop_pool[port])
						self.tcp_servers_pool.update({port: tcp_server})

						udp_server = udprelay.UDPRelay(a_config, self.dns_resolver_pool[port], False)
						udp_server.add_to_loop(self.eventloop_pool[port])
						self.udp_servers_pool.update({port: udp_server})

					except Exception as e:
						if not ipv6_ok:
							logging.warn("IPV4 %s " % (e,))

		return True

	def del_server(self, port):
		port = int(port)
		logging.info("del server at %d" % port)
		try:
			udpsock = socket(AF_INET, SOCK_DGRAM)
			udpsock.sendto('%s:%s:0:0' % (get_config().MANAGE_PASS, port), (get_config().MANAGE_BIND_IP, get_config().MANAGE_PORT))
			udpsock.close()
		except Exception as e:
			logging.warn(e)
		return True

	def cb_del_server(self, port):
		port = int(port)
		
		is_not_single = True
		if port in self.eventloop_pool:
			self.eventloop_pool[port].stop()
			is_not_single = False
			del self.eventloop_pool[port]
			
		if port in self.dns_resolver_pool:
			del self.dns_resolver_pool[port]
			
		if port in self.thread_pool:
			del self.thread_pool[port]
		
		if port not in self.tcp_servers_pool:
			logging.info("stopped server at %s:%d already stop" % (self.config['server'], port))
		else:
			logging.info("stopped server at %s:%d" % (self.config['server'], port))
			try:
				self.tcp_servers_pool[port].close(is_not_single)
				del self.tcp_servers_pool[port]
			except Exception as e:
				logging.warn(e)
			try:
				self.udp_servers_pool[port].close(is_not_single)
				del self.udp_servers_pool[port]
			except Exception as e:
				logging.warn(e)

		if 'server_ipv6' in self.config:
			if port not in self.tcp_ipv6_servers_pool:
				logging.info("stopped server at [%s]:%d already stop" % (self.config['server_ipv6'], port))
			else:
				logging.info("stopped server at [%s]:%d" % (self.config['server_ipv6'], port))
				try:
					self.tcp_ipv6_servers_pool[port].close(is_not_single)
					del self.tcp_ipv6_servers_pool[port]
				except Exception as e:
					logging.warn(e)
				try:
					self.udp_ipv6_servers_pool[port].close(is_not_single)
					del self.udp_ipv6_servers_pool[port]
				except Exception as e:
					logging.warn(e)
					
		
		return True

	def get_server_transfer(self, port):
		port = int(port)
		ret = [0, 0]
		if port in self.tcp_servers_pool:
			ret[0] = self.tcp_servers_pool[port].server_transfer_ul
			ret[1] = self.tcp_servers_pool[port].server_transfer_dl
		if port in self.udp_servers_pool:
			ret[0] += self.udp_servers_pool[port].server_transfer_ul
			ret[1] += self.udp_servers_pool[port].server_transfer_dl
		if port in self.tcp_ipv6_servers_pool:
			ret[0] += self.tcp_ipv6_servers_pool[port].server_transfer_ul
			ret[1] += self.tcp_ipv6_servers_pool[port].server_transfer_dl
		if port in self.udp_ipv6_servers_pool:
			ret[0] += self.udp_ipv6_servers_pool[port].server_transfer_ul
			ret[1] += self.udp_ipv6_servers_pool[port].server_transfer_dl
		return ret
		
	def get_mu_server_transfer(self, port):
		port = int(port)
		ret = {}
		if port in self.tcp_servers_pool:
			tempdict = self.tcp_servers_pool[port].mu_server_transfer_ul
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = [0,0]
				ret[self.uid_port_table[id]][0] += tempdict[id]
			tempdict = self.tcp_servers_pool[port].mu_server_transfer_dl
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = [0,0]
				ret[self.uid_port_table[id]][1] += tempdict[id]
			self.tcp_servers_pool[port]. mu_connected_iplist_clean()
		if port in self.tcp_ipv6_servers_pool:
			tempdict = self.tcp_ipv6_servers_pool[port].mu_server_transfer_ul
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = [0,0]
				ret[self.uid_port_table[id]][0] += tempdict[id]
			tempdict = self.tcp_ipv6_servers_pool[port].mu_server_transfer_dl
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = [0,0]
				ret[self.uid_port_table[id]][1] += tempdict[id]
			self.tcp_ipv6_servers_pool[port].mu_connected_iplist_clean()
		return ret

	def get_servers_transfer(self):
		servers = self.tcp_servers_pool.copy()
		servers.update(self.tcp_ipv6_servers_pool)
		servers.update(self.udp_servers_pool)
		servers.update(self.udp_ipv6_servers_pool)
		ret = {}
		for port in servers.keys():
			if servers[port]._config["is_multi_user"] == 0:
				ret[port] = self.get_server_transfer(port)
		for port in servers.keys():
			if servers[port]._config["is_multi_user"] == 1:
				temprets = self.get_mu_server_transfer(port)
				for id in temprets:
					if id in ret:
						ret[id][0] += temprets[id][0]
						ret[id][1] += temprets[id][1]
		return ret
		
	def get_server_iplist(self, port):
		port = int(port)
		ret = []
		if port in self.tcp_servers_pool:
			ret = self.tcp_servers_pool[port].connected_iplist[:]
			self.tcp_servers_pool[port].connected_iplist_clean()
		if port in self.udp_servers_pool:
			templist = self.udp_servers_pool[port].connected_iplist[:]
			for ip in templist:
				if ip not in ret:
					ret.append(ip)
			self.udp_servers_pool[port].connected_iplist_clean()
		if port in self.tcp_ipv6_servers_pool:
			templist = self.tcp_ipv6_servers_pool[port].connected_iplist[:]
			for ip in templist:
				if ip not in ret:
					ret.append(ip)
			self.tcp_ipv6_servers_pool[port].connected_iplist_clean()
		if port in self.udp_ipv6_servers_pool:
			templist = self.udp_ipv6_servers_pool[port].connected_iplist[:]
			for ip in templist:
				if ip not in ret:
					ret.append(ip)
			self.udp_ipv6_servers_pool[port].connected_iplist_clean()
		return ret
		
	def get_mu_server_iplist(self, port):
		port = int(port)
		ret = {}
		if port in self.tcp_servers_pool:
			tempdict = self.tcp_servers_pool[port].mu_connected_iplist.copy()
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = []
				tempret = ret[self.uid_port_table[id]][:]
				for ip in tempdict[id]:
					tempret.append(ip)
				ret[self.uid_port_table[id]] = tempret[:]
			self.tcp_servers_pool[port].mu_connected_iplist_clean()
		if port in self.tcp_ipv6_servers_pool:
			tempdict = self.tcp_ipv6_servers_pool[port].mu_connected_iplist.copy()
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = []
				tempret = ret[self.uid_port_table[id]][:]
				for ip in tempdict[id]:
					tempret.append(ip)
				ret[self.uid_port_table[id]] = tempret[:]
			self.tcp_ipv6_servers_pool[port].mu_connected_iplist_clean()
		return ret
	
	def get_servers_iplist(self):
		servers = self.tcp_servers_pool.copy()
		servers.update(self.tcp_ipv6_servers_pool)
		servers.update(self.udp_servers_pool)
		servers.update(self.udp_ipv6_servers_pool)
		ret = {}
		for port in servers.keys():
			if servers[port]._config["is_multi_user"] == 0:
				templist = self.get_server_iplist(port)
				if templist != [] :
					ret[port] = templist[:]
		for port in servers.keys():
			if servers[port]._config["is_multi_user"] == 1:
				templist = self.get_mu_server_iplist(port)
				for id in templist:
					for ip in templist[id]:
						if id not in ret:
							ret[id] = []
						if ip not in ret[id]:
							tempret = ret[id][:]
							tempret.append(ip)
							ret[id] = tempret[:]
		return ret

	def get_servers_detect_log(self):
		servers = self.tcp_servers_pool.copy()
		servers.update(self.tcp_ipv6_servers_pool)
		servers.update(self.udp_servers_pool)
		servers.update(self.udp_ipv6_servers_pool)
		ret = {}
		for port in servers.keys():
			if servers[port]._config["is_multi_user"] == 0:
				templist = self.get_server_detect_log(port)
				if templist != [] :
					ret[port] = templist[:]
		for port in servers.keys():
			if servers[port]._config["is_multi_user"] == 1:
				templist = self.get_mu_server_detect_log(port)
				for id in templist:
					for itemid in templist[id]:
						if id not in ret:
							ret[id] = []
						if itemid not in ret[id]:
							tempret = ret[id][:]
							tempret.append(itemid)
							ret[id] = tempret[:]
			
		return ret


	def get_server_detect_log(self, port):
		port = int(port)
		ret = []
		if port in self.tcp_servers_pool:
			ret = self.tcp_servers_pool[port].detect_log_list[:]
			self.tcp_servers_pool[port].detect_log_list_clean()
		if port in self.udp_servers_pool:
			templist = self.udp_servers_pool[port].detect_log_list[:]
			for id in templist:
				if id not in ret:
					ret.append(id)
			self.udp_servers_pool[port].detect_log_list_clean()
		if port in self.tcp_ipv6_servers_pool:
			templist = self.tcp_ipv6_servers_pool[port].detect_log_list[:]
			for id in templist:
				if id not in ret:
					ret.append(id)
			self.tcp_ipv6_servers_pool[port].detect_log_list_clean()
		if port in self.udp_ipv6_servers_pool:
			templist = self.udp_ipv6_servers_pool[port].detect_log_list[:]
			for id in templist:
				if id not in ret:
					ret.append(id)
			self.udp_ipv6_servers_pool[port].detect_log_list_clean()
		return ret
		
	def get_mu_server_detect_log(self, port):
		port = int(port)
		ret = {}
		if port in self.tcp_servers_pool:
			tempdict = self.tcp_servers_pool[port].mu_detect_log_list.copy()
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = []
				tempret = ret[self.uid_port_table[id]][:]
				for itemid in tempdict[id]:
					tempret.append(itemid)
				ret[self.uid_port_table[id]] = tempret[:]
		if port in self.tcp_ipv6_servers_pool:
			tempdict = self.tcp_ipv6_servers_pool[port].mu_detect_log_list.copy()
			for id in tempdict:
				if self.uid_port_table[id] not in ret:
					ret[self.uid_port_table[id]] = []
				tempret = ret[self.uid_port_table[id]][:]
				for itemid in tempdict[id]:
					tempret.append(itemid)
				ret[self.uid_port_table[id]] = tempret[:]
		return ret
		
		
		
	def get_server_wrong(self, port):
		port = int(port)
		ret = []
		if port in self.tcp_servers_pool:
			templist = self.tcp_servers_pool[port].wrong_iplist.copy()
			for ip in templist:
				if ip not in ret and templist[ip] < time.time() - 60:
					ret.append(ip)
			self.tcp_servers_pool[port].wrong_iplist_clean()
		if port in self.udp_servers_pool:
			templist = self.udp_servers_pool[port].wrong_iplist.copy()
			for ip in templist:
				if ip not in ret and templist[ip] < time.time() - 60:
					ret.append(ip)
			self.udp_servers_pool[port].wrong_iplist_clean()
		if port in self.tcp_ipv6_servers_pool:
			templist = self.tcp_ipv6_servers_pool[port].wrong_iplist.copy()
			for ip in templist:
				if ip not in ret and templist[ip] < time.time() - 60:
					ret.append(ip)
			self.tcp_ipv6_servers_pool[port].wrong_iplist_clean()
		if port in self.udp_ipv6_servers_pool:
			templist = self.udp_ipv6_servers_pool[port].wrong_iplist.copy()
			for ip in templist:
				if ip not in ret and templist[ip] < time.time() - 60:
					ret.append(ip)
			self.udp_ipv6_servers_pool[port].wrong_iplist_clean()
		return ret
		

	def get_servers_wrong(self):
		servers = self.tcp_servers_pool.copy()
		servers.update(self.tcp_ipv6_servers_pool)
		servers.update(self.udp_servers_pool)
		servers.update(self.udp_ipv6_servers_pool)
		ret = {}
		for port in servers.keys():
			templist = self.get_server_wrong(port)
			if templist != [] :
				ret[port] = templist[:]
		return ret
		
	def push_uid_port_table(self,table):
		self.uid_port_table = table
