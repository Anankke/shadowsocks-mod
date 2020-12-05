#!/bin/bash
# EXFLUX Shadowsocks-Python3 Backend
# Version :1.0
# Updata time : 2020/12/6

#check root
[ $(id -u) != "0" ] && { echo "Error : Please run as root!"; exit 1; }
unlink $0   

##fonts color
Green="\033[32m" 
Red="\033[31m" 
Yellow="\033[33m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#notification information
Info="${Green}[Info]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[Error]${Font}"
Notification="${Yellow}[Notification]${Font}"

# addr
config="/root/shadowsocks/userapiconfig.py"
Github="https://github.com/Cieonsers/ssrmu.git"
Libsodiumr_file="/usr/local/lib/libsodium.so"

get_ip(){
	ip=$(curl -s https://ipinfo.io/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ip.sb/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.ipify.org)
	[[ -z $ip ]] && ip=$(curl -s https://ip.seeip.org)
	[[ -z $ip ]] && ip=$(curl -s https://ifconfig.co/ip)
	[[ -z $ip ]] && ip=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && ip=$(curl -s icanhazip.com)
	[[ -z $ip ]] && ip=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
	[[ -z $ip ]] && echo -e "\n Cannot get ip!\n" && exit
}

check_system(){
	clear
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
	if [[ ${release} == "centos" ]] && [[ ${res} -eq 6 ]]; then
	echo -e "Unsupported System: [${release} ${bit}] . "
	echo -e "Please Choose ${Yellow} Centos7.x / Debian / Ubuntu ${Font} to deploy."
	exit 0;
	else
	echo -e "Supported System:[${release} ${bit}]"
	fi
}

optimize(){
	clear
	echo "fs.file-max = 51200" > /etc/sysctl.conf
	echo "net.core.rmem_max = 67108864" >> /etc/sysctl.conf
	echo "net.core.wmem_max = 67108864" >> /etc/sysctl.conf
	echo "net.core.netdev_max_backlog = 250000" >> /etc/sysctl.conf
	echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_tw_recycle = 0" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_fin_timeout = 30" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_keepalive_time = 1200" >> /etc/sysctl.conf
	echo "net.ipv4.ip_local_port_range = 10000 65000" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_max_syn_backlog = 8192" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_max_tw_buckets = 5000" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_rmem = 4096 87380 67108864" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_wmem = 4096 65536 67108864" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
	echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
	echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
	echo "* soft nofile 65535" > /etc/security/limits.conf
	echo "* hard nofile 65535" >> /etc/security/limits.conf
	echo "* soft nproc 65535" >> /etc/security/limits.conf
	echo "* hard nproc 65535" >> /etc/security/limits.conf
	sysctl -p
}

node_install_start_for_centos(){
	clear
    yum clean all && rm -rf /var/cache/yum && yum update -y
	yum install epel-release -y && yum makecache
    yum install git net-tools htop ntp -y
    yum install libsodium -y
    yum install python36 python36-pip -y
	yum update nss curl iptables -y
	# wget --no-check-certificate https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz
	# tar xf libsodium-1.0.18.tar.gz && cd libsodium-1.0.18
	# ./configure && make -j2 && make install
	# echo /usr/local/lib > /etc/ld.so.conf.d/usr_local_lib.conf
	# ldconfig
	# clear
	# [[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} Failed to install libsodium  !" && exit 1
	# echo && echo -e "${Info} Successfully installed libsodium  !" && echo
	cd /root
	# yum -y install python-setuptools
	# easy_install pip
	git clone ${Github} "/root/shadowsocks"
	cd shadowsocks
	pip3 install -r requirements.txt
	pip3 install cymysql
	cp apiconfig.py userapiconfig.py
	cp config.json user-config.json
}

node_install_start_for_debian(){
	clear
	apt-get update -y
	apt-get install git curl ntpdate iptables unzip zip build-essential -y
	wget --no-check-certificate https://download.libsodium.org/libsodium/releases/libsodium-1.0.18.tar.gz
	tar xf libsodium-1.0.18.tar.gz && cd libsodium-1.0.18
	./configure && make -j2 && make install
	ldconfig
	clear
	[[ ! -e ${Libsodiumr_file} ]] && echo -e "${Error} Failed to install libsodium !" && exit 1
	echo && echo -e "${Info} Successfully installed libsodium !" && echo
	cd /root
	apt-get install python3 python3-pip -y
	git clone ${Github} "/root/shadowsocks"
	cd shadowsocks
	pip3 install -r requirements.txt
	pip3 install cymysql
	cp apiconfig.py userapiconfig.py
	cp config.json user-config.json
}

api_new(){
    clear
	echo -e "Config Dir:${config}"
	read -p "Webapi_URL: " WEBAPI_URL
	read -p "muKey:" WEBAPI_TOKEN
	read -p "Noed_ID:  " NODE_ID
	read -p "Mu_Suffix(default: microsoft.com):  " MU_SUFFIX
	read -p "Install Monitor(default: Y)(Y/N):  " MONITOR
	MONITOR=${MONITOR:-"Y"} #Deploy Monitor
	if [[ ${release} == "centos" ]];then
	node_install_start_for_centos
	else
	node_install_start_for_debian
	fi
	cd /root/shadowsocks
	echo -e "modify Config.py...\n"
	get_ip
	WEBAPI_URL=${WEBAPI_URL:-"http://${ip}"}
	sed -i '/WEBAPI_URL/c \WEBAPI_URL = '\'${WEBAPI_URL}\''' ${config}
	WEBAPI_TOKEN=${WEBAPI_TOKEN:-"mupass"}
	sed -i '/WEBAPI_TOKEN/c \WEBAPI_TOKEN = '\'${WEBAPI_TOKEN}\''' ${config}
	NODE_ID=${NODE_ID:-"3"}
	sed -i '/NODE_ID/c \NODE_ID = '${NODE_ID}'' ${config}
	MU_SUFFIX=${MU_SUFFIX:-"microsoft.com"}
	sed -i '/MU_SUFFIX/c \MU_SUFFIX = '\'${MU_SUFFIX}\''' ${config}
	
	#Monitor Service
	if [[ ${MONITOR} == "Y" || ${MONITOR} == "y" ]];then
	crontab -l > crontab_monitor
	echo "30 4 * * * $(which systemctl) restart ssr" >> crontab_monitor
	crontab crontab_monitor
	rm -rf crontab_monitor
	fi
}

api_old(){
	clear
	echo -e "Config Dir:${config}"
	read -p "Enter a new node-backend dir(digits not allowed!): " NODE_LIST
	read -p "Webapi_URL: " WEBAPI_URL
	read -p "muKey:" WEBAPI_TOKEN
	read -p "Node_ID:  " NODE_ID
	read -p "Mu_Suffix(default: microsoft.com):  " MU_SUFFIX
	read -p "Install Monitor(default: Y)(Y/N):  " MONITOR
	NODE_LIST=${NODE_LIST:-"ssrmu"} #default: ssrmu
	MONITOR=${MONITOR:-"Y"} #Deploy Monitor
	git clone ${Github} "/root/${NODE_LIST}"
	if [ ! -d "/root/${NODE_LIST}" ]; then
		echo -e "${Error} Failed to download , please check to install Git"
		exit 1
	fi
	cd "/root/${NODE_LIST}"
	pip3 install -r requirements.txt
	pip3 install cymysql
	cp apiconfig.py userapiconfig.py
	cp config.json user-config.json
	cp ssr.service ${NODE_LIST}.service
	echo -e "modify Config.py...\n"
	get_ip
	#replay dir
	WEBAPI_URL=${WEBAPI_URL:-"http://${ip}"}
	sed -i '/WEBAPI_URL/c \WEBAPI_URL = '\'${WEBAPI_URL}\''' "/root/${NODE_LIST}/userapiconfig.py"
	WEBAPI_TOKEN=${WEBAPI_TOKEN:-"marisn"}
	sed -i '/WEBAPI_TOKEN/c \WEBAPI_TOKEN = '\'${WEBAPI_TOKEN}\''' "/root/${NODE_LIST}/userapiconfig.py"
	NODE_ID=${NODE_ID:-"3"}
	sed -i '/NODE_ID/c \NODE_ID = '${NODE_ID}'' "/root/${NODE_LIST}/userapiconfig.py"
	MU_SUFFIX=${MU_SUFFIX:-"microsoft.com"}
	sed -i '/MU_SUFFIX/c \MU_SUFFIX = '\'${MU_SUFFIX}\''' "/root/${NODE_LIST}/userapiconfig.py"
	#replay service
	sed -i "s/ssr/${NODE_LIST}/" ${NODE_LIST}.service
	sed -i "s/shadowsocks/${NODE_LIST}/" ${NODE_LIST}.service
	
	#Monitor Service
	if [[ ${MONITOR} == "Y" || ${MONITOR} == "y" ]];then
	crontab -l > crontab_monitor
	echo "30 4 * * * $(which systemctl) restart ${NODE_LIST}" >> crontab_monitor
	crontab crontab_monitor
	rm -rf crontab_monitor
	fi
}

db_new(){
	clear
	echo -e "Config Dir:${config}"
	read -p "MYSQL_HOST: " MYSQL_HOST
	read -p "MYSQL_DB:" MYSQL_DB
	read -p "MYSQL_PORT:" MYSQL_PORT
	read -p "MYSQL_USER:" MYSQL_USER
	read -p "MYSQL_PASS:" MYSQL_PASS
	read -p "NODE_ID:  " NODE_ID
	read -p "MU_SUFFIX(default: microsoft.com):  " MU_SUFFIX
	read -p "Install Monitor(default: Y)(Y/N):  " MONITOR
	MONITOR=${MONITOR:-"Y"} #Deploy Monitor
	if [[ ${release} == "centos" ]];then
	node_install_start_for_centos
	else
	node_install_start_for_debian
	fi
	cd /root/shadowsocks
	echo -e "modify Config.py...\n"
	get_ip
	sed -i '/API_INTERFACE/c \API_INTERFACE = '\'glzjinmod\''' ${config}
	MYSQL_HOST=${MYSQL_HOST:-"${ip}"}
	sed -i '/MYSQL_HOST/c \MYSQL_HOST = '\'${MYSQL_HOST}\''' ${config}
	MYSQL_DB=${MYSQL_DB:-"sspanel"}
	sed -i '/MYSQL_DB/c \MYSQL_DB = '\'${MYSQL_DB}\''' ${config}
	MYSQL_USER=${MYSQL_USER:-"root"}
	sed -i '/MYSQL_USER/c \MYSQL_USER = '\'${MYSQL_USER}\''' ${config}
	MYSQL_PASS=${MYSQL_PASS:-"root"}
	sed -i '/MYSQL_PASS/c \MYSQL_PASS = '\'${MYSQL_PASS}\''' ${config}
	MYSQL_PORT=${MYSQL_PORT:-"3306"}
	sed -i '/MYSQL_PORT/c \MYSQL_PORT = '${MYSQL_PORT}'' ${config}
	NODE_ID=${NODE_ID:-"3"}
	sed -i '/NODE_ID/c \NODE_ID = '${NODE_ID}'' ${config}
	MU_SUFFIX=${MU_SUFFIX:-"microsoft.com"}
	sed -i '/MU_SUFFIX/c \MU_SUFFIX = '\'${MU_SUFFIX}\''' ${config}
	
	#Monitor Service
	if [[ ${MONITOR} == "Y" || ${MONITOR} == "y" ]];then
	crontab -l > crontab_monitor
	echo "30 4 * * * $(which systemctl) restart ssr" >> crontab_monitor
	crontab crontab_monitor
	rm -rf crontab_monitor
	fi
}

db_old(){
    clear
	echo -e "Config Dir:${config}"
	read -p "Enter a new node-backend dir(digits not allowed!)(default:  ssrmu): " NODE_LIST
	read -p "MYSQL_HOST: " MYSQL_HOST
	read -p "MYSQL_DB:" MYSQL_DB
	read -p "MYSQL_PORT:" MYSQL_PORT
	read -p "MYSQL_USER:" MYSQL_USER
	read -p "MYSQL_PASS:" MYSQL_PASS
	read -p "NODE_ID:  " NODE_ID
	read -p "MU_SUFFIX(default: microsoft.com):  " MU_SUFFIX
	read -p "Install Monitor(default: Y)(Y/N):  " MONITOR
	NODE_LIST=${NODE_LIST:-"ssrmu"} #default : ssrmu
	MONITOR=${MONITOR:-"Y"} #Deploy Monitor
	git clone ${Github} "/root/${NODE_LIST}"
	if [ ! -d "/root/${NODE_LIST}" ]; then
		echo -e "${Error} Failed to download , please check to install Git"
		exit 1
	fi
	cd "/root/${NODE_LIST}"
	pip3 install -r requirements.txt
	pip3 install cymysql
	cp apiconfig.py userapiconfig.py
	cp config.json user-config.json
	cp ssr.service ${NODE_LIST}.service
	echo -e "modify Config.py...\n"
	get_ip
	sed -i '/API_INTERFACE/c \API_INTERFACE = '\'glzjinmod\''' "/root/${NODE_LIST}/userapiconfig.py"
	MYSQL_HOST=${MYSQL_HOST:-"${ip}"}
	sed -i '/MYSQL_HOST/c \MYSQL_HOST = '\'${MYSQL_HOST}\''' "/root/${NODE_LIST}/userapiconfig.py"
	MYSQL_DB=${MYSQL_DB:-"sspanel"}
	sed -i '/MYSQL_DB/c \MYSQL_DB = '\'${MYSQL_DB}\''' "/root/${NODE_LIST}/userapiconfig.py"
	MYSQL_USER=${MYSQL_USER:-"root"}
	sed -i '/MYSQL_USER/c \MYSQL_USER = '\'${MYSQL_USER}\''' "/root/${NODE_LIST}/userapiconfig.py"
	MYSQL_PASS=${MYSQL_PASS:-"root"}
	sed -i '/MYSQL_PASS/c \MYSQL_PASS = '\'${MYSQL_PASS}\''' "/root/${NODE_LIST}/userapiconfig.py"
	MYSQL_PORT=${MYSQL_PORT:-"3306"}
	sed -i '/MYSQL_PORT/c \MYSQL_PORT = '${MYSQL_PORT}'' "/root/${NODE_LIST}/userapiconfig.py"
	NODE_ID=${NODE_ID:-"3"}
	sed -i '/NODE_ID/c \NODE_ID = '${NODE_ID}'' "/root/${NODE_LIST}/userapiconfig.py"
	MU_SUFFIX=${MU_SUFFIX:-"microsoft.com"}
	sed -i '/MU_SUFFIX/c \MU_SUFFIX = '\'${MU_SUFFIX}\''' "/root/${NODE_LIST}/userapiconfig.py"
	#replace service
	sed -i "s/ssr/${NODE_LIST}/" ${NODE_LIST}.service
	sed -i "s/shadowsocks/${NODE_LIST}/" ${NODE_LIST}.service
	
	#Monitor service
	if [[ ${MONITOR} == "Y" || ${MONITOR} == "y" ]];then
	crontab -l > crontab_monitor
	echo "30 4 * * * $(which systemctl) restart ${NODE_LIST}" >> crontab_monitor
	crontab crontab_monitor
	rm -rf crontab_monitor
	fi
}

complete_new()
{
	clear
	if [[ ${release} == "centos" ]];then
	#disable firewalld
	systemctl stop firewalld.service
	systemctl disable firewalld.service
	fi
	#delete libsodium
	cd /root && rm -rf libsodium*
	cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime -r >/dev/null 2>&1
	timedatectl set-timezone Asia/Shanghai
	timedatectl
	ntpdate -u cn.pool.ntp.org
	clear
	echo -e "${GreenBG} Deploying optimizition...Please wait... ${Font}"
	optimize
	echo -e "${GreenBG} Creating backend serive...Please wait... ${Font}"
	sleep 2
	if [[ ${release} == "centos" ]];then
	cp /root/shadowsocks/ssr.service /usr/lib/systemd/system/ssr.service
	else
	cp /root/shadowsocks/ssr.service /lib/systemd/system/ssr.service
	fi
	systemctl daemon-reload
	systemctl start ssr
	systemctl enable ssr
	if [[ `ps -ef | grep server.py |grep -v grep | wc -l` -ge 1 ]];then
		echo -e "${OK} ${GreenBG} Backend started ${Font}"
	else
		echo -e "${OK} ${RedBG} Backend not started ${Font}"
		echo -e "Please check!"
		exit 1
	fi
	stdout() {
		echo -e "\033[32m$1\033[0m"
	}
	stdout "CMD：systemctl start ssr"
	stdout "CMD：systemctl stop ssr"
	stdout "CMD：systemctl restart ssr"
	stdout "CMD：systemctl enable ssr"
	stdout "CMD：systemctl disable ssr"
	stdout "CMD：systemctl status ssr"
	#Monitor service
	if [[ ${MONITOR} == "Y" || ${MONITOR} == "y" ]];then
	stdout "Monitor installed,enter to check: crontab -l "
	fi
}

complete_old()
{
	clear
	if [[ ${release} == "centos" ]];then
	cp /root/${NODE_LIST}/${NODE_LIST}.service /usr/lib/systemd/system/${NODE_LIST}.service
	else
	cp /root/${NODE_LIST}/${NODE_LIST}.service /lib/systemd/system/${NODE_LIST}.service
	fi
	systemctl daemon-reload
	systemctl start ${NODE_LIST}
	systemctl enable ${NODE_LIST}
	stdout() {
		echo -e "\033[32m$1\033[0m"
	}
	stdout "CMD: systemctl start ${NODE_LIST}"
	stdout "CMD: systemctl stop ${NODE_LIST}"
	stdout "CMD: systemctl restart ${NODE_LIST}"
	stdout "CMD: systemctl enable ${NODE_LIST}"
	stdout "CMD: systemctl disable ${NODE_LIST}"
	stdout "CMD: systemctl status ${NODE_LIST}"
	#Monitor service
	if [[ ${MONITOR} == "Y" || ${MONITOR} == "y" ]];then
	stdout "Monitor installed,enter to check: crontab -l"
	fi
}

uninstall_node()
{
	clear
	#Detect system
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	read -p "Please enter the dir in /root(default :shadowsocks):" CATALOGUE

	CATALOGUE=${CATALOGUE:-"shadowsocks"} #default: shadowsocks
	if [ ! -d "/root/${CATALOGUE}" ]; then
		echo -e "${Error} NOT FOUND!"
		exit 1
	fi
	if [[ ${CATALOGUE} == "shadowsocks" ]];then
		SERVICE="ssr"
	else
		SERVICE="${CATALOGUE}"
	fi
	systemctl stop ${SERVICE}
	systemctl disable ${SERVICE}
	rm -rf /root/${CATALOGUE}
	if [[ ${release} == "centos" ]];then
		rm -rf /usr/lib/systemd/system/${SERVICE}.service
	else
		rm -rf /lib/systemd/system/${SERVICE}.service
	fi
	clear
	#Final check
	if [ -d "/root/${CATALOGUE}" ]; then
		echo -e "${Notification} File still remain，fail to uninstalled"
	else
		echo -e "${OK} Succefully uninstalled"
		echo -e "${Notification} Please enter to manually delete monitor: crontab -e"
	fi
}

choose_mode()
{
	clear
	echo -e "\033[1;5;31mDocking type：\033[0m"
	echo -e "1.New node"
	echo -e "2.Having one running node"
	echo -e "3.Node uninstalled"
	read -t 30 -p "Choose：" MODE_MS
	case $MODE_MS in
			1)
				if [ -d "/root/shadowsocks" ]; then
					echo -e "${Error} Found installed node,please check"
					exit 1
				fi
				select_mode_new
				;;
			2)
				if [ ! -d "/root/shadowsocks" ]; then
					echo -e "${Error} Not found installed node，please check"
					exit 1
				fi
				select_mode_old
				;;
			3)
				uninstall_node
				;;
			*)
				echo -e "Please enter right option"
				exit 1
				;;
	esac
}

select_mode_new()
{
	clear
	echo -e "\033[1;5;31mDocking type：\033[0m"
	echo -e "1.API Docking"
	echo -e "2.Database Docking"
	read -t 30 -p "Choose：" NODE_MS_NEW
	case $NODE_MS_NEW in
			1)
				api_new
				complete_new
				;;
			2)
				db_new
				complete_new
				;;
			*)
				echo -e "Please enter right option"
				exit 1
				;;
	esac
}

select_mode_old()
{
	clear
	echo -e "\033[1;5;31mDocking type：\033[0m"
	echo -e "1.API Docking"
	echo -e "2.Database Docking"
	read -t 30 -p "Choose：" NODE_MS_OLD
	case $NODE_MS_OLD in
			1)
				api_old
				complete_old
				;;
			2)
				db_old
				complete_old
				;;
			*)
				echo -e "Please enter right option"
				exit 1
				;;
	esac
}

main() {
	check_system
	choose_mode
}

main


