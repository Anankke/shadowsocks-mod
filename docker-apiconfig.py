import os

# Config
NODE_ID = int(os.getenv('NODE_ID'), '0')

# hour,set 0 to disable
SPEEDTEST = int(os.getenv('SPEEDTEST', '6'))
CLOUDSAFE = int(os.getenv('CLOUDSAFE', '1'))
ANTISSATTACK = int(os.getenv('ANTISSATTACK', '0'))
AUTOEXEC = int(os.getenv('AUTOEXEC', '0'))

MU_SUFFIX = os.getenv('MU_SUFFIX', 'zhaoj.in')
MU_REGEX = os.getenv('MU_REGEX', '%5m%id.%suffix')

SERVER_PUB_ADDR = os.getenv('SERVER_PUB_ADDR', '127.0.0.1')
API_INTERFACE = os.getenv('API_INTERFACE', 'modwebapi')

WEBAPI_URL = os.getenv('WEBAPI_URL', 'https://zhaoj.in')
WEBAPI_TOKEN = os.getenv('WEBAPI_TOKEN', 'glzjin')

MUDB_FILE = os.getenv('MUDB_FILE', 'mudb.json')

MYSQL_HOST = os.getenv('MYSQL_HOST', '127.0.0.1')
MYSQL_PORT = int(os.getenv('MYSQL_PORT', '3306'))
MYSQL_USER = os.getenv('MYSQL_USER', 'ss')
MYSQL_PASS = os.getenv('MYSQL_PASS', 'ss')
MYSQL_DB = os.getenv('MYSQL_DB', 'shadowsocks')

MYSQL_SSL_ENABLE = os.getenv('MYSQL_SSL_ENABLE', 'false') == 'true'
MYSQL_SSL_CA = os.getenv('MYSQL_SSL_CA', '')
MYSQL_SSL_CERT = os.getenv('MYSQL_SSL_CERT', '')
MYSQL_SSL_KEY = os.getenv('MYSQL_SSL_KEY', '')

API_HOST = os.getenv('API_HOST', '127.0.0.1')
API_PORT = int(os.getenv('API_PORT', '80'))
API_PATH = os.getenv('API_PATH', '/mu/v2/')
API_TOKEN = os.getenv('API_TOKEN', 'abcdef')
API_UPDATE_TIME = int(os.getenv('API_UPDATE_TIME', '60'))

# Manager (ignore this)
MANAGE_PASS = os.getenv('MANAGE_PASS', 'ss233333333')
# if you want manage in other server you should set this value to global ip
MANAGE_BIND_IP = os.getenv('MANAGE_BIND_IP', '127.0.0.1')
# make sure this port is idle
MANAGE_PORT = int(os.getenv('MANAGE_PORT', '23333'))


PRINT_MYSQL_QUERY = os.getenv('PRINT_MYSQL_QUERY', 'false') == 'true'

# second
MYSQL_PUSH_DURATION = int(os.getenv('MYSQL_PUSH_DURATION', '60'))

"""
get port offset by node->name
HK 1 #9900
then offset is 9900
"""
GET_PORT_OFFSET_BY_NODE_NAME = os.getenv('GET_PORT_OFFSET_BY_NODE_NAME', 'true') == 'true'
