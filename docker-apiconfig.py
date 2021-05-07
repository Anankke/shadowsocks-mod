import os

# Config
NODE_ID = int(os.getenv('NODE_ID'), '0')

MU_SUFFIX = os.getenv('MU_SUFFIX', 'zhaoj.in')
MU_REGEX = os.getenv('MU_REGEX', '%5m%id.%suffix')

SERVER_PUB_ADDR = os.getenv('SERVER_PUB_ADDR', '127.0.0.1')
API_INTERFACE = os.getenv('API_INTERFACE', 'modwebapi')

WEBAPI_URL = os.getenv('WEBAPI_URL', 'https://demo.sspanel.host')
WEBAPI_TOKEN = os.getenv('WEBAPI_TOKEN', 'sspanel')

API_UPDATE_TIME = int(os.getenv('API_UPDATE_TIME', '60'))

"""
get port offset by node->name
HK 1 #9900
then offset is 9900
"""
GET_PORT_OFFSET_BY_NODE_NAME = os.getenv('GET_PORT_OFFSET_BY_NODE_NAME', 'true') == 'true'
