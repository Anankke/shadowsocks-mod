from configloader import get_config

def getKeys():
    key_list = ["id", "port", "u", "d", "transfer_enable", "passwd", "enable", "method", "obfs", "obfs_param", "protocol", "protocol_param", "id", "node_speedlimit", "forbidden_ip", "forbidden_port", "is_multi_user"]
    return key_list
    # return key_list + ['plan'] # append the column name 'plan'

def isTurnOn(row):
    return True
    # return row['plan'] == 'B' # then judge here
