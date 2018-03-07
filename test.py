#coding: utf-8

import net_api
import json
import os

def read_file():
    with open('/var/www/html/web/file/snmp/snmp_api/cisco_ip_info','r') as f:
        ip_list = f.readlines()
        return ip_list

ip_list=read_file()


for i in ip_list:
    args_dict={}
    info=i.strip('\n')
    info = info.split(',')

    ip = info[0]
    comm = info[1]
    args_dict['host']=ip
    args_dict['community']=comm
    args_dict['version']='v2c'


    net_conns=net_api.get_net_conntions(args_dict)
    res = net_conns.get_data()
    info =  json.dumps(res)
    #print info
    file_name = ip + '.json'
    path = "/var/www/html/web/file/snmp/" + file_name
    with open(path,'w') as sw:
	sw.write(info)
