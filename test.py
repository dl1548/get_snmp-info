#coding: utf-8

import net_api
import datetime
import json
import os

def read_file():
    with open('/root/net_api/cisco_ip_info','r') as f:
        ip_list = f.readlines()
        return ip_list

ip_list=read_file()


for i in ip_list:
    nowTime=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    args_dict={}
    info=i.strip('\n')
    info = info.split(',')

    ip = info[0]
    comm = info[1]
    args_dict['host']=ip
    args_dict['community']=comm
    args_dict['version']='v2c'

    try:
        net_conns=net_api.get_net_conntions(args_dict)
        res = net_conns.get_data()
        info =  json.dumps(res)
        #print info
        file_name = ip + '.json'
        path = "/root/net_api/" + file_name
        with open(path,'w') as sw:
            sw.write(info)
    except Exception,e:
        path = "/root/net_api/error_ip.log"
        with open(path,'a+') as sw:
            sw.write(ip + ': ' + nowTime + '---->' + str(e) + '\n' )