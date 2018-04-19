# coding: utf-8
from collections import defaultdict

try:
    from pysnmp.entity.rfc3413.oneliner import cmdgen

    has_pysnmp = True
except:
    has_pysnmp = False


class DefineOid(object):
    def __init__(self, dotprefix=False):
        if dotprefix:
            dp = "."
        else:
            dp = ""

        # From SNMPv2-MIB
        self.sysDescr = dp + "1.3.6.1.2.1.1.1.0"
        self.sysObjectId = dp + "1.3.6.1.2.1.1.2.0"
        self.sysUpTime = dp + "1.3.6.1.2.1.1.3.0"
        self.sysContact = dp + "1.3.6.1.2.1.1.4.0"
        self.sysName = dp + "1.3.6.1.2.1.1.5.0"
        self.sysLocation = dp + "1.3.6.1.2.1.1.6.0"
        self.sysModel = dp + "1.3.6.1.2.1.47.1.1.1.1.2.1"

        # From IF-MIB
        self.ifIndex = dp + "1.3.6.1.2.1.2.2.1.1"
        self.ifDescr = dp + "1.3.6.1.2.1.2.2.1.2"
        self.ifMtu = dp + "1.3.6.1.2.1.2.2.1.4"
        self.ifSpeed = dp + "1.3.6.1.2.1.2.2.1.5"
        self.ifPhysAddress = dp + "1.3.6.1.2.1.2.2.1.6"
        self.ifAdminStatus = dp + "1.3.6.1.2.1.2.2.1.7"
        self.ifOperStatus = dp + "1.3.6.1.2.1.2.2.1.8"
        self.ifAlias = dp + "1.3.6.1.2.1.31.1.1.1.18"

        # From IP-MIB
        self.ipAdEntAddr = dp + "1.3.6.1.2.1.4.20.1.1"
        self.ipAdEntIfIndex = dp + "1.3.6.1.2.1.4.20.1.2"
        self.ipAdEntNetMask = dp + "1.3.6.1.2.1.4.20.1.3"
        
        #z
        self.ipNetToMediaIfindex = dp + "1.3.6.1.2.1.4.22.1.1"
        self.ipNetToMediaPhysAddress = dp + "1.3.6.1.2.1.4.22.1.2"
        self.ipNetToMediaNetAddress = dp + "1.3.6.1.2.1.4.22.1.3"

        # From mac
        self.ifMactable1 = dp + "1.3.6.1.2.1.17.4.3.1.1"
        self.ifMactable2 = dp + "1.3.6.1.2.1.17.4.3.1.2"
        self.ifMactable3 = dp + "1.3.6.1.2.1.17.4.3.1.3"
        self.ifMacport = dp + "1.3.6.1.2.1.17.1.4.1.2"

class ServerError(Exception):
    """
    self define exception
    自定义异常
    """
    pass


#处理.
def decode_hex(hexstring):
    if len(hexstring) < 3:
        return hexstring
    if hexstring[:2] == "0x":
        return hexstring[2:].decode("hex")
    else:
        return hexstring

#处理.
def decode_mac(hexstring):
    if len(hexstring) != 14:
        return hexstring
    if hexstring[:2] == "0x":
        return hexstring[2:]
    else:
        return hexstring


def lookup_adminstatus(int_adminstatus):
    adminstatus_options = {
        1: 'up',
        2: 'down',
        3: 'testing'
    }
    if int_adminstatus in adminstatus_options.keys():
        return adminstatus_options[int_adminstatus]
    else:
        return ""


def lookup_operstatus(int_operstatus):
    operstatus_options = {
        1: 'up',
        2: 'down',
        3: 'testing',
        4: 'unknown',
        5: 'dormant',
        6: 'notPresent',
        7: 'lowerLayerDown'
    }
    if int_operstatus in operstatus_options.keys():
        return operstatus_options[int_operstatus]
    else:
        return ""




#调用的类
class get_net_conntions():
    def __init__(self,args={}):
        if not has_pysnmp:
            module.fail_json(msg='Missing required pysnmp module (check docs)')

        self.args=args
        self.cmdGen = cmdgen.CommandGenerator()


        #输入参数判断，预处理
        # Verify that we receive a community when using snmp v2
        if self.args['version'] == "v2" or self.args['version'] == "v2c":
            if self.args['community'] == False:
                raise ServerError('Community not set when using snmp version 2')

        if self.args['version'] == "v3":
            if self.args['username'] == None:
                raise ServerError('Username not set when using snmp version 3')

            if self.args['level'] == "authPriv" and self.args['privacy'] == None:
                raise ServerError('Privacy algorithm not set when using authPriv')

            if self.args['integrity'] == "sha":
                integrity_proto = cmdgen.usmHMACSHAAuthProtocol
            elif self.args['integrity'] == "md5":
                integrity_proto = cmdgen.usmHMACMD5AuthProtocol

            if self.args['privacy'] == "aes":
                privacy_proto = cmdgen.usmAesCfb128Protocol
            elif self.args['privacy'] == "des":
                privacy_proto = cmdgen.usmDESPrivProtocol

        # Use SNMP Version 2
        if self.args['version'] == "v2" or self.args['version'] == "v2c":

            self.snmp_auth = cmdgen.CommunityData(self.args['community'])

        # Use SNMP Version 3 with authNoPriv
        elif self.args['level'] == "authNoPriv":
            self.snmp_auth = cmdgen.UsmUserData(self.args['username'], authKey=self.args['authkey'], authProtocol=integrity_proto)

        # Use SNMP Version 3 with authPriv
        else:
            self.snmp_auth = cmdgen.UsmUserData(self.args['username'], authKey=self.args['authkey'], privKey=self.args['privkey'],
                                           authProtocol=integrity_proto, privProtocol=privacy_proto)


    def get_data(self):
        #具体的获取逻辑

        # Use p to prefix OIDs with a dot for polling
        p = DefineOid(dotprefix=True)
        # Use v without a prefix to use with return values
        v = DefineOid(dotprefix=False)

        Tree = lambda: defaultdict(Tree)

        results = Tree()

        errorIndication, errorStatus, errorIndex, varBinds = self.cmdGen.getCmd(
            self.snmp_auth,
            #cmdgen.UdpTransportTarget((self.args['host'], 161) ,timeout=30, retries=5),
            cmdgen.UdpTransportTarget((self.args['host'], 161)),
            cmdgen.MibVariable(p.sysDescr, ),
            cmdgen.MibVariable(p.sysObjectId, ),
            cmdgen.MibVariable(p.sysUpTime, ),
            cmdgen.MibVariable(p.sysContact, ),
            cmdgen.MibVariable(p.sysName, ),
            cmdgen.MibVariable(p.sysLocation, ),

            #cmdgen.MibVariable(p.sysModel, ),
            lookupMib=False
        )

        if errorIndication:
            raise ServerError(str(errorIndication))
        #获取系统参数
        for oid, val in varBinds:
            current_oid = oid.prettyPrint()
            current_val = val.prettyPrint()
            if current_oid == v.sysDescr:
                results['netsysdescr'] = decode_hex(current_val)
            elif current_oid == v.sysObjectId:
                results['netsysobjectid'] = current_val
            elif current_oid == v.sysUpTime:
                results['netsysuptime'] = current_val
            #elif current_oid == v.sysContact:
            #    results['netsyscontact'] = current_val
            elif current_oid == v.sysName:
                results['netsysname'] = current_val
            elif current_oid == v.sysLocation:
                results['netsyslocation'] = current_val
            #elif current_oid == v.sysModel:
            #    results['netsysmodel'] = current_val

        errorIndication, errorStatus, errorIndex, varTable = self.cmdGen.nextCmd(
            self.snmp_auth,
            #cmdgen.UdpTransportTarget((self.args['host'], 161) ,timeout=30, retries=5),
            cmdgen.UdpTransportTarget((self.args['host'], 161)),
            cmdgen.MibVariable(p.ifIndex, ),
            cmdgen.MibVariable(p.ifDescr, ),
            cmdgen.MibVariable(p.ifMtu, ),
            cmdgen.MibVariable(p.ifSpeed, ),
            cmdgen.MibVariable(p.ifPhysAddress, ),
            cmdgen.MibVariable(p.ifAdminStatus, ),
            cmdgen.MibVariable(p.ifOperStatus, ),
            cmdgen.MibVariable(p.ipAdEntAddr, ),
            cmdgen.MibVariable(p.ipAdEntIfIndex, ),
            cmdgen.MibVariable(p.ipAdEntNetMask, ),

            cmdgen.MibVariable(p.ifAlias, ),
            cmdgen.MibVariable(p.ifMactable3, ),
            cmdgen.MibVariable(p.ifMactable1, ),
            cmdgen.MibVariable(p.ifMactable2, ),
            cmdgen.MibVariable(p.ifMacport, ),

            #z
            cmdgen.MibVariable(p.ipNetToMediaIfindex, ),
            cmdgen.MibVariable(p.ipNetToMediaPhysAddress, ),
            cmdgen.MibVariable(p.ipNetToMediaNetAddress, ),

            lookupMib=False
        )

        if errorIndication:
            raise ServerError(str(errorIndication))

        interface_indexes = []

        all_ipv4_addresses = []
        ipv4_networks = Tree()

        all_mac_tables1 = {}
        all_mac_tables2 = {}
        all_mac_tables3 = {}


        #获取接口数据
        for varBinds in varTable:
            #print varBinds
            for oid, val in varBinds:
                current_oid = oid.prettyPrint()
                current_val = val.prettyPrint()
                #print current_oid
                #print current_val
                
                if v.ifIndex in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['ifindex'] = current_val
                    interface_indexes.append(ifIndex)
                if v.ifDescr in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['name'] = current_val
                if v.ifMtu in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['mtu'] = current_val
                if v.ifMtu in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['speed'] = current_val
                if v.ifPhysAddress in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['mac'] = decode_mac(current_val)
                if v.ifAdminStatus in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['adminstatus'] = lookup_adminstatus(int(current_val))
                if v.ifOperStatus in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 4)[-1])
                    results['netinterfaces'][ifIndex]['operstatus'] = lookup_operstatus(int(current_val))

                #z
                if v.ipNetToMediaIfindex in current_oid:
                    iptoindex = ".".join(current_oid.split('.')[-4::])
                    results['netiptoindex'][iptoindex]['iptoindex'] = int(current_val)
                if v.ipNetToMediaPhysAddress in current_oid:
                    iptomac = ".".join(current_oid.split('.')[-4::])
                    results['netiptomac'][iptomac]['iptomac'] = decode_mac(current_val)
                if v.ipNetToMediaNetAddress in current_oid:
                    iptoip = ".".join(current_oid.split('.')[-4::])
                    results['netiptoip'][iptoip]['iptoip'] = current_val


                if v.ipAdEntAddr in current_oid:
                    curIPList = current_oid.rsplit('.', 4)[-4:]
                    curIP = ".".join(curIPList)
                    ipv4_networks[curIP]['address'] = current_val
                    all_ipv4_addresses.append(current_val)
                if v.ipAdEntIfIndex in current_oid:
                    curIPList = current_oid.rsplit('.', 4)[-4:]
                    curIP = ".".join(curIPList)
                    ipv4_networks[curIP]['interface'] = current_val
                if v.ipAdEntNetMask in current_oid:
                    curIPList = current_oid.rsplit('.', 4)[-4:]
                    curIP = ".".join(curIPList)
                    ipv4_networks[curIP]['netmask'] = current_val

                if v.ifAlias in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['description'] = current_val

                if v.ifAlias in current_oid:
                    ifIndex = int(current_oid.rsplit('.', 1)[-1])
                    results['netinterfaces'][ifIndex]['description'] = current_val

                if v.ifMactable3 in current_oid:
                    ifmac16 = current_oid.rsplit('.')[-6:]
                    all_mac_tables3[''.join(ifmac16)] = int(current_val)

                if v.ifMactable1 in current_oid:
                    ifmac16 = current_oid.rsplit('.')[-6:]
                    all_mac_tables1[''.join(ifmac16)] = current_val

                if v.ifMactable2 in current_oid:
                    ifmac16 = current_oid.rsplit('.')[-6:]

                    if not all_mac_tables2.has_key(int(current_val)):
                        all_mac_tables2[int(current_val)] = []

                    if all_mac_tables3[''.join(ifmac16)] == 3:
                        all_mac_tables2[int(current_val)].append(all_mac_tables1[''.join(ifmac16)])

                if v.ifMacport in current_oid:
                    ifmacport = int(current_oid.rsplit('.', 1)[-1])

                    if all_mac_tables2.has_key(ifmacport):
                        results['netinterfaces'][int(current_val)]['macs'] = all_mac_tables2[ifmacport]
                

        interface_to_ipv4 = {}
        for ipv4_network in ipv4_networks:
            current_interface = ipv4_networks[ipv4_network]['interface']
            current_network = {
                'address': ipv4_networks[ipv4_network]['address'],
                'netmask': ipv4_networks[ipv4_network]['netmask']
            }
            if not current_interface in interface_to_ipv4:
                interface_to_ipv4[current_interface] = []
                interface_to_ipv4[current_interface].append(current_network)
            else:
                interface_to_ipv4[current_interface].append(current_network)
        #关联数据
        for interface in interface_to_ipv4:
            results['netinterfaces'][int(interface)]['ipv4'] = interface_to_ipv4[interface]

        results['netall_ipv4_addresses'] = all_ipv4_addresses

        return dict(results)
