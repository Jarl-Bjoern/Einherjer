#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables       import *
from ..Standard_Operations.Logs     import Logs
from ..Standard_Operations.Colors   import Colors
from ..Standard_Operations.Standard import Standard

class Check_SNMP:
    def Basic_Check(url, Dict_System = {}):
        def Walk_SNMP(oid, url, snmp_version):
            Temp_Output = ""
            if ('iso' in oid):
                Temp_Output = getCmd(
                                SnmpEngine(),
                                CommunityData('Public', mpModel=0),
                                UdpTransportTarget((f'{url}', 161)),
                                ContextData(),
                                ObjectType(ObjectIdentity(oid)),
                                lexicographicMode=False
                )
            else:
                Temp_Output = nextCmd(
                                SnmpEngine(),
                                CommunityData('Public', mpModel=0),
                                UdpTransportTarget(('{url}', 161)),
                                ContextData(),
                                ObjectType(ObjectIdentity(oid)),
                                lexicographicMode=False
                )
            return Temp_Output

        # Split_Protocol
        if ('snmp://' in url):    URL = url.split('snmp://')[1]
    
        # Port_Filter
        if (url.count(':') > 1): Port = URL.split(':')[1]
        else:                    Port = 22
    
        # Get_Only_Target
        if (':' in URL):         Target = URL.split(':')[0]
        else:                    Target = URL
    
        # Get_Host_Name
        if (Host_Name != ""):    Dict_System['DNS'] = Host_Name
        else:                    Dict_System['DNS'] = ""

        Temp_Output = None
        for oid in Array_OIDs:
            # SNMPv1
            Temp_Output = Walk_SNMP(oid, url, 0)

            # SNMPv2
            if (Temp_Output == None):
                Temp_Output = Walk_SNMP(oid, url, 1)

            for Indication_Error, Status_Error, Index_Error, Bind_Variables in Temp_Output:
                for _ in Bind_Variables:
                    print (_)

        return Dict_System


    def String_Enumeration(url, Dict_Temp = {}):
        pass
