#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables       import *
from ..Standard_Operations.Logs     import Logs
from ..Standard_Operations.Colors   import Colors
from ..Standard_Operations.Standard import Standard

class Check_SNMP:
    def Basic_Check(url, t_seconds, Host_Name, Location, Dict_System = {}):
        def Walk_SNMP(oid, url, snmp_version, community_string, t_seconds):
            Temp_Output = ""
            if ('iso' in oid):
                Temp_Output = getCmd(
                                SnmpEngine(),
                                CommunityData(community_string, mpModel=snmp_version),
                                UdpTransportTarget((f'{url}', 161), timeout=t_seconds, retries=1),
                                ContextData(),
                                ObjectType(ObjectIdentity(oid)),
                                lexicographicMode=False
                )
            else:
                Temp_Output = nextCmd(
                                SnmpEngine(),
                                CommunityData(community_string, mpModel=snmp_version),
                                UdpTransportTarget(('{url}', 161), timeout=t_seconds, retries=1),
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
            Temp_Output = Walk_SNMP(oid, url, 0, 'Public')

            # SNMPv2
            if (Temp_Output == None):
                Temp_Output = Walk_SNMP(oid, url, 1, 'Public')

            for Indication_Error, Status_Error, Index_Error, Bind_Variables in Temp_Output:
                for _ in Bind_Variables:
                    print (_)

        return Dict_System


    def String_Enumeration(url, t_seconds, Host_Name, Location, Dict_Temp = {}):
        for _ in Array_Community_Strings:
            Temp_Output = getCmd(
                                SnmpEngine(),
                                CommunityData(i, mpModel=0),
                                UdpTransportTarget((f'192.168.193.139', 161), timeout=2.0, retries=1),
                                ContextData(),
                                ObjectType(ObjectIdentity('iso.3.6.1.2.1.1.5.0')),
                                lexicographicMode=False
            )
        
            for errorIndication, errorStatus, errorIndex, varBinds in Temp_Output:
                       if (errorIndication == None):
                           print (i)
            break

