#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables       import *
from ..Standard_Operations.Logs     import Logs
from ..Standard_Operations.Colors   import Colors
from ..Standard_Operations.Standard import Standard

class Check_SNMP:
    def Basic_Check(url, Dict_Temp = {}):
        for oid in Array_OIDs:
            # SNMPv1
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

            # SNMPv2
            if (Temp_Output == None):
                if ('iso' in oid):
                    Temp_Output = getCmd(
                                    SnmpEngine(),
                                    CommunityData('Public', mpModel=1),
                                    UdpTransportTarget((f'{url}', 161)),
                                    ContextData(),
                                    ObjectType(ObjectIdentity(oid)),
                                    lexicographicMode=False
                    )
                else:
                    Temp_Output = nextCmd(
                                    SnmpEngine(),
                                    CommunityData('Public', mpModel=1),
                                    UdpTransportTarget(('{url}', 161)),
                                    ContextData(),
                                    ObjectType(ObjectIdentity(oid)),
                                    lexicographicMode=False
                    )
        
            for Indication_Error, Status_Error, Index_Error, Bind_Variables in Temp_Output:
                for _ in Bind_Variables:
                    print (_)


    def String_Enumeration(url, Dict_Temp = {}):
        pass
