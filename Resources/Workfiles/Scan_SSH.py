#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables     import *
from ..Standard_Operations.Logs   import Logs
from ..Standard_Operations.Colors import Colors

def SSH_Vulns(url, Host_Name, Location, Dict_SSH_Version = {}, Dict_SSH_Results = {'auth_methods': [], 'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}, Dict_Temp = {}):
    def Check_SSH_Values(List_With_Keys, Temp_Key = ""):
        Array_Temp = []
        for i in List_With_Keys:
            if ('@' in i): Temp_Key = i.split('@')[0]
            else: Temp_Key = i
            if (Temp_Key not in Array_SSH_Algorithms):
                Array_Temp.append(Temp_Key)
        return Array_Temp

    filter_values = r'x88|x01|x00|x15|xd5|\\|&|@openssh.com'

    # Split_Protocol
    if ('ssh://' in url):    URL = url.split('ssh://')[1]

    # Port_Filter
    if (url.count(':') > 1): Port = URL.split(':')[1]
    else:                    Port = 22

    # Get_Only_Target
    if (':' in URL):         Target = URL.split(':')[0]
    else:                    Target = URL

    # Get_Host_Name
    if (Host_Name != ""):    Dict_Temp['DNS'] = Host_Name
    else:                    Dict_Temp['DNS'] = ""

    # Get_Banner
    socket_defaulttimeout(30)
    try:
        with socket_create_connection((Target, int(Port)),5) as sock:
            sock.send(b"SSH-2.0-7331SSH\r\n")
            try:              Server_Banner = str(sock.recv(100), 'utf-8')
            except TypeError: Server_Banner = sock.recv(100)

            # Get_Ciphers
            Dict_System = {}
            Ciphers = sock.recv(4096)
            print (resplit(filter_values, str(Ciphers)))
            for _ in resplit(filter_values, str(Ciphers)):
                if (_ != ''):
                    print (_)

        if ('SSH-1' in str(Server_Banner)[::-(len(Server_Banner)-7)]):
            print (Server_Banner)
    except TimeoutError:
        pass

    # Confirm_Host_Keys
    #with sub_Popen(['ssh','-T','-o','StrictHostKeyChecking=no',Target,'-p',int(Port)], stdin=sub_PIPE, stdout=sub_PIPE) as process:
    #    process.terminate()

    # Check_Auth_Methods
    async def check_auth(Target):
        return await get_server_auth_methods(Target)

    # Experimental
    #opts        = Transport(Target, int(Port)).get_security_options()
    #Dict_System['kex_algorithms']             = Check_SSH_Values(opts.kex)
    #Dict_System['server_host_key_algorithms'] = Check_SSH_Values(opts.key_types)
    #Dict_System['encryption_algorithms']      = Check_SSH_Values(opts.ciphers)
    #Dict_System['mac_algorithms']             = Check_SSH_Values(opts.digests)
    #print(opts.compression)

    # Start_Scans
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        Dict_System['auth_methods'] = loop.run_until_complete(check_auth(Target))
    except (AsyncSSHError, OSError) as e:
        exit(f'SSH connection failed: {str(e)}')

    return Dict_System
