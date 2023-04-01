#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *
from ..Standard_Operations.Logs import Logs
from ..Standard_Operations.Colors import Colors

def SSH_Vulns(Target, Dict_SSH_Version = {}, Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}):
    def Check_SSH_Values(List_With_Keys, Temp_Key = ""):
        Array_Temp = []
        for i in List_With_Keys:
            if ('@' in i): Temp_Key = i.split('@')[0]
            else: Temp_Key = i
            if (Temp_Key not in Array_SSH_Algorithms):
                Array_Temp.append(Temp_Key)
        return Array_Temp

    Dict_System = {}
    opts        = Transport(Target, 22).get_security_options()
    Dict_System['kex_algorithms']             = Check_SSH_Values(opts.kex)
    Dict_System['server_host_key_algorithms'] = Check_SSH_Values(opts.key_types)
    Dict_System['encryption_algorithms']      = Check_SSH_Values(opts.ciphers)
    Dict_System['mac_algorithms']             = Check_SSH_Values(opts.digests)
    #print(opts.compression)

    # Get_Banner
    sock = create_connection((Target,22),5)
    sock.send(b"SSH-2.0-7331SSH\r\n")
    try:    Server_Banner = str(sock.recv(100), 'utf-8')
    except: Server_Banner = sock.recv(100)
    if ('SSH-1' in Server_Banner[::-(len(Server_Banner)-7)]):
        print (Server_Banner)

    class MySSHClient(SSHClient):
        def connection_made(self, conn: SSHClientConnection) -> None:
            print(conn.get_extra_info('client_version'))
            print(conn.get_extra_info('send_mac'))
            print(conn.get_extra_info('send_compression'))

        def auth_completed(self) -> None:
            print('Authentication successful.')

    async def check_auth(url):
        return await get_server_auth_methods(url)

    #async def run_client():
    #    result = await asyncssh.get_server_auth_methods('127.0.0.1')
    #    conn, client = await asyncssh.create_connection(MySSHClient, '127.0.0.1', known_hosts=None)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        Auth_Methods = loop.run_until_complete(check_auth(Target))
        #loop.run_until_complete(run_client())
    except (OSError, AsyncSSHError) as e:
        exit(f'SSH connection failed: {str(e)}')

    return Dict_System
