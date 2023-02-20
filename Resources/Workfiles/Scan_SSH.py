#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def SSH_Vulns(Target, Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}):
    global existing_nmap_file, Switch_nmap

    if (Switch_nmap == False):
        def Check_SSH_Values(List_With_Keys, Temp_Key = ""):
            Array_Temp = []
            for i in List_With_Keys:
                if ('@' in i): Temp_Key = i.split('@')[0]
                else: Temp_Key = i
                if (Temp_Key not in Array_SSH_Algorithms):
                    Array_Temp.append(Temp_Key)
            return Array_Temp

        Dict_System = {}
        opts = Transport(Target, 22).get_security_options()
        Dict_System['kex_algorithms'] = Check_SSH_Values(opts.kex)
        Dict_System['server_host_key_algorithms'] = Check_SSH_Values(opts.key_types)
        Dict_System['encryption_algorithms'] = Check_SSH_Values(opts.ciphers)
        Dict_System['mac_algorithms'] = Check_SSH_Values(opts.digests)
        #print(opts.compression)

        sock = create_connection((Target,22),5)
        sock.send(b"SSH-2.0-7331SSH\r\n")
        Server_Banner = sock.recv(984)
        print (Server_Banner)

        class MySSHClient(SSHClient):
            def connection_made(self, conn: SSHClientConnection) -> None:
                print(conn.get_extra_info('client_version'))
                print(conn.get_extra_info('send_mac'))
                print(conn.get_extra_info('send_compression'))

            def auth_completed(self) -> None:
                print('Authentication successful.')

        async def check_auth():
            return await get_server_auth_methods(url)

        #async def run_client():
        #    result = await asyncssh.get_server_auth_methods('127.0.0.1')
        #    conn, client = await asyncssh.create_connection(MySSHClient, '127.0.0.1', known_hosts=None)
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            Auth_Methods = loop.run_until_complete(check_auth())
            #loop.run_until_complete(run_client())
        except (OSError, asyncssh.Error) as e: exit(f'SSH connection failed: {str(e)}')

        return Dict_System
    else:
        # SSH-Nmap Variante
        with open(existing_nmap_file, 'r') as f:
            Report = f.readlines()

        for Result in range(1, len(Report)):
            if ("Nmap scan report" in Report[Result]): IP_Address = Report[Result].split(" ")[4].split('\n')[0]
            elif ("Host is" not in Report[Result] and "Scanned" not in Report[Result] and "PORT" not in Report[Result] and "MAC Address" not in Report[Result] and not "syn-ack" in Report[Result] and not "|" in Report[Result] and not "#" in Report[Result] and not "Read data" in Report[Result] and not "" in Report[Result]): pass
            elif ("tcp" in Report[Result]): Port = Report[Result].split('/')[0]
            elif ("|" in Report[Result]):
                if ("kex_algorithms" in Report[Result][4:-1] or "server_host_key_algorithms" in Report[Result][4:-1] or "encryption_algorithms" in Report[Result][4:-1] or "mac_algorithms" in Report[Result][4:-1]):
                    Dict_System[f'{IP_Address}:{Port}'] = ""
                    Target = Report[Result][4:-1].split(" ")[0][:-1]
                    while True:
                        Result += 1
                        if ("server_host_key_algorithms" not in Report[Result] and "encryption_algorithms" not in Report[Result] and "mac_algorithms" not in Report[Result] and "compression_algorithms" not in Report[Result]):
                            if (Report[Result][8:-1] not in Array_SSH_Algorithms):
                                if ('@' in Report[Result][8:-1]):
                                    if (Report[Result][8:-1].split("@")[0] not in Array_SSH_Algorithms):
                                        Dict_SSH_Results[Target].append(Report[Result][8:-1])
                                else:
                                    Dict_SSH_Results[Target].append(Report[Result][8:-1])
                        else: break
                elif ("compression_algorithms" in Report[Result]):
                    Dict_System[f'{IP_Address}:{Port}'] = Dict_SSH_Results
                    Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}

        with open(join(location, 'Vulns.txt'), 'w') as f:
            f.write("Host;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms\n")
            for i in Dict_System:
                f.write(f'{i};')
                for j in Dict_System[i]:
                    for k in range(0, len(Dict_System[i][j])):
                        if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                        else: f.write(f'{Dict_System[i][j][k]}')
                    f.write(f';')
                f.write('\n')
