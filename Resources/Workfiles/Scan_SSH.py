#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables     import *
from ..Standard_Operations.Logs   import Logs
from ..Standard_Operations.Colors import Colors

def SSH_Vulns(url, t_seconds, Host_Name, Location, Dict_System = {}):
    filter_values    = r'x88|x01|x00|x15|xd5|\\|&|@|none|x03|x0c|x14|x9f|x98|x7fl|xb4|xe6o|xa7|xee|x1b|xd8|x8c|x034|x92|~|x0f|x9d|xb8{|xf4|xe7|xcc|x89$Q|xef|xaa|xea|x93^|xe3|t:"F|/|openssh.com|xd1b+|xa0|xe8|xd9|x85|xba|xbf|lysator.liu.se'
    Dict_SSH_Results = {'DNS': "", 'auth_methods': [], 'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': [], 'SSH_Version': "", 'SSH_Banner': ""} 

    # Split_Protocol
    if ('ssh://' in url):    URL = url.split('ssh://')[1]

    # Port_Filter
    if (url.count(':') > 1): Port = URL.split(':')[1]
    else:                    Port = 22

    # Get_Only_Target
    if (':' in URL):         Target = URL.split(':')[0]
    else:                    Target = URL

    # Get_Host_Name
    if (Host_Name != ""):    Dict_System['DNS'] = Host_Name
    else:                    Dict_System['DNS'] = ""

    # Get_Banner
    socket_defaulttimeout(t_seconds)
    try:
        with socket_create_connection((Target, int(Port)),5) as sock:
            sock.send(b"SSH-2.0-7331SSH\r\n")
            try:              Server_Banner = str(sock.recv(100), 'utf-8')
            except TypeError: Server_Banner = sock.recv(100)

            # Get_Ciphers
            Temp_Filter = []
            Ciphers = sock.recv(4096)
            for _ in resplit(filter_values, str(Ciphers)):
                if (_ != '' and _[0] != 'x' and len(_) > 5):
                    if (',' in _):
                        Temp_Check = _.split(',')
                        for Cipher_Check in Temp_Check:
                            if (Cipher_Check != ''):
                                cipher = Cipher_Check.lower()
                                if (cipher not in Temp_Filter):
                                    if (cipher[0] == 'i'):   Temp_Filter.append(cipher[1:])
                                    else:                    Temp_Filter.append(cipher)    

                                if ('ssh'   in cipher or
                                    'ecdsa' in cipher or
                                    'x509'  in cipher or
                                    'pgp'   in cipher):
                                          if (cipher not in Dict_SSH_Results['server_host_key_algorithms']):
                                              Dict_SSH_Results['server_host_key_algorithms'].append(cipher)
                                elif ('diffie-hellman'  in cipher or
                                      'curve'           in cipher or
                                      'sntrup'          in cipher or
                                      'kex'             in cipher or
                                      'ecdh'            in cipher):
                                          if (cipher not in Dict_SSH_Results['kex_algorithms']):
                                              Dict_SSH_Results['kex_algorithms'].append(cipher)
                                elif ('hmac' in cipher or
                                      'umac' in cipher):
                                          if (cipher[0] == 'i'):
                                                if (cipher not in Dict_SSH_Results['mac_algorithms']):
                                                    Dict_SSH_Results['mac_algorithms'].append(cipher[1:])
                                          else:
                                                if (cipher not in Dict_SSH_Results['mac_algorithms']):
                                                    Dict_SSH_Results['mac_algorithms'].append(cipher)
                                elif ('aes'     in cipher or
                                      'arcfour' in cipher or
                                      'cbc'     in cipher or
                                      'chacha'  in cipher):
                                          if (cipher not in Dict_SSH_Results['encryption_algorithms']):
                                              Dict_SSH_Results['encryption_algorithms'].append(cipher)

        Dict_SSH_Results['SSH_Banner']  = str(Server_Banner)[:-2]
        if ('SSH-1' in str(Server_Banner)[::-(len(Server_Banner)-7)]):
            Dict_SSH_Results['SSH_Version'] = '1'
        else:
            Dict_SSH_Results['SSH_Version'] = '2'
    except TimeoutError:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    # Confirm_Host_Keys
    #with sub_Popen(['ssh','-T','-o','StrictHostKeyChecking=no',Target,'-p',int(Port)], stdin=sub_PIPE, stdout=sub_PIPE) as process:
    #    process.terminate()

    # Check_Auth_Methods
    async def check_auth(Target):
        return await get_server_auth_methods(Target)

    # Start_Scans
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        Dict_SSH_Results['auth_methods'] = loop.run_until_complete(check_auth(Target))
        Dict_System['SSH_Results']       = Dict_SSH_Results

        # Logging
        if (Host_Name != ""):
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'SSH-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {URL} - {Host_Name}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{Temp_Filter}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_SSH_Results}\n\n',
                join(Location, 'Logs')
            )
        else:
            Logs.Log_File(
                Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.BLUE+'SSH-Check\n'
                +Colors.YELLOW+'-----------------------------------------------------------------------------------------------------------\n'
                +Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {URL}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{Temp_Filter}'
                +Colors.BLUE+'\n-----------------------------------------------------------------------------------------------------------'
                +Colors.ORANGE+'\nEinherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_SSH_Results}\n\n',
                join(Location, 'Logs')
            )
    except (AsyncSSHError, OSError) as e:
        Logs.Write_Log(url, Host_Name, join(Location, 'Logs'))

    return Dict_System
