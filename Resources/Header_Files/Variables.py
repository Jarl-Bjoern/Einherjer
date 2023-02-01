#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Colors import Colors
from Resources.Header_Files.Libraries import *
from Resources.Standard_Operations.Standard import *
from Resources.Standard_Operations.Logs import *

# Template_Filtering
if (args.read_config_cookie_security_flags != None): Array_Security_Flags = Standard.Read_Template(join(dirname(realpath(__file__)), "Templates/http_cookie_security.txt"))
else: Array_Security_Flags = []
if (args.read_config_http_header != None): Array_Header, Array_HTTP_Filter = Standard.Read_File_Special(join(dirname(realpath(__file__)), "Templates/http_header.txt"))
else: Array_Header, Array_HTTP_Filter = [], []
if (args.read_config_http_header_api != None): Array_Header, Array_HTTP_Filter = Standard.Read_File_Special(join(dirname(realpath(__file__)), "Templates/http_header_api.txt"))
else: Array_Header, Array_HTTP_Filter = [], []
if (args.read_config_http_information_disclosure != None): Array_Information_Disclosure_Header = Standard.Read_Template(join(dirname(realpath(__file__)), "Templates/http_information_disclosure.txt"))
else: Array_Information_Disclosure_Header = []
if (args.read_config_http_methods != None): Array_HTTP_Methods = Standard.Read_Template(join(dirname(realpath(__file__)), "Templates/http_methods.txt"))
else: Array_HTTP_Methods = []
if (args.read_config_ssh_ciphers != None): Array_SSH_Algorithms = Standard.Read_Template(join(dirname(realpath(__file__)), "Templates/ssh_ciphers.txt"))
else: Array_SSH_Algorithms = []
if (args.read_config_ssl_ciphers != None): Array_TLS_Algorithms = Standard.Read_Template(join(dirname(realpath(__file__)), "Templates/ssl_ciphers.txt"))
else: Array_TLS_Algorithms = []

# Arrays
#Array_Header = ['X-FRAME-OPTIONS', 'X-XSS-PROTECTION', 'CONTENT-SECURITY-POLICY', 'STRICT-TRANSPORT-SECURITY', 'X-CONTENT-TYPE-OPTIONS', 'REFERRER-POLICY']
Array_Paths, Array_SSL_Vulns, Array_Results = [],[],[]
#Array_Information_Disclosure_Header = ["X-POWERED-BY", "SERVER"]
#Array_Security_Flags = ['SAMESITE', 'HTTPONLY', 'SECURE']
Array_SSH_Header = ['kex_algorithms', 'server_host_key_algorithms', 'encryption_algorithms', 'mac_algorithms']
#Array_TLS_Algorithms = ["SHA","MD5","RC2","RC4","IDEA","ADH","3DES","NULL","PSK","ANON","CBC","DHE","ECDHE"]

# Variables
COLOR_Headline = "black"
Switch_nmap, existing_nmap_file = False, ""

# Design
disable_warnings(InsecureRequestWarning)
progress_columns = (
    SpinnerColumn(),
    "[progress.description]{task.description}",
    BarColumn(),
    TaskProgressColumn(),
    "Elapsed:",
    TimeElapsedColumn(),
    "Remaining:",
    TimeRemainingColumn(),
)

# Functions
def Host_Swap(Word, T_Switch = ""):
    T_Switch = Word[:-1]
    Word = T_Switch
    return Word

def Filter_Host_Name(Element, Target, Array_Temp, Word):
    if (Element != Array_Temp[len(Array_Temp)-1] and Element != Target): Word += f"{Element}, "
    elif (Element != Array_Temp[len(Array_Temp)-1] and Element == Target): pass
    elif (Element == Array_Temp[len(Array_Temp)-1] and Element == Target):
        if (Word[-1] == ","): Word = Host_Swap(Word)
    elif (Element == Array_Temp[len(Array_Temp)-1] and Element != Target): Word += f"{Element}"
    return Word

def Get_Host_Name(url, Target = "", Temp = "", Word = ""):
    if ('//' in url):
        if (url.count(':') == 2): Target = url.split('//')[1].split(':')[0]
        else: Target = url.split('//')[1]
    else: Target = url

    try: Temp = gethostbyaddr(Target)
    except (gaierror, herror):
        try:
            Temp = gethostbyname(Target)
            if (Temp == Target): Temp = ""
        except (gaierror, herror, UnicodeError): pass
    except UnicodeError: pass

    if (type(Temp) == tuple or type(Temp) == list):
        for _ in Temp:
            if (_ != []):
                if (type(_) != list): Word = Filter_Host_Name(_, Target, Temp, Word)
#                    if (_ != Temp[len(Temp)-1] and _ != Target): Word += f"{_}, "
#                    elif (_ != Temp[len(Temp)-1] and _ == Target): pass
#                    elif (_ == Temp[len(Temp)-1] and _ == Target):
#                        if (Word[-1] == ","):
#                            T_Switch = Target[:-1]
#                            Word = T_Switch
#                    elif (_ == Temp[len(Temp)-1] and _ != Target): Word += f"{_}"
                else:
                    for j in _:
#                        Word = Filter_Host_Name(j, Target, _, Word)
                        if (j != _[len(_)-1] and j != Target): Word += f"{j}, "
                        elif (j != _[len(_)-1] and j == Target): pass
                        elif (j == _[len(_)-1] and j == Target):
                            if (Word[-1] == ","): Word = Host_Swap(Word)
                        elif (j == _[len(_)-1] and j != Target):
                            if (_ != Temp[len(Temp)-1] and _ != Target): Word += f"{j}, "
                            elif (_ != Temp[len(Temp)-1] and _ == Target): pass
                            elif (_ == Temp[len(Temp)-1] and _ == Target):
                                if (Word[-1] == ","): Word = Host_Swap(Word)
                            elif (_ == Temp[len(Temp)-1] and _ != Target): Word += f"{j}"
    elif (type(Temp) == str): Word = Temp
    return Word

def Check_Site_Paths(url, t_seconds, array_wordlists, Array_Temp = [], Array_Status_Code = ["200", "302", "405", "500"]):
    for Word in array_wordlists:
        URL = f'{url}/{Word}'
        r = get(URL, timeout=t_seconds, verify=False, allow_redirects=True)
        if (str(r.status_code) in Array_Status_Code):
            if (URL not in Array_Temp): Array_Temp.append(URL)
        sleep(t_seconds)

    return Array_Temp

def Check_Website(url, t_seconds, Dict_Temp = {}, Array_Output = [], Temp_Array = []):
    Array_Filter = ["Apache/", "Tomcat/", "Server Version:"]

    with open('/opt/test.txt', 'w') as f:
         for i in array(Read_File(argv[1])):
             r = get(str(i), verify=False, timeout=(25,25))
             for _ in array(Array_Filter):
                 x = search(rf'^.*{_}.*', str(r.content))
                 if (x != None):
                    for j in array(r.text.splitlines()):
                        if (_ in j):
                            Temp_Array = resplit("<dl>|<dt>|</dt>", j)
                            if (len(Temp_Array) > 1):
                                for k in array(Temp_Array):
                                    if (len(k) > 1):
                                        if (f'{i} - {k}' not in Array_Output): Array_Output.append(f'{i} - {k}')

    return Dict_Temp

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

def SSL_Vulns(url, t_seconds, context = create_unverified_context(), Dict_SSL = {'Ciphers': [], 'TLS': [], 'Certificate': {}}):
    def Check_SSL_Values(List_With_Keys, Temp_Key = ""):
        Array_Temp = []
        for i in List_With_Keys:
            if ('@' in i): Temp_Key = i.split('@')[0]
            else: Temp_Key = i
            if (Temp_Key not in Array_SSH_Algorithms):
                Array_Temp.append(Temp_Key)
        return Array_Temp

    def Check_Protocol(Ciphers):
        if (Ciphers != "TLSv1.3" or Ciphers != "TLSv1.2"): return Ciphers
        else: return Ciphers

    if ('http://' in url): URL = url.split('http://')[1]
    elif ('https://' in url): URL = url.split('https://')[1]

    if (url.count(':') > 1): Port = url.split(':')[2]
    else: Port = 443

    try:
        with create_connection((URL, int(Port)), timeout=t_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=URL) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())

                # Check_Ciphers
                for Ciphers in ssock.shared_ciphers():
                    for Algorithm in array(Array_TLS_Algorithms):
                        if (Algorithm in Ciphers[0]):
                            if (Array_TLS_Algorithms[0] in Ciphers[0]):
                                if ("SHA256" in Ciphers[0] or "SHA512" in Ciphers[0]): Dict_SSL['Ciphers'].append(Ciphers[0])
                                Dict_SSL['TLS'].append(Check_Protocol(Ciphers[1]))
                                break
                            else:
                                Dict_SSL['Ciphers'].append(Ciphers[0])
                                Dict_SSL['TLS'].append(Check_Protocol(Ciphers[1]))
                                break
        return Dict_SSL
    except (ConnectionRefusedError, gaierror): Logs.Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the website\n')
