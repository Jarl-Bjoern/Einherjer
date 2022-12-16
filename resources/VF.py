#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from resources.HF import *

# Arrays
Array_Header = ['X-Frame-Options', 'X-XSS-Protection', 'Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy']
Array_Threads, Array_Paths, Array_Wordlists, Array_SSL_Vulns, Array_Fuzzing, Array_Thread_Args, Array_Switch, Array_Results, Array_Security_Flags = [],[],[],[],[],[],[],[],[]
Array_Selenium = ['--start_maximized','--no-sandbox','--remote-debugging-port=19222','--ignore-certificate-errors','--test-type','--headless','--log-level=3']
Array_Information_Disclosure_Header = ["X-Powered-By", "Server"]
Array_SSH_Header = ['kex_algorithms', 'server_host_key_algorithms', 'encryption_algorithms', 'mac_algorithms']
Array_SSH_Algorithms = [
    # Key Exchange Methods
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group15-sha512",
    "diffie-hellman-group16-sha512",
    "rsa2048-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    # Optional
    "curve25519-sha256",
    "diffie-hellman-group18-sha512",
    # Server_Host_Key_Algorithm OR Public_Key_Algorithm
    "pgp-sign-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "x509v3-ecdsa-sha2-nistp256",
    "x509v3-ecdsa-sha2-nistp384",
    "x509v3-ecdsa-sha2-nistp521",
    # Optional
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-ed25519",
    # Encryption_Algorithm
    "AEAD_AES_128_GCM",
    "AEAD_AES_256_GCM",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    # Optional
    "chacha20-poly1305",
    "aes128-gcm",
    "aes256-gcm",
    # MAC
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha2-256-etm",
    "hmac-sha2-512-etm",
    #Optional
    "umac-128",
    "umac-128-etm"]
Array_TLS_Algorithms = ["SHA","MD5","RC2","RC4","IDEA","ADH","3DES","NULL","PSK","ANON","CBC","DHE","ECDHE"]

# Dict
Dict_Proxies = {}

# Variables
Date, End_Result, Location, COLOR_Headline, Process_Limit, Thread_Limit = strftime('%Y-%m-%d_%H-%M-%S'), "\n\nYour Scan was successful and the result will be found at the following location:\n", "", "black", "", ""
File_Name, Switch_nmap, existing_nmap_file, Method, Kill_Command, Counter_Connections = "result", False, "", "", False, 0
Program_Description = """-------------------------------------------------------------------------------------
|  Rainer Christian Bjoern Herold                                                   |
|  Copyright 2022. All rights reserved.                                             |
|                                                                                   |
|  Please do not use the program for illegal activities.                            |
|                                                                                   |
|  If you got any problems don't hesitate to contact me so I can try to fix them.   |
|                                                                                   |
|  If you use the "Kali-Last-Snapshot" repository, you might install a slightly     |
|  older driver of Chromium with the command "apt install -y chromium". If this     |
|  is the case, then you should check after the installation with the command       |
|  "apt-cache policy chromium" which version was installed and then download the    |
|  appropriate Chrome Webdriver from the following page                             |
|  "https://chromedriver.chromium.org/downloads" and replace it instead.            |
-------------------------------------------------------------------------------------
"""

# Design
disable_warnings() # Removes the SSL-self-signed-certificate warning
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

# Classes
class Colors:
    CYAN = '\033[36m'
    GREEN = '\033[32m'
    ORANGE = '\033[33m'
    BLUE = '\033[34m'
    RED = '\033[31m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

# Functions
def Stdout_Output(Text_Array, Output_Seconds):
    for char in Text_Array:
        stdout.write(char)
        stdout.flush()
        sleep(Output_Seconds)

def Initialien(debug_parameter):
    if (debug_parameter == False):
        if (osname == 'nt'): system('cls')
        else: system('clear')
    else: system('')
    Header = """
💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀
💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t           """+Colors.UNDERLINE+"Einherjer"+Colors.RESET+ """\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t\t  """+Colors.ORANGE+"Version "+Colors.BLUE+"0.7"+Colors.RESET+"""\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t"""+Colors.CYAN+"Rainer Christian Bjoern Herold"+Colors.RESET+"""\t\t\t\t\t\t  💀
💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀\n\n
"""
    Stdout_Output(Header, 0.004)

def Read_File(file_path):
    with open(file_path, 'r') as f:
        return f.read().splitlines()

def Error_Message(x):
    print(x), sleep(2), exit()

def Thread_Check(Check_Value, Array_Check):
    global Array_Threads, Counter_Connections

    if (Check_Value not in str(Array_Check)):
        try: Array_Threads.remove(Check_Value)
        except ValueError: pass
        Counter_Connections -= 1

def Driver_Specification(option):
    if (osname == 'nt'): driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'resources/chromedriver.exe')), options=option)
    else: driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'resources/chromedriver')), options=option)
    return driver

def Create_Location_Dir(output_location_dir):
    try:
        makedirs(output_location_dir)
        return output_location_dir
    except:
        makedirs(join(dirname(realpath(__file__)), output_location_dir))
        print (f"Your location can't be found or was not allowed!\n\nYour new location was set to {join(dirname(realpath(__file__)), output_location_dir)}")
        return join(dirname(realpath(__file__)), output_location_dir)

def Try_Remove_File(x):
    while True:
        try:
            remove(x)
            break
        except FileNotFoundError:
            break
        except PermissionError: Error_Message(f"The file {x} is already open!\nPlease close it and wait five seconds.")
        sleep(5)

def Get_Host_Name(url, Temp = ""):
    try: Temp = gethostbyaddr(url)
    except (gaierror, herror):
        try:
            Temp = gethostbyname(url)
            if (Temp == url): Temp = ""
        except (gaierror, herror): pass
    return Temp

def Write_Log(url, host, Log_Path = dirname(realpath(__file__)).replace('resources', 'Logs')):
    if (not exists(Log_Path)): makedirs(Log_Path)
    with open(join(Log_Path, f'{Date}_failed-url.txt'), 'a') as f:
        f.write(f'{url}\n')
    if (host != ""): Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - {host} - FAILED\n')
    else: Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - FAILED\n')

def Log_File(Text, Log_Path = dirname(realpath(__file__)).replace('resources', 'Logs')):
    if (not exists(Log_Path)): makedirs(Log_Path)
    with open(join(Log_Path, f"{Date}.log"), "a") as f:
        f.write(Text)

def Read_Template(template_file):
    if (exists(template_file)):
        return Read_File(template_file)
    else: Error_Message(f'The requested File {template_file} does not exist!')

def Check_Site_Paths(url, t_seconds):
    for Word in Array_Wordlists:
        URL = f'{url}/{Word}'
        r = get(URL, timeout=t_seconds, verify=False, allow_redirects=True)
        if (str(r.status_code) == "200" or str(r.status_code) == "302" or str(r.status_code) == "405" or str(r.status_code) == "500"):
            if (URL not in Array_Fuzzing): Array_Fuzzing.append(URL)

def Check_Certificate(url, Counter_URL = 0):
    try: import OpenSSL
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

    for i in url:
        if (i == ':'): Counter_URL += 1
    if (Counter_URL > 1): Port = url.split(':')[2]
    else: Port = 443
    Cert = get_server_certificate((url, int(Port)))

    with create_connection((url, 443), timeout=t_seconds) as sock:
        with context.wrap_socket(sock, server_hostname=url) as ssock:
            cert_der = ssock.getpeercert(True)
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            print (cert.signature_hash_algorithm.name)

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

def Check_Security_Flags(url, t_seconds):
    s = Session()
    r = s.get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)

    for cookie in dict(s.cookies):
        pass
#        for i,j in cookie.__dict__.items():
#            if ('_rest' in i):
#                print (f'{i} : {j}')

#                        try:
#                            Cookie = r.cookies.get_dict()
#                            for head in Cookie:
#                                if ('JSID' not in head):
#
#                                elif ('Test' not in head):
#                        except: pass
#
#
#                        Dict_Result['Security_Flag']
    return Dict_Result


def SSH_Vulns(Target, Dict_SSH_Results = {'kex_algorithms': [], 'server_host_key_algorithms': [], 'encryption_algorithms': [], 'mac_algorithms': []}):
    try: from paramiko.transport import Transport
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
    global Location, existing_nmap_file, Switch_nmap

    # Test1
    def Check_SSH_Values(List_With_Keys, Temp_Key = ""):
        Array_Temp = []
        for i in List_With_Keys:
            if ('@' in i): Temp_Key = i.split('@')[0]
            else: Temp_Key = i
            if (Temp_Key not in Array_SSH_Algorithms):
                Array_Temp.append(Temp_Key)
        return Array_Temp

    # Test2
#sock = create_connection(("127.0.0.1",22),5)
#sock.send(b"SSH-2.0-7331SSH\r\n")
#sock_recv = sock.recv(984)
#print (sock_recv)

#class MySSHClient(asyncssh.SSHClient):
#    def connection_made(self, conn: asyncssh.SSHClientConnection) -> None:
#        print(conn.get_extra_info('client_version'))
#        print(conn.get_extra_info('send_mac'))
#        print(conn.get_extra_info('send_compression'))
#
#    def auth_completed(self) -> None:
#        print('Authentication successful.')
#
#async def run_client():
#    result = await asyncssh.get_server_auth_methods('127.0.0.1')
#    print (result)
#    conn, client = await asyncssh.create_connection(MySSHClient, '127.0.0.1', known_hosts=None)
#try:
#    loop = asyncio.new_event_loop()
#    asyncio.set_event_loop(loop)
#    loop.run_until_complete(run_client())
#except (OSError, asyncssh.Error) as e: exit(f'SSH connection failed: {str(e)}')

    if (Switch_nmap == False):
        Dict_System = {}
        opts = Transport(Target, ).get_security_options()
        Dict_System['kex_algorithms'] = Check_SSH_Values(opts.kex)
        Dict_System['server_host_key_algorithms'] = Check_SSH_Values(opts.key_types)
        Dict_System['encryption_algorithms'] = Check_SSH_Values(opts.ciphers)
        Dict_System['mac_algorithms'] = Check_SSH_Values(opts.digests)
        #print(opts.compression)

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

        with open(join(Location, 'Vulns.txt'), 'w') as f:
            f.write("Host;kex_algorithms;server_host_key_algorithms;encryption_algorithms;mac_algorithms\n")
            for i in Dict_System:
                f.write(f'{i};')
                for j in Dict_System[i]:
                    for k in range(0, len(Dict_System[i][j])):
                        if (k != len(Dict_System[i][j])-1): f.write(f'{Dict_System[i][j][k]}, ')
                        else: f.write(f'{Dict_System[i][j][k]}')
                    f.write(f';')
                f.write('\n')

def SSL_Vulns(url, t_seconds, context = create_unverified_context(), Dict_SSL = {'Ciphers': [], 'TLS': [], 'Certificate': []}, Counter_URL = 0):
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

    for _ in url:
       if (_ == ':'): Counter_URL += 1
    if (Counter_URL > 1): Port = url.split(':')[2]
    else: Port = 443

    try:
        with create_connection((URL, int(Port)), timeout=t_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=URL) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                Cert_EOL = cert.not_valid_after
                Cert_Signature_Algorithm = cert.signature_hash_algorithm.name.upper()
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
    except (ConnectionRefusedError, gaierror): Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the website\n')

def Take_Screenshot(driver, url, location):
    global Location

    Screen_Dir = join(Location, 'Screenshots')
    try: makedirs(Screen_Dir)
    except FileExistsError: pass
    if ("://" in url): Screen_Name = url.split('://')[1]
    else: Screen_Name = url
    try:
        driver.get(url)
        driver.save_screenshot(join(Screen_Dir, f"{Date}_({Screen_Name}).png"))
    except MaxRetryError: Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - It was not possible to connect to the website to take screenshots\n')
    finally: driver.quit()

    for Picture in listdir(Screen_Dir):
        raw_image = imread(join(Screen_Dir, Picture))
        height = raw_image.shape[0]
        width = raw_image.shape[1]
        start_point, end_point = (0,0), (width, height)
        color = (0,0,0)
        thickness = 10
        img = rectangle(raw_image, start_point, end_point, color, thickness)
        imwrite(join(Screen_Dir, Picture), img)
