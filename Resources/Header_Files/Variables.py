#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Colors import Colors
from Resources.Header_Files.Libraries import *
from Resources.Standard_Operations.Standard import *
from Resources.Standard_Operations.Logs import *

# Arrays
Array_Header = ['X-FRAME-OPTIONS', 'X-XSS-PROTECTION', 'CONTENT-SECURITY-POLICY', 'STRICT-TRANSPORT-SECURITY', 'X-CONTENT-TYPE-OPTIONS', 'REFERRER-POLICY']
Array_Paths, Array_SSL_Vulns, Array_Results = [],[],[]
Array_Information_Disclosure_Header = ["X-POWERED-BY", "SERVER"]
Array_Security_Flags = ['SameSite', 'samesite', 'HttpOnly', 'httponly', 'Secure', 'secure', 'JSessID']
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
    "rsa-sha2-256",
    "rsa-sha2-512",
    "ssh-ed25519",
    # Encryption_Algorithm
    "AEAD_AES_128_GCM",
    "AEAD_AES_256_GCM",
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "chacha20-poly1305",
    "aes128-gcm",
    "aes256-gcm",
    # MAC
    "hmac-sha2-256",
    "hmac-sha2-512",
    "hmac-sha2-256-etm",
    "hmac-sha2-512-etm",
    "umac-128",
    "umac-128-etm"]
Array_TLS_Algorithms = ["SHA","MD5","RC2","RC4","IDEA","ADH","3DES","NULL","PSK","ANON","CBC","DHE","ECDHE"]

# Dictionaries
Dict_Proxies = {'http': '', 'https': ''}

# Variables
Date, COLOR_Headline, Log_Path = strftime('%Y-%m-%d_%H-%M-%S'), "black", dirname(realpath(__file__)).replace('Resources/Header_Files', 'Logs')
Switch_Internet_Connection, Switch_nmap, existing_nmap_file = False, False, ""

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

# Classes
#class Standard:
#    def Stdout_Output(Text_Array, Output_Seconds):
#        for char in Text_Array:
#            stdout.write(char)
#            stdout.flush()
#            sleep(Output_Seconds)
#
#    def Create_Underline(Text, max_numbers, word = ""):
#        for _ in range(0, max_numbers):
#            word += Text
#        return word
#
#    def Initialien(debug_parameter):
#        if (debug_parameter == False):
#            if (osname == 'nt'): system('cls')
#            else: system('clear')
#        else: system('')
#        Header = """
#💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀
#💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
#💀\t\t\t\t\t           """+Colors.UNDERLINE+"Einherjer"+Colors.RESET+ """\t\t\t\t\t\t\t  💀
#💀\t\t\t\t\t\t  """+Colors.ORANGE+"Version "+Colors.BLUE+"0.7"+Colors.RESET+"""\t\t\t\t\t\t\t  💀
#💀\t\t\t\t\t"""+Colors.CYAN+"Rainer Christian Bjoern Herold"+Colors.RESET+"""\t\t\t\t\t\t  💀
#💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
#💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀\n\n
#"""
#        Standard.Stdout_Output(Header, 0.004)
#
#    def Create_Location_Dir(output_location_dir):
#        try:
#            makedirs(output_location_dir)
#            return output_location_dir
#        except:
#            makedirs(join(dirname(realpath(__file__)), output_location_dir))
#            print (f"Your location can't be found or was not allowed!\n\nYour new location was set to {join(dirname(realpath(__file__)), output_location_dir)}")
#            return join(dirname(realpath(__file__)), output_location_dir)
#
#    def Read_File(file_path):
#        with open(file_path, 'r') as f:
#            return f.read().splitlines()
#
#    def Read_Template(template_file):
#        if (exists(template_file)):
#            return Standard.Read_File(template_file)
#        else: Logs.Error_Message(f'The requested File {template_file} does not exist!')
#
#    def Try_Remove_File(x):
#        while True:
#            try:
#                remove(x)
#                break
#            except FileNotFoundError:
#                break
#            except PermissionError: Logs.Error_Message(f"The file {x} is already open!\nPlease close it and wait five seconds.")
#            sleep(5)

#class Logs:
#    def Error_Message(x):
#        print(x), sleep(2), exit()
#
#    def Write_Log(url, host):
#        if (not exists(Log_Path)): makedirs(Log_Path)
#        with open(join(Log_Path, f'{Date}_failed-url.txt'), 'a') as f:
#            f.write(f'{url}\n')
#        if (host != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.RED+'FAILED\n'+Colors.RESET)
#        else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.RED+'FAILED\n'+Colors.RESET)
#
#    def Log_File(Text):
#        if (not exists(Log_Path)): makedirs(Log_Path)
#        with open(join(Log_Path, f"{Date}.log"), "a") as f:
#            f.write(Text)

class Web:
    def Driver_Specification(option):
        if (osname == 'nt'): driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'Resources/Webdriver/chromedriver.exe')), options=option)
        else: driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'Resources/Webdriver/chromedriver')), options=option)
        return driver

    def Configurate_Driver(options, driver = None):
        try: driver = Web.Driver_Specification(options)
        except (ConnectionError): pass
        except (MaxRetryError, ProxyError, ProxySchemeUnknown): Logs.Error_Message("\n\nThere is a error in your proxy configuration or the proxy server is blocking your connection.\n\n")
        except (gaierror, NewConnectionError): Logs.Error_Message("\n\nIt was not possible to connect to the Server.\n\n")
        except SessionNotCreatedException as e:
            if (osname != 'nt'):
                print (f'Chromium: {getoutput("apt-cache policy chromium").splitlines()[1][1:].split(":")[1][1:]})')
                for _ in str(e).splitlines():
                    if ("chrome=" in _):
                        print(f'Webdriver: {_.split("chrome=")[1][:-1]}')
                if ('xfce' in getoutput('ls /usr/bin/*session') or 'gnome' in getoutput('ls /usr/bin/*session')):
                    sleep(3.5), webbrowser_open("https://chromedriver.chromium.org/downloads")
            Logs.Error_Message("\nIt looks like you do not have the correct Chromedriver version installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the Resources folder.\n")
        except WebDriverException: Logs.Error_Message("\nIt looks like that you do not have Chromedriver installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the Resources folder.\n")
        return driver

    def Screenshot_Filter(Path):
        for Pictures in listdir(Path):
            Picture = imread(join(Path, Pictures))
            for _ in listdir(Path):
                if (_ != Picture):
                    Duplicate = imread(join(Path, _))
                    Difference = subtract(Picture, Duplicate)
                    b,g,r = cvsplit(difference)

                    if (countNonZero(b) == 0 and countNonZero(g) == 0 and countNonZero(r) == 0):
                        pass

# Functions
def Get_Host_Name(url, Count_Double_Point = 0, Target = "", Temp = "", Word = ""):
    if ('//' in url):
        for i in range(0, len(url)):
            if (url[i] == ":"): Count_Double_Point += 1
        if (Count_Double_Point == 2): Target = url.split('//')[1].split(':')[0]
        else: Target = url.split('//')[1]
    else: Target = url

    try: Temp = gethostbyaddr(Target)
    except (gaierror, herror):
        try:
            Temp = gethostbyname(Target)
            if (Temp == Target): Temp = ""
        except (gaierror, herror): pass

    if (type(Temp) == tuple or type(Temp) == list):
        for _ in Temp:
            if (_ != []):
                if (type(_) != list):
                    if (_ != Temp[len(Temp)-1]): Word += f"{_}, "
                    else: Word += f"{_}"
                else:
                    for j in _:
                        if (j != _[len(_)-1]): Word += f"{j}, "
                        else:
                            if (_ != Temp[len(Temp)-1]): Word += f"{j}, "
                            else: Word += f"{j}"
    elif (type(Temp) == str): Word = Temp
    return Word

def Check_Site_Header(url, t_seconds, Host_Name, Dict_Temp_Header = {}, Dict_Temp_Information_Disclosure = {}):
    try:
        r = get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)
        if (Host_Name != ""): Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name, Host_Name
        else: Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""

        for Header in r.headers.items():
            if (Header[0].upper() in Array_Header): Dict_Temp_Header[Header[0].upper()] = Header[1].upper()
            elif (Header[0].upper() in Array_Information_Disclosure_Header): Dict_Temp_Information_Disclosure[Header[0].upper()] = Header[1]
            else:
                for Temp_Header in array(Array_Header):
                    if (Temp_Header not in Dict_Temp_Header): Dict_Temp_Header[Temp_Header] = "FEHLT"
        if (Host_Name != ""): Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - {Host_Name} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
        else: Logs.Log_File(Colors.GREEN+f'{strftime("%Y-%m-%d %H:%M:%S")}'+Colors.RESET+f' - {url} - '+Colors.BLUE+f'{r}'+Colors.ORANGE+'\nOriginal Output'+Colors.RED+' -> '+Colors.RESET+f'{r.headers.items()}'+Colors.ORANGE+'\n Einherjer Filter'+Colors.RED+' -> '+Colors.RESET+f'{Dict_Temp_Header}\n')
    except ReadTimeout: Logs.Write_Log(url, Host_Name)

    return Dict_Temp_Header, Dict_Temp_Information_Disclosure

def Check_Site_Paths(url, t_seconds, array_wordlists, Array_Temp = [], Array_Status_Code = ["200", "302", "405", "500"]):
    for Word in array_wordlists:
        URL = f'{url}/{Word}'
        r = get(URL, timeout=t_seconds, verify=False, allow_redirects=True)
        if (str(r.status_code) in Array_Status_Code):
            if (URL not in Array_Temp): Array_Temp.append(URL)
        sleep(t_seconds)

    return Array_Temp

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

    for Header_Key, Header_Values in r.headers.items():
        if ("COOKIE" in Header_Key.upper()):
            for Flag in Array_Security_Flags:
                if (Flag not in Header_Values): pass
    for cookie in dict(s.cookies): pass
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

def Take_Screenshot(driver, url, location, switch_connection):
    if (switch_connection == True):
        if (osname == 'nt'):
            Chrome_Path = ChromeDriverManager().install()
            driver = webdriver.Chrome(service=Service(Chrome_Path), options=options)
        else:
            driver = Web.Driver_Specification(options)
    else: driver = Web.Driver_Specification(options)
    driver.implicitly_wait(args.timeout), driver.set_window_size(1920,1080), driver.execute_script("document.body.style.zoom='250%'")

    Screen_Dir = join(location, 'Screenshots')
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
