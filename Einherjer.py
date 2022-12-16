#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Variables_And_Functions
from resources.VF import *

def main(Dict_Result = {'Header': {}, 'Information': {}, 'SSH': {}, 'SSL': {}, 'Fuzzing': {}, 'Security_Flag': {}}):
    global Counter_Connections, End_Result, File_Name, Location, Switch_nmap, Kill_Command

    def Thread_Scanning_Start(url, t_seconds, queue, driver, scan_ssl, scan_header, scan_fuzzing, scan_ssh, scan_fuzzing_recurse, scan_security_flag, Count_Double_Point = 0, Host_Name = "", Target = ""):
        global Kill_Command

        while (Kill_Command != True):
                try:
                    Dict_Result = queue.get()
                    if (driver != None and '//' in url and 'http' in url): Take_Screenshot(driver, url)
                    if (scan_header != False and '//' in url and 'http' in url):
                        Dict_Temp_Header, Dict_Temp_Information_Disclosure = {},{}
                        try:
                            r = get(url, timeout=(t_seconds, t_seconds), verify=False, allow_redirects=True)
                            # Host_Name_Filtering
                            if ('//' in url):
                                for i in range(0, len(url)):
                                    if (url[i] == ":"): Count_Double_Point += 1
                                if (Count_Double_Point == 2): Host_Name = Get_Host_Name(url.split('//')[1].split(':')[0])
                                else: Host_Name = Get_Host_Name(url.split('//')[1])
                            else: Host_Name = Get_Host_Name(url)
                            if (Host_Name != ""):
                                Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = Host_Name[0], Host_Name[0]
                            else: Dict_Temp_Header['DNS'], Dict_Temp_Information_Disclosure['DNS'] = "",""
                            # Header_Check
                            for Header in r.headers.items():
                                if (Header[0] in Array_Header): Dict_Temp_Header[Header[0]] = Header[1]
                                elif (Header[0] in Array_Information_Disclosure_Header): Dict_Temp_Information_Disclosure[Header[0]] = Header[1]
                                else:
                                    for Temp_Header in array(Array_Header):
                                        if (Temp_Header not in Dict_Temp_Header): Dict_Temp_Header[Temp_Header] = "FEHLT"
                                Dict_Result['Header'][url] = Dict_Temp_Header
                                if (len(Dict_Temp_Information_Disclosure) > 0): Dict_Result['Information'][url] = Dict_Temp_Information_Disclosure
                            if (Host_Name != ""): Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - {Host_Name[0]} - {r}\n{r.headers.items()}\n{Dict_Temp_Header}\n')
                            else: Log_File(f'{strftime("%Y-%m-%d_%H:%M:%S")} - {url} - {r}\n{r.headers.items()}\n{Dict_Temp_Header}\n')
                        except ReadTimeout: Write_Log(url, Host_Name)
                    if (scan_ssl != False and '//' in url and 'http' in url): Dict_Result['SSL'] = SSL_Vulns(url, t_seconds)
                    if (scan_security_flag != False and '//' in url and 'http' in url): Dict_Result['Security_Flag'] = Check_Security_Flags(url, t_seconds)
                    if (scan_fuzzing != False and '//' in url and 'http' in url): Dict_Result['Fuzzing'] = Check_Site_Paths(url, t_seconds)
                    if (scan_fuzzing_recurse != False and '//' in url and 'http' in url): pass
                    if (scan_ssh != False and '//' not in url):
                        try:
                            if (':' not in url): Dict_Result['SSH'][url] = SSH_Vulns((url, 22))
                            else:
                                Target = url.split(':')
                                Dict_Result['SSH'][url] = SSH_Vulns((Target[0]), int(Target[1]))
                        except paramiko.ssh_exception.SSHException: Write_Log(url, Host_Name)
                except (ConnectionError, gaierror, WebDriverException, RequestException): Write_Log(url, Host_Name)
                finally:
                    queue.put(Dict_Result)
                    break
        else:
            Write_Log(url, Host_Name)

    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter, description=Colors.ORANGE+Program_Description+Colors.RESET)
    required = parser.add_argument_group(Colors.ORANGE+'required arguments'+Colors.RESET)
    scan_arguments = parser.add_argument_group(Colors.ORANGE+'scan arguments'+Colors.RESET)
    target_arguments = parser.add_argument_group(Colors.ORANGE+'target arguments'+Colors.RESET)
    auth_arguments = parser.add_argument_group(Colors.ORANGE+'authentication arguments'+Colors.RESET)
    config_arguments = parser.add_argument_group(Colors.ORANGE+'config arguments'+Colors.RESET)
    performance_arguments = parser.add_argument_group(Colors.ORANGE+'performance arguments'+Colors.RESET)
    optional = parser.add_argument_group(Colors.ORANGE+'optional arguments'+Colors.RESET)
    debug_arguments = parser.add_argument_group(Colors.ORANGE+'debug arguments'+Colors.RESET)

    required.add_argument('-f', '--format', choices=['csv','docx','html','json','latex','pdf','tex','xlsx','xml'], type=str, help=Colors.GREEN+'Specify your used format like xlsx (Excel), Docx (MS Word), LaTeX or PDF.'+Colors.RESET+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, required=True)
    required.add_argument('-s', '--sleep', type=float, help=Colors.GREEN+'Set the pauses between the scans to do not DDoS the target.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, required=True)
    scan_arguments.add_argument('-sA', '--scan-all', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this it is possible to scan all functions'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSs', '--scan-site-screenshot', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you can create screenshots of the start pages.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSsr', '--scan-site-screenshot-recursive', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you can create screenshots of the target pages,\nbut with the special feature that any results are checked with the fuzzing\nand screenshots are created from them in each case.'+Colors.RESET+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSL', '--scan-site-ssl', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the TLS/SSL connections for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSh', '--scan-site-header', type=bool, nargs='?', const=True, help=Colors.GREEN+'Use this function to check the HTTP headers for useful information and\nmisconfigurations.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSF', '--scan-site-fuzzing', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the web services for hidden directories or files.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSH', '--scan-ssh', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the SSH service for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sSSF', '--scan-security-flags', type=bool, nargs='?', const=True, help=Colors.GREEN+'With this function you check the cookie flags for vulnerabilities.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-sC', '--scan-credentials', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET, default=False)
    scan_arguments.add_argument('-aNr', '--add-nmap-ssh-result', type=str, help=Colors.GREEN+'With this function you analyze the ssh output of nmap.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    scan_arguments.add_argument('-aW', '--add-wordlist', type=str, help=Colors.GREEN+'With this function you add a word list for fuzzing.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    scan_arguments.add_argument('-amW', '--add-multiple-wordlists', type=str, help=Colors.GREEN+'With this function you add several word lists which are checked for duplicates and\nsort them out for fuzzing.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    target_arguments.add_argument('-iL', '--import-list', type=str, help=Colors.GREEN+'Import your target list in the following example:\n  - http://192.168.2.2\n  - https://192.168.2.3\n  - https://192.168.2.4:8443\n  - 192.168.2.5:22'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)    
    target_arguments.add_argument('-t', '--target', type=str, help=Colors.GREEN+'Specify a single target.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aC', '--add-cert', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aUL', '--add-user-list', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aCPw', '--add-cert-password', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aP', '--add-proxy', type=str, help=Colors.GREEN+'Specify your proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aPc', '--add-proxy-chain', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-o', '--output-location', type=str, help=Colors.GREEN+'Specify the location where the result should be saved.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rCssh', '--read-config-ssh-ciphers', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rCssl', '--read-config-ssl-ciphers', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-mx', '--max-connections', type=int, default=cpu_count()*2, help=Colors.GREEN+f'Defines the max connections via threads or processes for every try to scan. \n\nDefault: {cpu_count()*2}'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-m', '--method', type=str, choices=['Multiprocessing', 'multiprocessing', 'mp', 'MP', 'threading', 'Threading', 't', 'Thread', 'thread'], default='Threading', help=Colors.GREEN+'Defines which method you wanted to use.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-to', '--timeout', type=int, default=30, help=Colors.GREEN+'Specify the connection http timeout in seconds. Default: 30 seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-r', '--random-order', type=bool, nargs='?', const=True, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-tHo', '--thread-timeout', type=int, default=60, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-app', '--append-to-existing-xlsx', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-c', '--custom-chromium-path', type=str, help=Colors.GREEN+'Specify the location of your custom chromium.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    args = parser.parse_args()
    if (args.target == None and args.import_list == None): Error_Message('The program cannot be started without attack targets\n\n')
    elif (args.target == None and args.import_list != None):
        try:
            Array_Targets = Read_File(args.import_list)
            Array_Targets.sort()
        except FileNotFoundError as e: Error_Message(f"Your targetlist can't be found!\n\n{e}")
    else: Array_Targets = [args.target]

    # Webdriver_Options
    if (args.scan_site_screenshot != False):
        options = webdriver.ChromeOptions()
        for _ in Array_Selenium: options.add_argument(_)
        if (args.custom_chromium_path != None): options.binary_location = args.custom_chromium_path
        else:
            if (osname != 'nt'): options.binary_location = "/usr/bin/chromium"

        def Driver_Specification(option):
            if (osname == 'nt'): driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'resources/chromedriver.exe')), options=option)
            else: driver = webdriver.Chrome(service=Service(join(dirname(realpath(__file__)), 'resources/chromedriver')), options=option)
            return driver

        if ("ttl" in getoutput('ping -c 2 8.8.8.8')):
            if (osname == 'nt'): driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
            else:
                try: driver = Driver_Specification(options)
                except (ConnectionError): pass
                except (MaxRetryError, ProxyError, ProxySchemeUnknown): Error_Message("\n\nThere is a error in your proxy configuration or the proxy server is blocking your connection.\n\n")
                except (gaierror, NewConnectionError): Error_Message("\n\nIt was not possible to connect to the Server.\n\n")
                except SessionNotCreatedException as e:
                    if (osname != 'nt'):
                        print (f'Chromium: {getoutput("apt-cache policy chromium").splitlines()[1][1:].split(":")[1][1:]})')
                        for _ in str(e).splitlines():
                            if ("chrome=" in _):
                                print(f'Webdriver: {_.split("chrome=")[1][:-1]}')
                        if ('xfce' in getoutput('ls /usr/bin/*session') or 'gnome' in getoutput('ls /usr/bin/*session')):
                            sleep(3.5), webbrowser_open("https://chromedriver.chromium.org/downloads")
                    Error_Message("\nIt looks like you do not have the correct Chromedriver version installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the resources folder.\n")
                except WebDriverException: Error_Message("\nIt looks like that you do not have Chromedriver installed.\n\nPlease go to https://chromedriver.chromium.org/downloads and download the correct chromedriver and paste it into the resources folder.\n")
            driver.implicitly_wait(args.timeout), driver.set_window_size(1920,1080), driver.execute_script("document.body.style.zoom='250%'")
        else: driver = Driver_Specification(options)

    if (args.add_wordlist != None and args.add_multiple_wordlists == None):
        if (args.add_wordlist not in Array_Wordlists):
            for word in Read_File(args.add_wordlist):
                if (word not in Array_Wordlists): Array_Wordlists.append(word)
    elif (args.add_wordlist == None and args.add_multiple_wordlists != None):
        for root,_,files in walk(args.add_multiple_wordlists):
            for file in files:
                for word in Read_File(join(root, file)):
                    if (word not in Array_Wordlists):
                        Array_Wordlists.append(word)

    if (args.output_location != None):
        if exists(args.output_location):
            if ('.' in args.output_location or './' in args.output_location):
                if ('./' in args.output_location): Location = join(getcwd(), args.output_location[2:])
                else: Location = join(getcwd(), args.output_location)
            elif ('.' not in args.output_location and '/' not in args.output_location): Location = join(getcwd(), args.output_location)
            elif ('/' in args.output_location and not '.' in args.output_location): Location = args.output_location
        else:
            if ('.' in args.output_location or './' in args.output_location):
                if ('./' in args.output_location):
                    makedirs(join(getcwd(), args.output_location[2:]))
                    Location = join(getcwd(), args.output_location[2:])
                else:
                    makedirs(join(getcwd(), args.output_location))
                    Location = join(getcwd(), args.output_location)
            elif ('.' not in args.output_location and '/' not in args.output_location): Location = Create_Location_Dir(join(getcwd(), args.output_location))
            elif ('/' in args.output_location and not '.' in args.output_location): Location = Create_Location_Dir(args.output_location)
    else: Location = dirname(realpath(__file__))

    if (args.method == "Threading" or args.method == "threading" or args.method == "t" or args.method == "Thread" or args.method == "thread"): Method = "Thread"
    elif (args.method == "Multiprocessing" or args.method == 'multiprocessing' or args.method == 'mp' or args.method == 'MP'): Method = "MP"

    if (args.read_config_ssh_ciphers != None): pass
    if (args.read_config_ssl_ciphers != None): pass

    if (args.scan_all == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False): Error_Message('The scanning method is missing!\n')
    elif (args.scan_all != False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
        Array_Switch.append(driver),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True)
    elif (args.scan_all == False):
        if (args.scan_site_screenshot != False): Array_Switch.append(driver)
        else: Array_Switch.append(None)
        if (args.scan_site_ssl != False): Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_site_header != False): Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_site_fuzzing != False): Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_ssh != False): Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.add_nmap_ssh_result != None): Switch_nmap = True
        if (args.scan_site_screenshot_recursive != False): Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_security_flags != False): Array_Switch.append(True)
        else: Array_Switch.append(False)

    Initialien(args.debug)
    setdefaulttimeout(args.timeout)
    Counter_Bar = float(100/len(Array_Targets))
    if __name__ == '__main__':
        with Progress(*progress_columns) as progress:
            queue = Queue()
            queue.put(Dict_Result)
            task_Scan = progress.add_task("[cyan]Scanning for vulnerabilities...", total=len(Array_Targets))
            task_Filter = progress.add_task("[cyan]Filtering the results...", total=100, start=False)
            for Target in array(Array_Targets):
                Array_Thread_Args.append(Target), Array_Thread_Args.append(args.timeout), Array_Thread_Args.append(queue)
                for _ in Array_Switch: Array_Thread_Args.append(_)
                if (Method == "Thread"): p = Thread(target=Thread_Scanning_Start, args=Array_Thread_Args, daemon=True)
                elif (Method == "MP"): p = Process(target=Thread_Scanning_Start, args=Array_Thread_Args, daemon=True)
                p.start()
                Counter_Connections += 1
                if (Counter_Connections == args.max_connections):
                    Timer = perf_counter()
                    while (len(Array_Threads) > 0):
                        for Thread_ID in array(Array_Threads):
                            if (Method == "Thread"): Thread_Check(Thread_ID, Th_enumerate())
                            elif (Method == "MP"): Thread_Check(Thread_ID, active_children())
                        Status = perf_counter()
                        if (int(Status - Timer) < 90):
                            sleep(2.25)
                        else:
                            Kill_Command, Counter_Connections = True, 0
                            Array_Threads.clear(), sleep (1.5)
                            Kill_Command = False
                else:
                     if (p.name not in Array_Threads): Array_Threads.append(p.name), sleep(args.sleep)
                progress.update(task_Scan, advance=Counter_Bar)
                Array_Thread_Args.clear()
            Timer = perf_counter()
            while (len(Array_Threads) > 0):
                for Thread_ID in array(Array_Threads):
                    if (Method == "Thread"): Thread_Check(Thread_ID, Th_enumerate())
                    elif (Method == "MP"): Thread_Check(Thread_ID, active_children())
                    Status = perf_counter()
                    if (int(Status - Timer) < 600):
                        sleep(2.25)
                    else:
                        Kill_Command = True
                        Array_Threads.clear(), sleep (1.5)
                        Kill_Command = False
                sleep(0.75)
            Dict_Result = queue.get()

            if ("csv" in args.format):
                from Format.CSV_Format import CSV_Table
                Array_Output = CSV_Table(Dict_Result, Location, File_Name)
            elif ("docx" in args.format or "word" in args.format):
                from Format.Word_Format import Word_Table
                Word_Table(Dict_Result)
            elif ("html" in args.format):
                from Format.HTML_Format import HTML_Table
                HTML_Table(Dict_Result)
            elif ("json" in args.format):
                from Format.JSON_Format import Create_JSON
                #Create_Json(Dict_Result)
            elif ("latex" in args.format or "tex" in args.format):
                from Format.LaTeX_Format import Latex_Table
                Latex_Table(Dict_Result)
            elif ("pdf" in args.format):
                from Format.PDF_Format import Create_PDF
                Word_Table(Dict_Result)
                if (osname == 'nt'): Create_PDF()
                else: print("At this point it's not be possible to convert a docx file into a pdf under linux.\nPlease try it under windows.\n")
            elif ("xlsx" in args.format):
                from Format.Excel_Format import Excel_Table
                Excel_Table(Dict_Result)
            elif ("xml" in args.format):
                from Format.XML_Format import Create_XML
                #Create_XML(Dict_Result)
            else: Error_Message("Your Decision was not acceptable!")

            progress.start_task(task_Filter)
            while not progress.finished:
                progress.update(task_Scan, advance=Counter_Bar)
                progress.update(task_Filter, advance=0.5)
                sleep(0.01)

    Stdout_Output(Colors.CYAN+End_Result+Colors.RESET, 0.01)
    for _ in Array_Output:
        Stdout_Output(Colors.ORANGE+f'   - {_}\n'+Colors.RESET, 0.01)
# Main
if __name__ == '__main__':
    try: main()
    except KeyboardInterrupt:
        Kill_Command = True
        exit()
