#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.TF import *

# Main_Function
def main(Date, Dict_Result = {'Header': {}, 'Information': {}, 'SSH': {}, 'SSL': {}, 'Fuzzing': {}, 'Security_Flag': {}}, Dict_Threads = {}, Counter_Connections = 0, Array_Switch = []):
    global Location, Switch_Internet_Connection, Switch_nmap

    parser = ArgumentParser(add_help=False, formatter_class=RawTextHelpFormatter, description=Colors.ORANGE+Program_Description+Colors.RESET, allow_abbrev=False)
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
    scan_arguments.add_argument('-6', '--ipv6', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    target_arguments.add_argument('-iL', '--import-list', type=str, help=Colors.GREEN+'Import your target list in the following example:\n  - http://192.168.2.2\n  - https://192.168.2.3\n  - https://192.168.2.4:8443\n  - 192.168.2.5:22'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)    
    target_arguments.add_argument('-t', '--target', type=str, nargs='*', help=Colors.GREEN+'Specify a single or multiple targets like in the following example:\n   - 127.0.0.1, http://127.0.0.1, https://127.0.0.1'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aC', '--add-cert', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aUL', '--add-user-list', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    auth_arguments.add_argument('-aCPw', '--add-cert-password', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aHP', '--add-http-proxy', type=str, help=Colors.GREEN+'Specify your HTTP-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-aHSP', '--add-https-proxy', type=str, help=Colors.GREEN+'Specify your HTTPS-Proxy.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-o', '--output-location', type=str, help=Colors.GREEN+'Specify the location where the result should be saved.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rCssh', '--read-config-ssh-ciphers', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    config_arguments.add_argument('-rCssl', '--read-config-ssl-ciphers', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-mx', '--max-connections', type=int, default=cpu_count()*2, help=Colors.GREEN+f'Defines the max connections via threads or processes for every try to scan. \n\nDefault: {cpu_count()*2}'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-to', '--timeout', type=int, default=30, help=Colors.GREEN+'Specify the connection http timeout in seconds.\n\nDefault: 30 seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-r', '--random-order', type=bool, nargs='?', default=False, help=Colors.GREEN+'This parameter randomize your targets.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    performance_arguments.add_argument('-tHo', '--thread-timeout', type=int, default=90, help=Colors.GREEN+'This parameter sets the max time to wait until a thread will be terminated\n\nDefault: 90 Seconds'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-app', '--append-to-existing-xlsx', type=str, help=Colors.GREEN+'UNDER CONSTRUCTION.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-c', '--custom-chromium-path', type=str, help=Colors.GREEN+'Specify the location of your custom chromium.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    optional.add_argument('-h','--help', action='help', default=SUPPRESS, help=Colors.GREEN+'Show this help message and exit.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)
    debug_arguments.add_argument('-d', '--debug', type=bool, nargs='?', default=False, help=Colors.GREEN+'This Parameter deactivates the terminal clearing after starting the tool.'+Colors.BLUE+'\n\n-------------------------------------------------------------------------------------'+Colors.RESET)

    args = parser.parse_args()
    if (args.target == None and args.import_list == None): Logs.Error_Message('The program cannot be started without targets')
    elif (args.target == None and args.import_list != None):
        try:
            Array_Targets = Standard.Read_File(args.import_list)
            if (args.random_order == True): shuffle(Array_Targets)
            else: Array_Targets.sort()
        except FileNotFoundError as e: Logs.Error_Message(f"Your targetlist can't be found!\n\n{e}")
    else:
        if (len(args.target) > 1):
            Array_Targets = []
            for _ in args.target:
                if (',' in _): Array_Targets.append(_[:-1])
                else: Array_Targets.append(_)
        else:
            if (',' in args.target[0]):
                Temp_Split = args.target[0].split(',')
                for _ in Temp_Split:
                    if (_ != ''): Array_Targets.append(_)
            else: Array_Targets = [args.target[0]]

    # Webdriver_Options
    if (args.scan_site_screenshot != False):
        if ("ttl" in getoutput('ping -c 2 8.8.8.8')):
            Switch_Internet_Connection = True
        options = webdriver.ChromeOptions()
        for _ in Array_Selenium: options.add_argument(_)
        if (args.custom_chromium_path != None): options.binary_location = args.custom_chromium_path
        else:
            if (osname != 'nt'): options.binary_location = "/usr/bin/chromium"

        if (Switch_Internet_Connection == True):
            if (osname == 'nt'):
                Chrome_Path = ChromeDriverManager().install()
                driver = webdriver.Chrome(service=Service(Chrome_Path), options=options)
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
        else: driver = Driver_Specification(options)
        driver.implicitly_wait(args.timeout), driver.set_window_size(1920,1080), driver.execute_script("document.body.style.zoom='250%'")

    if (args.add_wordlist != None and args.add_multiple_wordlists == None):
        if (args.add_wordlist not in Array_Wordlists):
            for word in Standard.Read_File(args.add_wordlist):
                if (word not in Array_Wordlists): Array_Wordlists.append(word)
    elif (args.add_wordlist == None and args.add_multiple_wordlists != None):
        for root,_,files in walk(args.add_multiple_wordlists):
            for file in files:
                for word in Standard.Read_File(join(root, file)):
                    if (word not in Array_Wordlists):
                        Array_Wordlists.append(word)

    if (args.output_location != None):
        if exists(args.output_location):
            if ('.' in args.output_location or './' in args.output_location):
                if ('./' in args.output_location): Location = join(getcwd(), f"{args.output_location[2:]}/{Date}")
                else: Location = join(getcwd(), f"{args.output_location}/{Date}")
            elif ('.' not in args.output_location and '/' not in args.output_location): Location = join(getcwd(), f"{args.output_location}/{Date}")
            elif ('/' in args.output_location and not '.' in args.output_location): Location = f"{args.output_location}/{Date}"
        else:
            if ('.' in args.output_location or './' in args.output_location):
                if ('./' in args.output_location): Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location[2:]}/{Date}"))
                else: Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location}/{Date}"))
            elif ('.' not in args.output_location and '/' not in args.output_location): Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location}/{Date}"))
            elif ('/' in args.output_location and not '.' in args.output_location): Location = Standard.Create_Location_Dir(f"{args.output_location}/{Date}")
    else: Location = join(dirname(realpath(__file__)), f"{args.output_location}/{Date}")

    if (args.read_config_ssh_ciphers != None): pass
    if (args.read_config_ssl_ciphers != None): pass

    if (args.add_http_proxy != None): Dict_Proxies['http'] = args.add_http_proxy
    if (args.add_https_proxy != None): Dict_Proxies['https'] = args.add_https_proxy

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

    Standard.Initialien(args.debug)
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
                p = Process(target=Thread_Scanning_Start, args=Array_Thread_Args, daemon=True)
                p.start()
                Counter_Connections += 1
                if (Counter_Connections == args.max_connections):
                    while (len(Dict_Threads) > 0):
                        try:
                            for Thread_ID in Dict_Threads:
                                if (Thread_ID not in str(active_children())):
                                    Dict_Threads.pop(Thread_ID, None)
                                    Counter_Connections -= 1
                                else:
                                    if ((time() - Dict_Threads[Thread_ID][1]) > args.thread_timeout):
                                        Dict_Threads[Thread_ID][0].terminate()
                                        Logs.Write_Log(Target)
                                        Dict_Threads.pop(Thread_ID, None)
                                        Counter_Connections -= 1
                        except RuntimeError: pass
                        sleep(2.25)
                else:
                     if (p.name not in Dict_Threads):
                            Dict_Threads[p.name] = [p, time(), Target]
                            sleep(args.sleep)
                progress.update(task_Scan, advance=Counter_Bar)
                Array_Thread_Args.clear()
            while (len(Dict_Threads) > 0):
                try:
                    for Thread_ID in Dict_Threads:
                        if (Thread_ID not in str(active_children())):
                            Dict_Threads.pop(Thread_ID, None)
                        else:
                            if ((time() - Dict_Threads[Thread_ID][1]) > 900):
                                Dict_Threads[Thread_ID][0].terminate()
                                Dict_Threads.pop(Thread_ID, None)
                except RuntimeError: pass
                sleep(0.75)
            Dict_Result = queue.get()

            if ("csv" in args.format):
                from Resources.Format.CSV_Format import CSV_Table
                Array_Output = CSV_Table(Dict_Result, Location)
            elif ("docx" in args.format or "word" in args.format):
                from Resources.Format.Word_Format import Word_Table
                Array_Output = Word_Table(Dict_Result)
            elif ("html" in args.format):
                from Resources.Format.HTML_Format import HTML_Table
                Array_Output = HTML_Table(Dict_Result)
            elif ("json" in args.format):
                from Resources.Format.JSON_Format import Create_JSON
                #Create_Json(Dict_Result)
            elif ("latex" in args.format or "tex" in args.format):
                from Resources.Format.LaTeX_Format import Latex_Table
                Array_Output = Latex_Table(Dict_Result)
            elif ("pdf" in args.format):
                from Resources.Format.PDF_Format import Create_PDF
                Array_Output = Word_Table(Dict_Result)
                if (osname == 'nt'): Create_PDF()
                else: print("At this point it's not be possible to convert a docx file into a pdf under linux.\nPlease try it under windows.\n")
            elif ("xlsx" in args.format):
                from Resources.Format.Excel_Format import Excel_Table
                Array_Output = Excel_Table(Dict_Result)
            elif ("xml" in args.format):
                from Resources.Format.XML_Format import Create_XML
                #Array_Output = Create_XML(Dict_Result)
            else: Error_Message("Your Decision was not acceptable!")

            progress.start_task(task_Filter)
            while not progress.finished:
                progress.update(task_Scan, advance=Counter_Bar)
                progress.update(task_Filter, advance=0.5)
                sleep(0.01)

    if (Array_Output != []):
        Standard.Stdout_Output(Colors.CYAN+"\n\nYour Scan was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
        for _ in Array_Output:
            Standard.Stdout_Output(Colors.ORANGE+f'   - {_}\n'+Colors.RESET, 0.01)
    else: Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your connection or target file and try it again.'+Colors.RESET, 0.01)

# Main
if __name__ == '__main__':
    try: main(Date)
    except KeyboardInterrupt:
        exit()
