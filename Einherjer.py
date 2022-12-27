#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.VF import *

# Main_Function
def main(Date, Dict_Result = {'Header': {}, 'Information': {}, 'SSH': {}, 'SSL': {}, 'Fuzzing': {}, 'Security_Flag': {}}, Array_Switch = [], Array_Thread_Args = [], Dict_Threads = {}, Counter_Connections = 0):
    global Switch_Internet_Connection, Switch_nmap

    # Argument_Parser
    from Resources.ArgParser import Argument_Parser
    args = Argument_Parser()
    del Argument_Parser

    # Target_Options
    if (args.target == None and args.import_list == None): Logs.Error_Message('The program cannot be started without targets')
    elif (args.target == None and args.import_list != None):
        try: Array_Targets = Standard.Read_File(args.import_list)
        except FileNotFoundError as e: Logs.Error_Message(f"Your targetlist can't be found!\n\n{args.import_list}")
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
    if (args.random_order == True):
        try: from random import shuffle
        except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
        shuffle(Array_Targets)
        del shuffle
    else: Array_Targets.sort()

    # Webdriver_Options
    if (args.scan_site_screenshot != False):
        try:
            from contextlib import redirect_stdout
            from cv2 import countNonZero, imread, imwrite, rectangle, split as cvsplit, subtract
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.common.keys import Keys
            from selenium.webdriver.chrome.service import Service
            from selenium.webdriver.remote.webdriver import WebDriver
            from webbrowser import open as webbrowser_open
            with redirect_stdout(None):
               from webdriver_manager.chrome import ChromeDriverManager
        except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

        Array_Selenium = ['--start_maximized','--no-sandbox','--remote-debugging-port=19222','--ignore-certificate-errors','--test-type','--headless','--log-level=3']

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
                driver = Web.Driver_Specification(options)
        else: driver = Web.Driver_Specification(options)
        driver.implicitly_wait(args.timeout), driver.set_window_size(1920,1080), driver.execute_script("document.body.style.zoom='250%'")
        del ChromeDriverManager, webbrowser_open

    # Wordlist_Filtering
    if (args.add_wordlist != None and args.add_multiple_wordlists == None):
        Array_Wordlists = []
        if (args.add_wordlist not in Array_Wordlists):
            for word in Standard.Read_File(args.add_wordlist):
                if (word not in Array_Wordlists): Array_Wordlists.append(word)
    elif (args.add_wordlist == None and args.add_multiple_wordlists != None):
        Array_Wordlists = []
        for root,_,files in walk(args.add_multiple_wordlists):
            for file in files:
                for word in Standard.Read_File(join(root, file)):
                    if (word not in Array_Wordlists):
                        Array_Wordlists.append(word)

    # Output_Location
    if (args.output_location != None):
        if ('.' in args.output_location or './' in args.output_location):
            if ('./' in args.output_location): Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location[2:]}/{Date}"))
            else: Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location}/{Date}"))
        elif ('.' not in args.output_location and '/' not in args.output_location): Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location}/{Date}"))
        elif ('/' in args.output_location and not '.' in args.output_location): Location = Standard.Create_Location_Dir(f"{args.output_location}/{Date}")
    else: Location = Standard.Create_Location_Dir(join(dirname(realpath(__file__)), Date))

    # Template_Filtering
    if (args.read_config_http_header != None): pass
    if (args.read_config_cookie_security_flags != None): pass
    if (args.read_config_ssh_ciphers != None): pass
    if (args.read_config_ssl_ciphers != None): pass

    # Proxy_Settings
    if (args.add_http_proxy != None): Dict_Proxies['http'] = args.add_http_proxy
    if (args.add_https_proxy != None): Dict_Proxies['https'] = args.add_https_proxy

    # Scanning_Options
    if (args.scan_all == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False): Error_Message('The scanning method is missing!\n')
    elif (args.scan_all != False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
        try:
            from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from paramiko.transport import Transport
            from requests import get, Session
            from socket import create_connection
            import asyncio
        except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
        Array_Switch.append(driver),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True)
    elif (args.scan_all == False):
        if (args.scan_site_screenshot != False): Array_Switch.append(driver)
        else: Array_Switch.append(None)
        if (args.scan_site_ssl != False):
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from socket import create_connection
            except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
            Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_site_header != False):
            try: from requests import get
            except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
            Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_site_fuzzing != False):
            try: from requests import get
            except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
            Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_ssh != False):
            try:
                from asyncssh import Error as AsyncSSHError, get_server_auth_methods, SSHClient, SSHClientConnection
                from paramiko.transport import Transport
                import asyncio
            except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
            Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.add_nmap_ssh_result != None): Switch_nmap = True
        if (args.scan_site_screenshot_recursive != False): Array_Switch.append(True)
        else: Array_Switch.append(False)
        if (args.scan_security_flags != False):
            try: from requests import Session
            except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
            Array_Switch.append(True)
        else: Array_Switch.append(False)

    def Thread_Scanning_Start(url, t_seconds, queue, driver_options, scan_ssl, scan_header, scan_fuzzing, scan_ssh, scan_fuzzing_recurse, scan_security_flag, Host_Name = "", Target = ""):
        try:
            Dict_Result = queue.get()
            Host_Name = Get_Host_Name(url)
            if (driver_options != None and '//' in url and 'http' in url):
                Take_Screenshot(url, driver_options)
            if (scan_header != False and '//' in url and 'http' in url):
                Dict_Result['Header'][url], Dict_Result['Information'][url] = Check_Site_Header(url, t_seconds, Host_Name)
            if (scan_ssl != False and '//' in url and 'http' in url):
                Dict_Result['SSL'] = SSL_Vulns(url, t_seconds)
            if (scan_security_flag != False and '//' in url and 'http' in url):
                Dict_Result['Security_Flag'] = Check_Security_Flags(url, t_seconds)
            if (scan_fuzzing != False and '//' in url and 'http' in url):
                Dict_Result['Fuzzing'] = Check_Site_Paths(url, t_seconds)
            if (scan_fuzzing_recurse != False and '//' in url and 'http' in url):
                pass
            if (scan_ssh != False and '//' not in url):
                try:
                    if (':' not in url): Dict_Result['SSH'][url] = SSH_Vulns((url, 22))
                    else:
                        Target = url.split(':')
                        Dict_Result['SSH'][url] = SSH_Vulns((Target[0]), int(Target[1]))
                except paramiko.ssh_exception.SSHException: Logs.Write_Log(url, Host_Name)
        except (ConnectionError, gaierror, WebDriverException, RequestException): Logs.Write_Log(url, Host_Name)
        finally:
            queue.put(Dict_Result)

    # Program_Start
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

            # Format_Filtering
            if ("csv" in args.format):
                from Resources.Format.CSV import CSV_Table
                Array_Output = CSV_Table(Dict_Result, Location)
            elif ("docx" in args.format or "word" in args.format):
                from Resources.Format.Word import Word_Table
                Array_Output = Word_Table(Dict_Result, Location)
            elif ("html" in args.format):
                from Resources.Format.HTML import HTML_Table
                Array_Output = HTML_Table(Dict_Result, Location)
            elif ("json" in args.format):
                from Resources.Format.JSON import JSON_Table
                #Array_Output = JSON_Table(Dict_Result, Location)
            elif ("md" in args.format):
                from Resources.Format.Markdown import Markdown_Table
                Array_Output = Markdown_Table(Dict_Result, Location)
            elif ("pdf" in args.format):
                from Resources.Format.PDF import Create_PDF
                Array_Output = Word_Table(Dict_Result, Location)
                if (osname == 'nt'): Create_PDF(Location)
                else: print("At this point it's not be possible to convert a docx file into a pdf under linux.\nPlease try it under windows.\n")
            elif ("tex" in args.format):
                from Resources.Format.LaTeX import Latex_Table
                Array_Output = Latex_Table(Dict_Result, Location)
            elif ("xlsx" in args.format):
                from Resources.Format.Excel import Excel_Table
                Array_Output = Excel_Table(Dict_Result, Location)
            elif ("xml" in args.format):
                from Resources.Format.XML import XML_Table
                #Array_Output = XML_Table(Dict_Result, Location)
            else: Error_Message("Your Decision was not acceptable!")

            # Progress_End
            progress.start_task(task_Filter)
            while not progress.finished:
                progress.update(task_Scan, advance=Counter_Bar)
                progress.update(task_Filter, advance=0.5)
                sleep(0.01)

    # Output_End
    if (Array_Output != []):
        Standard.Stdout_Output(Colors.CYAN+"\n\nYour Scan was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
        for _ in Array_Output:
            Standard.Stdout_Output(Colors.ORANGE+f'   - {_}\n'+Colors.RESET, 0.01)
    else: Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your connection or target file and try it again.'+Colors.RESET, 0.01)

# Main
if __name__ == '__main__':
    try: main(Date)
    except KeyboardInterrupt: exit()
