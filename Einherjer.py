#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Threads import *
from Resources.Workfiles.Scan_Screen import Web

# Main_Function
def main(Date, args, Dict_Result = {'Header': {}, 'Information': {}, 'SSH': {}, 'SSL': {}, 'Fuzzing': {}, 'Security_Flag': {}}, Dict_Proxies = {'http': '', 'https': ''}, Array_HTTP_Filter = [], Array_Switch = [], Array_Thread_Args = [], Dict_Switch = {}, Dict_Threads = {}, Counter_Connections = 0, Switch_Internet_Connection = False, Screen_Dir = "", driver_options = None):
    global Switch_nmap

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

    # Webdriver_Options
    if (args.scan_site_screenshot != False):
        Array_Selenium = ['--start_maximized','--no-sandbox','--remote-debugging-port=19222','--ignore-certificate-errors','--test-type','--log-level=3','--hide-scrollbars','--enable-javascript']
        if (args.debug != True): Array_Selenium.append('--headless')

        if ("ttl" in getoutput('ping -c 2 8.8.8.8')):
            Switch_Internet_Connection = True
        driver_options = Options()
        for _ in Array_Selenium: driver_options.add_argument(_)
        if (args.custom_chromium_path != None): driver_options.binary_location = args.custom_chromium_path
        else:
            if (osname != 'nt'): driver_options.binary_location = "/usr/bin/chromium"
        if (osname == 'nt'): environ["CHROME_DRIVER_PATH"] = join(dirname(realpath(__file__)), "Resources/Webdriver/chromedriver.exe")
        else: environ["CHROME_DRIVER_PATH"] = join(dirname(realpath(__file__)), "Resources/Webdriver/chromedriver")
        Screen_Dir = join(Location, 'Screenshots')
        try: makedirs(Screen_Dir)
        except FileExistsError: pass

    # Template_Filtering
    if (args.read_config_http_header != None): Array_Header, Array_HTTP_Filter = Standard.Read_File_Special(join(dirname(realpath(__file__)), "Templates/http_header.txt"))
    if (args.read_config_http_header_api != None): Array_Header, Array_HTTP_Filter = Standard.Read_File_Special(join(dirname(realpath(__file__)), "Templates/http_header_api.txt"))
    if (args.read_config_cookie_security_flags != None): Array_Security_Flags = Standard.Read_File(join(dirname(realpath(__file__)), "Templates/http_cookie_security.txt"))
    if (args.read_config_ssh_ciphers != None): Array_SSH_Algorithms = Standard.Read_File(join(dirname(realpath(__file__)), "Templates/ssh_ciphers.txt"))
    if (args.read_config_ssl_ciphers != None): Array_TLS_Algorithms = Standard.Read_File(join(dirname(realpath(__file__)), "Templates/ssl_ciphers.txt"))

    # Proxy_Settings
    if (args.add_http_proxy != None): Dict_Proxies['http'] = args.add_http_proxy
    if (args.add_https_proxy != None): Dict_Proxies['https'] = args.add_https_proxy

    # Scanning_Options
    if (args.scan_all == False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
        from Resources.Header_Files.ArgParser_Intro import Argument_Parser
        Argument_Parser("\n\n\t\t\t\t\tThe scanning method is missing!\n\t\t\t    For more information use the parameter -h or --help.\n"), exit()
    elif (args.scan_all != False and args.scan_site_screenshot == False and args.scan_site_ssl == False and args.scan_site_header == False and args.scan_site_fuzzing == False and args.scan_ssh == False and args.scan_site_screenshot_recursive == False and args.scan_security_flags == False):
        Array_Switch.append(driver_options),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True),Array_Switch.append(True)
    elif (args.scan_all == False):
        try:
            if (args.scan_site_screenshot != False): Array_Switch.append(driver_options)
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
        except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

    # Program_Start
    Standard.Initialien(args.debug)
    setdefaulttimeout(args.timeout)
    Counter_Bar = float(100/len(Array_Targets))
    if __name__ == '__main__':
        with Progress(*progress_columns) as progress:
            queue = Queue()
            queue.put(Dict_Result)
            task_Scan = progress.add_task("[cyan]Scanning for vulnerabilities...", total=len(Array_Targets))
            task_Processes = progress.add_task("[cyan]Waiting for the results...", total=1, start=False)
            task_Filter = progress.add_task("[cyan]Filtering the results...", total=100, start=False)
            for Target in array(Array_Targets):
                Array_Thread_Args.append(Target), Array_Thread_Args.append(args.timeout), Array_Thread_Args.append(queue)
                for _ in Array_Switch: Array_Thread_Args.append(_)
                Array_Thread_Args.append(Screen_Dir), Array_Thread_Args.append(Switch_Internet_Connection), Array_Thread_Args.append(args.screenshot_wait), Array_Thread_Args.append(args.webdriver_wait)
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
                                        Logs.Write_Log(Target, "")
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
            progress.start_task(task_Processes)
            if (len(Dict_Threads) > 0): progress.update(task_Processes, total=len(Dict_Threads))
            while (len(Dict_Threads) > 0):
                try:
                    for Thread_ID in Dict_Threads:
                        if (Thread_ID not in str(active_children())):
                            Dict_Threads.pop(Thread_ID, None)
                            progress.update(task_Processes, advance=0.75)
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
                progress.update(task_Processes, advance=0.75)
                progress.update(task_Filter, advance=0.5)
                sleep(0.01)

    if (args.scan_site_screenshot != False):
#        Web.Screenshot_Filter(Screen_Dir)
        if (len(listdir(Screen_Dir)) > 0):
            for _ in listdir(Screen_Dir): Array_Output.append(join(Screen_Dir, _))

    # Output_End
    if (Array_Output != []):
        Standard.Stdout_Output(Colors.CYAN+"\n\nYour Scan was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
        for _ in Array_Output:
            Standard.Stdout_Output(Colors.ORANGE+f'   - {_}\n'+Colors.RESET, 0.01)
    else: Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your connection or target file and try it again.'+Colors.RESET, 0.01)

# Main
if __name__ == '__main__':
    try: main(Date, args)
    except KeyboardInterrupt: exit()
