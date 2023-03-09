#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Define_Module_Path
from os.path import dirname, join, realpath
from sys import path as SYSTEM_PATH
SYSTEM_PATH.append(dirname(realpath(__file__)).split("Resources")[0])

# Libraries
from Resources.Header_Files.Threads import *
from Resources.Workfiles.Scan_Screen import Web
from Resources.Filter.Methods import Filter

# Main_Function
def main(Date, Program_Mode, args, Array_Output = []):
    def Brute_Force_Mode(Date, Output_location, args, Array_Output = []):
        #Standard.Initialien(args.debug)
        from Resources.Header_Files.ArgParser_Brute_Intro import Argument_Parser
        Argument_Parser("\n\n\t\t\tThis section is UNDER CONSTRUCTION!\n\n"), exit()

        return Array_Output

    def Filter_Mode(Date, Output_location, args, Array_Output = []):
        # Filtering_Options
        if (args.nmap_files_location == None and
            args.screenshot_location == None and
            args.hostname_template_file == None and
            args.hostname_target_file == None):
                from Resources.Header_Files.ArgParser_Filter_Intro import Argument_Parser
                Argument_Parser("\n\n\t\t\tThe program cannot be started without filter methods!\n\t\t\t For more information use the parameter -h or --help.\n"), exit() 
        else:
            # Program_Start
            Standard.Initialien(args.debug)

            if (args.nmap_files_location != None):
                Array_Output = Filter.SSH_Nmap(args.nmap_files_location, Output_location)
            if (args.screenshot_location != None):
                Array_Output = Filter.Screenshot_Frame(args.screenshot_location, args.screenshot_frame_thickness)
            if ((args.hostname_template_file != None and args.hostname_target_file == None) or
                (args.hostname_template_file == None and args.hostname_target_file != None)):
                    from Resources.Header_Files.ArgParser_Filter_Intro import Argument_Parser
                    Argument_Parser("\n\n\t\t\tThe program cannot be started if only one hostname filtering parameter is specified!\n\t\t\t\t\tFor more information use the parameter -h or --help.\n"), exit() 
            elif (args.hostname_template_file != None and args.hostname_target_file != None):
                Array_Output = Filter.Hostname_Filter(args.hostname_template_file, args.hostname_target_file, Output_location)

        return Array_Output

    def Scanning_Mode(Date, args, Dict_Result = {'Certificate': {}, 'Fuzzing': {}, 'Header': {}, 'HTTP_Methods': {}, 'Information': {}, 'Security_Flag': {}, 'SSH': {}, 'SSL': {}}, Dict_Proxies = {'http': '', 'https': ''}, Array_HTTP_Filter = [], Array_Thread_Args = [], Dict_Threads = {}, Counter_Connections = 0, Switch_Internet_Connection = False, Screen_Dir = "", driver_options = None):
        Dict_Switch = {
            'scan_certificate': False,
            'scan_dns': False,
            'scan_fuzzing': False,
            'scan_header': False,
            'scan_http_methods': False,
            'scan_security_flags': False,
            'scan_screenshot': None,
            'scan_screenshot_recursive': False,
            'scan_snmp': False,
            'scan_smtp': False,
            'scan_ssh': False,
            'scan_ssl': False
        }

        # Target_Options
        if (args.target == None and args.import_list == None):
            from Resources.Header_Files.ArgParser_Scan_Intro import Argument_Parser
            Argument_Parser("\n\n\t\t\t   The program cannot be started without targets!\n\t\t\tFor more information use the parameter -h or --help.\n"), exit()
        elif (args.target == None and args.import_list != None):
            try: Array_Targets = Standard.Read_Targets_v4(args.import_list)
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
            if (osname == 'nt'): environ["CHROME_DRIVER_PATH"] = join(dirname(realpath(__file__)), "Webdriver/chromedriver.exe")
            else: environ["CHROME_DRIVER_PATH"] = join(dirname(realpath(__file__)), "Webdriver/chromedriver")
            Screen_Dir = join(Location, 'Screenshots')
            try: makedirs(Screen_Dir)
            except FileExistsError: pass

        # Proxy_Settings
        if (args.add_http_proxy != None): Dict_Proxies['http'] = args.add_http_proxy
        if (args.add_https_proxy != None): Dict_Proxies['https'] = args.add_https_proxy

        # Scanning_Options
        if (args.scan_all == False and
            args.scan_site_screenshot == False and
            args.scan_site_http_methods == False and
            args.scan_site_certificate == False and
            args.scan_site_ssl == False and
            args.scan_site_header == False and
            args.scan_site_fuzzing == False and
            args.scan_ssh == False and
            args.scan_site_screenshot_recursive == False and
            args.scan_security_flags == False):
                    from Resources.Header_Files.ArgParser_Intro import Argument_Parser
                    Argument_Parser("\n\n\t\t\t\t\tThe scanning method is missing!\n\t\t\t    For more information use the parameter -h or --help.\n"), exit()
        elif (args.scan_all != False and
              args.scan_site_screenshot == False and
              args.scan_site_http_methods == False and
              args.scan_site_certificate == False and
              args.scan_site_ssl == False and
              args.scan_site_header == False and
              args.scan_site_fuzzing == False and
              args.scan_ssh == False and
              args.scan_site_screenshot_recursive == False and
              args.scan_security_flags == False):
                    Dict_Switch = {
                        'scan_certificate': True,
                        'scan_dns': True,
                        'scan_fuzzing': True,
                        'scan_header': True,
                        'scan_http_methods': True,
                        'scan_security_flags': True,
                        'scan_screenshot': driver_options,
                        'scan_screenshot_recursive': True,
                        'scan_snmp': True,
                        'scan_smtp': True,
                        'scan_ssh': True,
                        'scan_ssl': True
                    }
        elif (args.scan_all == False):
            if (args.scan_site_certificate != False):           Dict_Switch['scan_certificate'] = True
            if (args.scan_site_fuzzing != False):               Dict_Switch['scan_fuzzing'] = True
            if (args.scan_site_header != False):                Dict_Switch['scan_header'] = True
            if (args.scan_site_http_methods != False):          Dict_Switch['scan_http_methods'] = True
            if (args.scan_security_flags != False):             Dict_Switch['scan_security_flags'] = True
            if (args.scan_site_screenshot != False):            Dict_Switch['scan_screenshot'] = driver_options
            if (args.scan_site_screenshot_recursive != False):  Dict_Switch['scan_screenshot_recursive'] = True
            if (args.scan_ssh != False):                        Dict_Switch['scan_ssh'] = True
            if (args.scan_site_ssl != False):                   Dict_Switch['scan_ssl'] = True

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
                    Array_Thread_Args = [Target, args.timeout, queue, Dict_Switch, Screen_Dir, Switch_Internet_Connection, args.screenshot_wait, args.webdriver_wait]
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
                                progress.update(task_Processes, advance=0.75)
                                Dict_Threads.pop(Thread_ID, None)
                            else:
                                if ((time() - Dict_Threads[Thread_ID][1]) > 900):
                                    progress.update(task_Processes, advance=0.75)
                                    Dict_Threads[Thread_ID][0].terminate()
                                    Dict_Threads.pop(Thread_ID, None)
                    except RuntimeError: pass
                    sleep(0.75)
                Dict_Result = queue.get()

                # Format_Filtering
                if ("csv" in args.format):
                    from Resources.Format.CSV import CSV_Table
                    Array_Output = CSV_Table(Dict_Result, Location)
                elif ("docx" in args.format):
                    from Resources.Format.Word import Word_Table
                    Array_Output = Word_Table(Dict_Result, Location)
                elif ("html" in args.format):
                    from Resources.Format.HTML import HTML_Table
                    Array_Output = HTML_Table(Dict_Result, Location)
                elif ("json" in args.format):
                    from Resources.Format.JSON import JSON_Table
                    Array_Output = JSON_Table(Dict_Result, Location)
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
                elif ("yaml" in args.format):
                    from Resources.Format.YAML import YAML_Table
                    #Array_Output = YAML_Table(Dict_Result, Location)
                else: Error_Message("Your Decision was not acceptable!")

                # Progress_End
                progress.start_task(task_Filter)
                while not progress.finished:
                    progress.update(task_Scan, advance=Counter_Bar)
                    progress.update(task_Processes, advance=0.75)
                    progress.update(task_Filter, advance=0.5)
                    sleep(0.01)

        if (args.scan_site_screenshot != False):
            Filter_Output_File = Web.Screenshot_Filter(Screen_Dir, Location)
            if (len(listdir(Screen_Dir)) > 0):
                for _ in listdir(Screen_Dir): Array_Output.append(join(Screen_Dir, _))
            if (Filter_Output_File != ""):
                Array_Output.append(Filter_Output_File)

        return Array_Output

    # Output_Location
    if (args.output_location != None):
        if ('.' in args.output_location or './' in args.output_location):
            if ('./' in args.output_location): Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location[2:]}/{Date}"))
            else: Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location}/{Date}"))
        elif ('.' not in args.output_location and '/' not in args.output_location): Location = Standard.Create_Location_Dir(join(getcwd(), f"{args.output_location}/{Date}"))
        elif ('/' in args.output_location and not '.' in args.output_location): Location = Standard.Create_Location_Dir(f"{args.output_location}/{Date}")
    else: Location = Standard.Create_Location_Dir(join(dirname(realpath(__file__)).replace('/Resources','/einherjer_output'), Date))

    # Program_Mode
    if (Program_Mode == "Scanning_Mode"):
        Array_Output = Scanning_Mode(Date, args)
    elif (Program_Mode == "Filter_Mode"):
        Array_Output = Filter_Mode(Date, Location, args)
    elif (Program_Mode == "Brute_Force_Mode"):
        Array_Output = Brute_Force_Mode(Date, Location, args)

    # Output_End
    if (Array_Output != []):
        if (Program_Mode == "Scanning_Mode"):
            Standard.Stdout_Output(Colors.CYAN+"\n\nYour Scan was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
            if (args.scan_site_screenshot != False or args.scan_site_screenshot_recursive != False):
                if (len(listdir(join(Location, 'Screenshots'))) == 0):
                    Chromium_Version = getoutput('apt-cache policy chromium').splitlines()[1][1:].split(':')[1][1:]
                    if (osname != 'nt'):
                        if (Chromedriver_Version in Chromium_Version):
                            Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\nChromium: "+Colors.RED+f"{Chromium_Version}\n"+Colors.ORANGE+"Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}"+Colors.RESET, 0.01)
                        else:
                            Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\nChromium: "+Colors.RED+f"{Chromium_Version}\n"+Colors.ORANGE+"Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}"+Colors.RESET, 0.01)
                    else:
                        Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\nChromedriver Version: "+Colors.RED+f"{Chromedriver_Version}"+Colors.RESET, 0.01)
        elif (Program_Mode == "Filter_Mode"):
            Standard.Stdout_Output(Colors.CYAN+"\n\nThe filter process was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
        for _ in Array_Output:
            Standard.Stdout_Output(Colors.ORANGE+f'   - {_}\n'+Colors.RESET, 0.01)
    else:
        if (Program_Mode == "Scanning_Mode"):
            Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your connection or target file and try it again.'+Colors.RESET, 0.01)
            if (args.scan_site_screenshot != False or args.scan_site_screenshot_recursive != False):
                if (len(listdir(join(Location, 'Screenshots'))) == 0):
                    Chromium_Version = getoutput('apt-cache policy chromium').splitlines()[1][1:].split(':')[1][1:]
                    if (osname != 'nt'):
                        if (Chromedriver_Version in Chromium_Version):
                            Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\nChromium: "+Colors.RED+f"{Chromium_Version}\n"+Colors.ORANGE+"Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}"+Colors.RESET, 0.01)
                        else:
                            Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\nChromium: "+Colors.RED+f"{Chromium_Version}\n"+Colors.ORANGE+"Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}"+Colors.RESET, 0.01)
                    else:
                        Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\nChromedriver Version: "+Colors.RED+f"{Chromedriver_Version}"+Colors.RESET, 0.01)
        elif (Program_Mode == "Filter_Mode"):
            Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your locations or target files and try it again.'+Colors.RESET, 0.01)

# Main
if __name__ == '__main__':
    try: main(Date, Program_Mode, args)
    except KeyboardInterrupt: exit()
