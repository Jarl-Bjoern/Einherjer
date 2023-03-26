#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Define_Module_Path
from os.path import dirname, join, realpath
from sys import path as SYSTEM_PATH
SYSTEM_PATH.append(dirname(realpath(__file__)).split("Resources")[0])

# Libraries
from Resources.Header_Files.Threads_Scanning import *
from Resources.Header_Files.Threads_SSL import *
from Resources.Workfiles.Scan_Screen import Web
from Resources.Filter.Methods import Filter

# Main_Function
def main(Date, Program_Mode, args, Array_Output = [], Switch_Screenshots = False):
    # Get_Password
    if (Program_Mode == "Scanning_Mode"):
        if (args.zip_file != False):
            if (args.zip_file_password != False):
                print (Colors.ORANGE+'\nPlease specify your ZipFile Password.'+Colors.RESET)
                Password_Input = getpass('\n\nPassword: ')
                if (len(Password_Input) < 16):
                    exit(Colors.RED+"\n\nPlease use a minimum password length of 16 digits!"+Colors.RESET)
            else:
                Password_Creator = SystemRandom()
                Password_Input = ""
                for _ in range(0, 33):
                    Password_Input += chr(Password_Creator.randrange(33,126))
                del Password_Creator

    # Functions
    def Message_Chromium(Check_Dir):
        if (len(listdir(Check_Dir)) == 0):
            Chromium_Version = getoutput('apt-cache policy chromium').splitlines()[1][1:].split(':')[1][1:]
            if (osname != 'nt'):
                if (Chromedriver_Version[:-4] in Chromium_Version):
                    Standard.Stdout_Output(Colors.ORANGE+"\n\n\tUnfortunately, it was not possible to establish a connection via the webdriver, possibly the target\n\t\tsystem has a WAF in use, as the versions of the Chromedriver and Chromium match."+"\n\n\t\t\t\t    Chromium:             "+Colors.RED+f"{Chromium_Version}\n\t\t\t\t"+Colors.ORANGE+"    Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}\n"+Colors.RESET, 0.01)
                else:
                    Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\n\t\t\t\t    Chromium:             "+Colors.RED+f"{Chromium_Version}\n\t\t\t\t"+Colors.ORANGE+"    Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}\n"+Colors.RESET, 0.01)
            else:
                Standard.Stdout_Output(Colors.ORANGE+"\n\n\t\t    It was not possible to use the current chromium and webdriver version.\n\n\t\t\t\t    Chromedriver Version: "+Colors.RED+f"{Chromedriver_Version}\n"+Colors.RESET, 0.01)

    def Brute_Force_Mode(Date, Output_location, args, Array_Output = [], Switch_Screenshots = False):
        Dict_Switch = {
            'brute_dns':                  False,
            'brute_fuzzing':              False,
            'brute_screenshot_recursive': False,
            'brute_snmp':                 False,
            'brute_smtp':                 False
        }

        #Standard.Initialien(args.debug)
        from Resources.Header_Files.ArgParser_Brute_Intro import Argument_Parser
        Argument_Parser("\n\n\t\t\tThis section is UNDER CONSTRUCTION!\n\n"), exit()

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

        return Array_Output, Switch_Screenshots

    def Filter_Mode(Date, Output_location, args, Array_Output = []):
        # Filtering_Options
        if (args.nmap_files_location    == None and
            args.screenshot_location    == None and
            args.hostname_template_file == None and
            args.hostname_target_file   == None):
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

    def Scanning_Mode(Date, args, Array_Thread_Args = [], Dict_Threads = {}, Dict_Proxies = {'http': "",'https': ""}, Counter_Connections = 0, Switch_Internet_Connection = False, Screen_Dir = "", driver_options = None, Switch_Screenshots = False, Array_Targets = [], Array_SSL_Targets = []):
        # Dict_Declaration
        Dict_Result = {
            'Certificate':               {},
            'DNS':                       {},
            'Header':                    {},
            'HTTP_Methods':              {},
            'Information':               {},
            'Security_Flag':             {},
            'SSH':                       {},
            'SSL':                       {}
        }

        Dict_Auth = {
            'user':                      '',
            'password':                  '',
            'pkcs12_cert':               '',
            'pkcs12_password':           ''
        }

        Dict_Switch = {
            'scan_certificate':          False,
            'scan_dns':                  False,
            'scan_header':               False,
            'scan_host_name':            False,
            'scan_http_methods':         False,
            'scan_security_flags':       False,
            'scan_screenshot':           None,
            'scan_snmp':                 False,
            'scan_smtp':                 False,
            'scan_ssh':                  False,
            'scan_ssl':                  False
        }

        # Target_Options
        if (args.target == None and args.import_list == None and args.add_nmap_xml_result == None):
            from Resources.Header_Files.ArgParser_Scan_Intro import Argument_Parser
            Argument_Parser("\n\n\t\t\t   The program cannot be started without targets!\n\t\t\tFor more information use the parameter -h or --help.\n"), exit()
        elif (args.target == None and (args.import_list != None or args.add_nmap_xml_result != None)):
            if (args.import_list != None):
                try:
                    Array_Targets, Array_SSL_Targets = Standard.Read_Targets_v4(args.import_list)
                except FileNotFoundError as e:
                    Logs.Error_Message(f"Your targetlist can't be found!\n\n{args.import_list}")

            if (args.add_nmap_xml_result != None):
                try:
                    Array_Temp_Zero, Array_SSL_Zero = Standard.Read_Targets_XML(args.add_nmap_xml_result)
                    if (len(Array_Targets) > 0):
                        for _ in array(Array_Temp_Zero):
                            if (_ not in Array_Targets):
                                Array_Targets.append(_)
                    else:
                        Array_Targets = Array_Temp_Zero

                    if (len(Array_SSL_Targets) > 0):
                        for _ in array(Array_SSL_Zero):
                            if (_ not in Array_SSL_Zero):
                                Array_SSL_Targets.append(_)
                    else:
                        Array_SSL_Targets = Array_SSL_Zero

                except FileNotFoundError as e:
                    Logs.Error_Message(f"Your targetlist can't be found!\n\n{args.add_nmap_xml_result}")
        else:
            if (len(args.target) > 1):
                Array_Targets, Array_SSL_Targets = [], []
                for _ in args.target:
                    if (',' in _):
                        if ('/' in _[:-1]):
                            for IP in IPv4Network(_):
                                if (IP not in Array_Targets):
                                    Array_Targets.append(IP)
                        else:
                            Array_Targets.append(_[:-1])
                    else:
                        if ('/' in _):
                            for IP in IPv4Network(_):
                                if (IP not in Array_Targets):
                                    Array_Targets.append(IP)
                        else:
                            Array_Targets.append(_)
            else:
                if (',' in args.target[0]):
                    Temp_Split = args.target[0].split(',')
                    for _ in Temp_Split:
                        if (_ != ''):
                            if ('https://' in Temp_Split or 'ssl://' in Temp_Split):
                                Array_SSL_Targets.append(_)
                            Array_Targets.append(_)
                else:
                    if ('https://' in args.target[0] or 'ssl://' in args.target[0]):
                        Array_SSL_Targets = [args.target[0]]                    
                    Array_Targets = [args.target[0]]
        if (args.random_order == True):
            try: from random import shuffle
            except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")
            shuffle(Array_Targets)
            del shuffle

        # Proxy_Settings
        if (args.add_http_proxy  != None):                   Dict_Proxies['http']         = args.add_http_proxy
        if (args.add_https_proxy != None):                   Dict_Proxies['https']        = args.add_https_proxy

        # Webdriver_Options
        if (args.scan_site_screenshot != False):
            # Pre_Settings
            Array_Selenium = [
                '--start_maximized',
                '--no-sandbox',
                '--remote-debugging-port=19222',
                '--ignore-certificate-errors',
                '--test-type',
                '--log-level=3',
                '--hide-scrollbars',
                '--enable-javascript'
            ]

            # Debugging_Options
            if (args.debug != True): Array_Selenium.append('--headless')

            # Internet_Connection
            if ("ttl" in getoutput('ping -c 2 8.8.8.8')):
                Switch_Internet_Connection = True

            # Driver_Settings
            driver_options = Options()
            for _ in Array_Selenium:                driver_options.add_argument(_)

            # Proxy_Settings
            if (Dict_Proxies['http'] != ''):        driver_options.add_argument(f'--proxy-server=http://{Dict_Proxies["http"]}')
            if (Dict_Proxies['https'] != ''):       driver_options.add_argument(f'--proxy-server=https://{Dict_Proxies["https"]}')
            if (args.add_socks_proxy != None):      driver_options.add_argument(f'--proxy-server=socks5://{args.add_socks_proxy}')

            # Custom_Chromium
            if (args.custom_chromium_path != None): driver_options.binary_location = args.custom_chromium_path
            else:
                if (osname != 'nt'): driver_options.binary_location = "/usr/bin/chromium"

            # Chromedriver_Settings
            if (osname == 'nt'): environ["CHROME_DRIVER_PATH"] = join(dirname(realpath(__file__)), "Webdriver/chromedriver.exe")
            else: environ["CHROME_DRIVER_PATH"] = join(dirname(realpath(__file__)), "Webdriver/chromedriver")

            # Screenshot_Path
            Screen_Dir = join(Location, 'Screenshots')
            try: makedirs(Screen_Dir)
            except FileExistsError: pass

        # Auth_Settings
        if (args.add_basic_authentication_user     != None):       Dict_Auth['user']            = args.add_basic_authentication_user
        if (args.add_basic_authentication_password != None):       Dict_Auth['password']        = args.add_basic_authentication_password
        if (args.add_pkcs12_cert                   != None):       Dict_Auth['pkcs12_cert']     = args.add_pkcs12_cert
        if (args.add_pkcs12_cert_password          != None):       Dict_Auth['pkcs12_password'] = args.add_pkcs12_cert_password

        # Scanning_Options
        if (args.scan_all                 == False and
            args.scan_host_name           == False and
            args.scan_security_flags      == False and
            args.scan_site_certificate    == False and
            args.scan_site_header         == False and
            args.scan_site_http_methods   == False and
            args.scan_site_screenshot     == False and
            args.scan_site_ssl            == False and
            args.scan_ssh                 == False):
                    from Resources.Header_Files.ArgParser_Intro import Argument_Parser
                    Argument_Parser("\n\n\t\t\t\t\tThe scanning method is missing!\n\t\t\t    For more information use the parameter -h or --help.\n"), exit()
        elif (args.scan_all               != False and
            args.scan_host_name           == False and
            args.scan_security_flags      == False and
            args.scan_site_certificate    == False and
            args.scan_site_header         == False and
            args.scan_site_http_methods   == False and
            args.scan_site_screenshot     == False and
            args.scan_site_ssl            == False and
            args.scan_ssh                 == False):
                    Dict_Switch = {
                        'scan_certificate':           True,
                        'scan_dns':                   True,
                        'scan_header':                True,
                        'scan_host_name':             True,
                        'scan_http_methods':          True,
                        'scan_security_flags':        True,
                        'scan_screenshot':            driver_options,
                        'scan_snmp':                  True,
                        'scan_smtp':                  True,
                        'scan_ssh':                   True,
                        'scan_ssl':                   True
                    }
        elif (args.scan_all == False):
            if (args.scan_host_name         != False):          Dict_Switch['scan_host_name']            = True
            if (args.scan_security_flags    != False):          Dict_Switch['scan_security_flags']       = True
            if (args.scan_site_certificate  != False):          Dict_Switch['scan_certificate']          = True
            if (args.scan_site_header       != False):          Dict_Switch['scan_header']               = True
            if (args.scan_site_http_methods != False):          Dict_Switch['scan_http_methods']         = True
            if (args.scan_site_screenshot   != False):          Dict_Switch['scan_screenshot']           = driver_options
            if (args.scan_site_ssl          != False):          Dict_Switch['scan_ssl']                  = True
            if (args.scan_ssh               != False):          Dict_Switch['scan_ssh']                  = True

        # Program_Start
        Standard.Initialien(args.debug)
        setdefaulttimeout(args.timeout)
        Counter_Bar = float(100/(len(Array_Targets)+len(Array_SSL_Targets)))
        if __name__ == '__main__':
            with Progress(*progress_columns) as progress:
                queue = Queue()
                queue.put(Dict_Result)
                task_Scan      = progress.add_task("[cyan]Scanning for vulnerabilities...", total=(len(Array_Targets)+len(Array_SSL_Targets)))
                task_Processes = progress.add_task("[cyan]Waiting for the results...", total=1, start=False)
                task_Filter    = progress.add_task("[cyan]Filtering the results...", total=1, start=False)

                # Normal_Targets
                if (Dict_Switch['scan_dns']            != False or
                    Dict_Switch['scan_certificate']    != False or
                    Dict_Switch['scan_host_name']      != False or
                    Dict_Switch['scan_header']         != False or
                    Dict_Switch['scan_http_methods']   != False or
                    Dict_Switch['scan_screenshot']     != None or
                    Dict_Switch['scan_snmp']           != False or
                    Dict_Switch['scan_smtp']           != False or
                    Dict_Switch['scan_security_flags'] != False):
                        for Target in array(Array_Targets):
                            Array_Thread_Args = [
                                Target,
                                args.timeout,
                                queue,
                                Dict_Switch,
                                Screen_Dir,
                                Switch_Internet_Connection,
                                args.screenshot_wait,
                                args.webdriver_wait,
                                args.async_ssl_timeout,
                                Dict_Proxies,
                                Dict_Auth,
                                args.format,
                                Location,
                                args.allow_redirects
                            ]

                            if (Counter_Connections == args.max_connections):
                                while (len(Dict_Threads) > 0):
                                    for Thread_ID in array(list(Dict_Threads)):
                                        if (Thread_ID not in str(active_children())):
                                            Dict_Threads.pop(Thread_ID, None)
                                            Counter_Connections -= 1
                                        else:
                                            if ((int(time()) - Dict_Threads[Thread_ID][1]) > args.thread_timeout):
                                                Dict_Threads[Thread_ID][0].terminate()
                                                Logs.Write_Log(Target, "", join(Location, 'Logs'))
                                                Dict_Threads.pop(Thread_ID, None)
                                                Counter_Connections -= 1
                                    sleep(2.25)

                            p = Process(target=Thread_Scanning_Start, args=Array_Thread_Args, daemon=True)
                            p.start()
                            Counter_Connections += 1
                            if (p.name not in Dict_Threads):
                                Dict_Threads[p.name] = [p, int(time()), Target]
                                sleep(args.sleep)
                            progress.update(task_Scan, advance=Counter_Bar)

                # SSL_Targets
                if (Dict_Switch['scan_ssl'] == True):
                    Temp_SSL_Array, Counter_SSL_Targets, Max_Len_SSL_Targets = [], 0, len(Array_SSL_Targets)
                    for Target in array(Array_SSL_Targets):
                        if (Counter_SSL_Targets != args.max_ssl_targets and Counter_SSL_Targets != Max_Len_SSL_Targets):
                            Temp_SSL_Array.append(Target)
                            Counter_SSL_Targets += 1

                        if (Counter_SSL_Targets == args.max_ssl_targets or Counter_SSL_Targets == Max_Len_SSL_Targets):
                            Array_Thread_Args = [
                                Temp_SSL_Array,
                                args.timeout,
                                queue,
                                Dict_Switch,
                                args.async_ssl_timeout,
                                Dict_Proxies,
                                Dict_Auth,
                                args.format,
                                Location,
#                                args.allow_redirects
                            ]

                            if (Counter_Connections == args.max_connections):
                                while (len(Dict_Threads) > 0):
                                    for Thread_ID in array(list(Dict_Threads)):
                                        if (Thread_ID not in str(active_children())):
                                            Dict_Threads.pop(Thread_ID, None)
                                            Counter_Connections -= 1
                                        else:
                                            if ((int(time()) - Dict_Threads[Thread_ID][1]) > args.thread_timeout):
                                                Dict_Threads[Thread_ID][0].terminate()
                                                Logs.Write_Log(Target, "", join(Location, 'Logs'))
                                                Dict_Threads.pop(Thread_ID, None)
                                                Counter_Connections -= 1
                                    sleep(2.25)

                            p = Process(target=Thread_SSL_Start, args=Array_Thread_Args, daemon=True)
                            p.start()
                            Counter_Connections += 1
                            if (p.name not in Dict_Threads):
                                Dict_Threads[p.name] = [p, int(time()), Target]
                                sleep(args.sleep)
                            progress.update(task_Scan, advance=Counter_Bar)
                            Max_Len_SSL_Targets =- Counter_SSL_Targets
                            Temp_SSL_Array,Counter_SSL_Targets = [], 0

                # Terminate_Timeout_Processes
                progress.start_task(task_Processes)
                if (len(Dict_Threads) > 0): progress.update(task_Processes, total=len(Dict_Threads))
                Start_Kill, End_Kill = int(time()), int(time())
                while ((End_Kill - Start_Kill) < 3600):
                    while (len(Dict_Threads) > 0):
                        for Thread_ID in array(list(Dict_Threads)):
                            if (Thread_ID not in str(active_children())):
                                progress.update(task_Processes, advance=0.75)
                                Dict_Threads.pop(Thread_ID, None)
                            else:
                                if ((int(time()) - Dict_Threads[Thread_ID][1]) > 900):
                                    progress.update(task_Processes, advance=0.75)
                                    Dict_Threads[Thread_ID][0].terminate()
                                    Dict_Threads.pop(Thread_ID, None)
                        End_Kill = int(time())
                        sleep(0.75)
                    else:
                        break
                else:
                    while (len(Dict_Threads) > 0):
                        for Thread_ID in array(list(Dict_Threads)):
                            if (Thread_ID in str(active_children())):
                                progress.update(task_Processes, advance=0.75)
                                Dict_Threads[Thread_ID][0].terminate()
                                Dict_Threads.pop(Thread_ID, None)
                            else:
                                progress.update(task_Processes, advance=0.75)
                                Dict_Threads.pop(Thread_ID, None)
                        sleep(0.25)

                # Get_Results
                Dict_Result = queue.get()

                # Get_All_Files
                progress.start_task(task_Filter)
                Temp_Path_Length = len(Standard.List_Directory_Recursive(Location))

                if (Temp_Path_Length > 0):
                    Counter_Bar_Filter = 100/Temp_Path_Length
                    progress.update(task_Filter, total=Temp_Path_Length)
                    for root, _, files in walk(Location, topdown=False):
                        for file in files:
                            if (args.zip_file != False):
                                if (join(Location, 'Einherjer_Output.zip') not in Array_Output):
                                    Array_Output.append(join(Location, 'Einherjer_Output.zip'))

                                with AESZipFile(join(Location, 'Einherjer_Output.zip'), 'a', compression=ZIP_LZMA, encryption=WZ_AES) as zF:
                                    zF.setpassword(bytes(Password_Input, encoding='utf-8'))
                                    if ('Screenshots' in root):
                                        zF.write(join(root, file), join('Screenshots', file))
                                    elif ('Logs' in root):
                                        zF.write(join(root, file), join('Logs', file))
                                    else:
                                        zF.write(join(root, file), file)

                                if ('Screenshots' in root):
                                    Switch_Screenshots = True
                                remove(join(root, file))
                            else:
                                if (join(root, file) not in Array_Output):
                                    Array_Output.append(join(root, file))
                            progress.update(task_Filter, advance=Counter_Bar_Filter)

                    if (args.zip_file != False):
                        kp    = create_database(
                            join(Location, 'zip.kdbx'),
                            password='Einherjer',
                            keyfile=None,
                            transformed_key=None
                        )
                        group = kp.add_group(kp.root_group, 'ZipFile')
                        entry = kp.add_entry(group, 'ZipFile', '-', Password_Input)
                        kp.save()
                else:
                    Counter_Bar_Filter = 0.75

                # Progress_End
                while not progress.finished:
                    progress.update(task_Scan, advance=Counter_Bar)
                    progress.update(task_Processes, advance=0.75)
                    progress.update(task_Filter, advance=Counter_Bar_Filter)
                    sleep(0.01)

        if (args.scan_site_screenshot != False):
            Filter_Output_File = Web.Screenshot_Filter(Screen_Dir, Location)
            if (Filter_Output_File != ""):
                Array_Output.append(Filter_Output_File)

        if (args.zip_file != False):
            for _ in listdir(Location):
                if (isdir(join(Location, _))):
                    rmdir(join(Location, _))

        return Array_Output, Switch_Screenshots

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
        Array_Output, Switch_Screenshots = Scanning_Mode(Date, args)
    elif (Program_Mode == "Filter_Mode"):
        Array_Output = Filter_Mode(Date, Location, args)
    elif (Program_Mode == "Brute_Force_Mode"):
        Array_Output, Switch_Screenshots = Brute_Force_Mode(Date, Location, args)

    # Output_End
    if (Array_Output != []):
        if (Program_Mode == "Scanning_Mode"):
            if (args.scan_site_screenshot != False and Switch_Screenshots == False):
                Message_Chromium(join(Location, 'Screenshots'))
            Standard.Stdout_Output(Colors.CYAN+"\n\nYour Scan was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
        elif (Program_Mode == "Brute_Force_Mode"):
            if (args.brute_screenshot_recursive != False and Switch_Screenshots == False):
                Message_Chromium(join(Location, 'Screenshots'))
            Standard.Stdout_Output(Colors.CYAN+"\n\nYour Scan was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)
        elif (Program_Mode == "Filter_Mode"):
            Standard.Stdout_Output(Colors.CYAN+"\n\nThe filter process was successful and the result will be found at the following location:\n"+Colors.RESET, 0.01)

        if (type(Array_Output) == list):
            for _ in Array_Output:
                Standard.Stdout_Output(Colors.ORANGE+f'   - {_}\n'+Colors.RESET, 0.01)
        elif (type(Array_Output) == str):
            Standard.Stdout_Output(Colors.ORANGE+f'   - {Array_Output}\n'+Colors.RESET, 0.01)

    else:
        if (Program_Mode == "Scanning_Mode"):
            if (args.scan_site_screenshot != False and Switch_Screenshots == False):
                Message_Chromium(join(Location, 'Screenshots'))
            Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your connection or target file and try it again.'+Colors.RESET, 0.01)
        elif (Program_Mode == "Brute_Force_Mode"):
            if (args.brute_screenshot_recursive != False and Switch_Screenshots == False):
                Message_Chromium(join(Location, 'Screenshots'))
            Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your connection or target file and try it again.'+Colors.RESET, 0.01)
        elif (Program_Mode == "Filter_Mode"):
            Standard.Stdout_Output(Colors.ORANGE+f'\n\t\t\t\tIt was not possible to collect any kind of data!\n\n\t\t\t     Check your locations or target files and try it again.'+Colors.RESET, 0.01)

# Main
if __name__ == '__main__':
    try: main(Date, Program_Mode, args)
    except KeyboardInterrupt: exit()
