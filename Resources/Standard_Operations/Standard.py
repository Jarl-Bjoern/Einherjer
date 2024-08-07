#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Colors                  import Colors
from ..Header_Files.Variables import *
from .Logs                    import *

class Standard:
    def Stdout_Output(Text_Array, Output_Seconds):
        for char in Text_Array:
            stdout.write(char)
            stdout.flush()
            sleep(Output_Seconds)

    def Create_Underline(Text, max_numbers, word = ""):
        for _ in range(0, max_numbers):
            word += Text
        return word

    def Print_Header():
        Header = """
💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀
💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t           """+Colors.UNDERLINE+"Einherjer"+Colors.RESET+ """\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t\t  """+Colors.ORANGE+"Version "+Colors.BLUE+"0.8"+Colors.RESET+"""\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t"""+Colors.CYAN+"Rainer Christian Bjoern Herold"+Colors.RESET+"""\t\t\t\t\t\t  💀
💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀\n\n
"""
        if (osname == "nt"): system('cls')
        else:                system('clear')
        print(Header)

    def Initialien(debug_parameter):
        if (debug_parameter == False):
            if (osname == 'nt'): system('cls')
            else:                system('clear')
        else: system('')
        Header = """
💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀
💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t           """+Colors.UNDERLINE+"Einherjer"+Colors.RESET+ """\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t\t  """+Colors.ORANGE+"Version "+Colors.BLUE+"0.8"+Colors.RESET+"""\t\t\t\t\t\t\t  💀
💀\t\t\t\t\t"""+Colors.CYAN+"Rainer Christian Bjoern Herold"+Colors.RESET+"""\t\t\t\t\t\t  💀
💀\t\t\t\t\t\t\t\t\t\t\t\t\t\t  💀
💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀\n\n
"""
        Standard.Stdout_Output(Header, 0.004)

    def Create_Location_Dir(output_location_dir):
        try:
            makedirs(output_location_dir)
            return output_location_dir
        except:
            makedirs(join(dirname(realpath(__file__)), output_location_dir))
            print (f"Your location can't be found or was not allowed!\n\nYour new location was set to {join(dirname(realpath(__file__)), output_location_dir)}")
            return join(dirname(realpath(__file__)), output_location_dir)

    def List_Directory_Recursive(file_path):
        for root, _, files in walk(file_path, topdown=False):
            return files

    def Read_File(file_path):
        try:
            with open(file_path, 'r') as f:
                return f.read().splitlines()
        except IsADirectoryError:
            print ("It's not possible to use a directory as a file."), exit()

    def Read_Color(template_file):
        if (exists(template_file)):
            R,G,B = 0,0,0
            for _ in Standard.Read_File(template_file):
                if   ('R:' in _): R = int(_.split('R:')[1])
                elif ('G:' in _): G = int(_.split('G:')[1])
                elif ('B:' in _): B = int(_.split('B:')[1])
            return (R,G,B)
        else: Logs.Error_Message(f'The requested File {template_file} does not exist!')

    def Read_Template(template_file):
        if (exists(template_file)):
            Temp_Array = []
            for _ in Standard.Read_File(template_file):
                if ('#' not in _): Temp_Array.append(_)
            if (len(Temp_Array) > 0):
                Temp_Array.sort()
            return Temp_Array
        else: Logs.Error_Message(f'The requested File {template_file} does not exist!')

    def Read_YAML_Config_File(template_file, section_name, mode):
        def Special_Filter(YAML_Array):
            Dict_Temp = {}
            for _ in YAML_Array:
                if (":" in _):
                    Temp = _.split(':')
                    try:
                        if (';' in Temp[1]):
                            Array_Value_Temp = Temp[1].split(';')
                            if (Temp[0] not in Dict_Temp):
                                Dict_Temp[Temp[0]] = Temp[1].split(';')
                        elif (',' in Temp[1]):
                            Array_Value_Temp = Temp[1].split(',')
                            if (Temp[0] not in Dict_Temp):
                                Dict_Temp[Temp[0]] = Temp[1].split(',')
                        else:
                            if (Temp[0] not in Dict_Temp):
                                Dict_Temp[Temp[0]] = Temp[1]
                    except IndexError:
                        if (Temp[0] not in Dict_Temp):
                            Dict_Temp[Temp[0]] = Temp[1]
    
            return Dict_Temp

        if (exists(template_file)):
            Temp_Array, Temp_Array_Ciphers, Temp_Array_Community = [],[],[]
            with open(template_file, 'r') as f:
                yaml_in_template = yaml_safe_load(f)

            # Color
            if (mode == 'color'):
                R,G,B = 0,0,0
                for _ in yaml_in_template[section_name]:
                    if   ('R:' in _): R = int(_.split('R:')[1])
                    elif ('G:' in _): G = int(_.split('G:')[1])
                    elif ('B:' in _): B = int(_.split('B:')[1])
                return (R,G,B)

            # HTTP_Config
            elif (mode == 'http'):
                for j in yaml_in_template[section_name]:
                    if (j not in Temp_Array):
                        Temp_Array.append(j)
    
                if (len(Temp_Array) > 0):
                    Temp_Array.sort()
                return Temp_Array

            # JSON
            elif (mode == 'json'):
                if (section_name == 'http_custom_header'):
                    return yaml_in_template[section_name]
                elif (section_name == 'http_header' or section_name == 'http_header_api'):
                    return Special_Filter(yaml_in_template[section_name])

            # SSH_Filter
            elif (mode == 'ssh'):
                for i in yaml_in_template:
                    for j in yaml_in_template[i]:
                        if (j not in Temp_Array_Ciphers):
                            Temp_Array_Ciphers.append(j)

                if (len(Temp_Array_Ciphers) > 0):    Temp_Array_Ciphers.sort()
                return Temp_Array_Ciphers

            # SNMP
            elif (mode == 'snmp'):
                for _ in yaml_in_template['oid']:
                    if (_ not in Temp_Array):
                        Temp_Array.append(_)
                for _ in yaml_in_template['community_strings']:
                    if (_ not in Temp_Array_Community):
                        Temp_Array_Community.append(_)

                return Temp_Array, Temp_Array_Community

            # TLS_Filter
            elif (mode == 'tls'):
                pass

        else: Logs.Error_Message(f'The requested File {template_file} does not exist!')  

    def Read_YAML_Template(template_file):
        if (exists(template_file)):
            Temp_Array_Names, Temp_Array_Ciphers = []
            with open(template_file, 'r') as f:
                yaml_in_template = yaml_safe_load(f)

            for i in yaml_in_template:
                for j in yaml_in_template[i]:
                    if (j not in Temp_Array):
                        Temp_Array.append(j)

            if (len(Temp_Array) > 0):
                Temp_Array.sort()
            return Temp_Array
        else: Logs.Error_Message(f'The requested File {template_file} does not exist!') 

    def Read_File_Special(file_path, Dict_Temp = {}):
        for _ in Standard.Read_Template(file_path):
            if (":" in _):
                Temp = _.split(':')
                try:
                    if (';' in Temp[1]):
                        Array_Value_Temp = Temp[1].split(';')
                        if (Temp[0] not in Dict_Temp):
                            Dict_Temp[Temp[0]] = Temp[1].split(';')
                    elif (',' in Temp[1]):
                        Array_Value_Temp = Temp[1].split(',')
                        if (Temp[0] not in Dict_Temp):
                            Dict_Temp[Temp[0]] = Temp[1].split(',')
                    else:
                        if (Temp[0] not in Dict_Temp):
                            Dict_Temp[Temp[0]] = Temp[1]
                except IndexError:
                    if (Temp[0] not in Dict_Temp):
                        Dict_Temp[Temp[0]] = Temp[1]

        return Dict_Temp

    def Read_JSON_File(file_path, dict_temp = {}):
        with open(file_path, 'r', encoding='utf-8') as jsonFile:
            try:
                dict_temp = json_loads(jsonFile)
            except TypeError:
                try:
                    dict_temp = json_load(jsonFile)
                except TypeError:
                    dict_temp = json_dumps(jsonFile)
            except JSONDecodeError:
                exit(Colors.RED+"There was a problem with the encoding in the file."+Colors.RESET)
        jsonFile.close()

        return dict_temp

    def Read_Targets_XML(file_path, Array_Out = [], Array_SSL_Out = [], Array_Template = []):
        if (exists(join(dirname(realpath(__file__)).split("Resources/Standard_Operations")[0], "scan.state"))):
            Array_Template = Standard.Read_File(join(dirname(realpath(__file__)).split("Resources/Standard_Operations")[0], "scan.state"))

        Protocol, Address, Port, Skip_Attributes = "","","",False
        try:
            for event, elem in ET.iterparse(file_path, events=("end",)):
                if (event == "end"):
                    if (elem.tag == 'address'):
                        if (Skip_Attributes != True):
                            if (elem.attrib['addrtype'] == 'ipv4'):
                                Address = elem.attrib['addr']
                    elif (elem.tag == 'state'):
                        if (elem.attrib['state'] != "open"):
                            Skip_Attributes = True
                    elif (elem.tag == 'service'):
                        if (Skip_Attributes != True):
                            if ('http' in elem.attrib['name'] and not 'ssl' in elem.attrib['name'] and not 'https' in elem.attrib['name']):
                                Protocol = "http"
                            elif ('https' in elem.attrib['name'] or ('http' in elem.attrib['name'] and 'ssl' in elem.attrib['name'])):
                                Protocol = "https"
                            elif ('ftp' in elem.attrib['name']):
                                Protocol = "ftp"
                    elif (elem.tag == 'port'):
                        if (Skip_Attributes != True):
                            Port = elem.attrib['portid']
                        if (Protocol != "" and Address != "" and Port != ""):
                            Full_Target = f'{Protocol}://{Address}:{Port}'
                            Protocol, Address, Port = "","",""

                            if ('ssl://' in Full_Target):
                                if (Full_Target not in Array_SSL_Out):
                                    if (Full_Target not in Array_Template):
                                        Array_SSL_Out.append(Full_Target)
                            elif ('https://' in Full_Target):
                                if (Full_Target not in Array_SSL_Out):
                                    if (Full_Target not in Array_Template):
                                        Array_SSL_Out.append(Full_Target)
                                        Array_Out.append(Full_Target)
                            else:
                                if (Full_Target not in Array_Out):
                                    if (Full_Target not in Array_Template):
                                        Array_Out.append(Full_Target)
                            Full_Target = ""

                        Skip_Attributes = False
        except ParseError:
            print ("It's seems that the xml file"+Colors.RED+f" {file_path} "+Colors.RESET+"is empty."), exit()

        return Array_Out, Array_SSL_Out

    def Read_Targets_v4(file_path, Array_Out = [], Array_SSL_Out = [], Array_Template = []):
        if (exists(join(dirname(realpath(__file__)).split("Resources/Standard_Operations")[0], "scan.state"))):
            Check = input(Colors.ORANGE+f'\nIt was possible to find a existing state file '+Colors.RED+f'{join(dirname(realpath(__file__)).split("Resources/Standard_Operations")[0], "scan.state")}'+Colors.ORANGE+'.\n\nShould it be loaded? (Y/n)\n\n'+Colors.RESET+'Decision: ')
            if (Check == "Y" or Check == "y"):
                print (Colors.ORANGE+"\n\nThe load of the state file was successful."+Colors.RESET), sleep(3)
                Array_Template = Standard.Read_File(join(dirname(realpath(__file__)).split("Resources/Standard_Operations")[0], "scan.state"))
            elif (Check == "N" or Check == "n"):
                print (Colors.ORANGE+"\n\nThe state file was ignored and will be removed."+Colors.RESET), sleep(3)

        for Target in Standard.Read_File(file_path):
            if (Target.count('/') > 2):
                Counter, Position = 0, ''
                for _ in range(0, len(Target)):
                    if (Counter != 3):
                        if (Target[_] == '/'):
                            Position = _
                            Counter += 1
                    else: break
                if ('ssl://' in Target):
                    if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_SSL_Out):
                        if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_Template):
                            Array_SSL_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                            Array_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                elif ('https://' in Target):
                    if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_SSL_Out):
                        if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_Template):
                            Array_SSL_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                            Array_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                else:
                    if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_Out):
                        if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_Template):
                            Array_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
            else:
                if ('ssl://' in Target):
                    if (Target not in Array_SSL_Out):
                        if (Target not in Array_Template):
                            Array_SSL_Out.append(Target)
                elif ('https://' in Target):
                    if (Target not in Array_SSL_Out):
                        if (Target not in Array_Template):
                            Array_SSL_Out.append(Target)
                            Array_Out.append(Target)
                else:
                    if (Target not in Array_Out):
                        if (Target not in Array_Template):
                            Array_Out.append(Target)

        return Array_Out, Array_SSL_Out

    def Remove_From_Filtered_File(filter_file_name, delete_entry):
        if (exists(filter_file_name)):
            Array_Temp = Standard.Read_File(filter_file_name)
            for _ in Array_Temp:
                if (delete_entry in _):
                    Array_Temp.remove(_)
                    with open(filter_file_name, 'w') as f:
                        for _ in Array_Temp:
                            f.write(f'{_}\n')
        else: Logs.Error_Message(f'The requested File {filter_file_name} does not exist!')

    def Remove_Empty_Filter_File(filter_file_name):
        try:
            if ('affected' in filter_file_name):
                if (len(Standard.Read_File(filter_file_name)) == 0):
                    remove(filter_file_name)
            else:
                if (len(Standard.Read_File(filter_file_name)) < 2):
                    remove(filter_file_name)
        except FileNotFoundError:
            pass

    def Try_Remove_File(x):
        while True:
            try:
                remove(x)
                break
            except FileNotFoundError:
                break
            except PermissionError: Logs.Error_Message(f"The file {x} is already open!\nPlease close it and wait five seconds.")
            sleep(5)

    def Write_Output_File(Output_File_Name, Text, Location, Array_Check = []):
        if (exists(join(Location, Output_File_Name))):
            Write_Mode = 'a'
        else:
            Write_Mode = 'w'

        if (exists(join(Location, Output_File_Name))):
            with open(join(Location, Output_File_Name), 'r') as f:
                Array_Check = f.read().splitlines()

        with open(join(Location, Output_File_Name), Write_Mode) as f:
            if (Text not in Array_Check):
                f.write(f'{Text}\n')

    def Write_State_File(Array_State, Location):
        with open(join(Location, 'scan.state'), 'w') as f:
            for _ in Array_State:
                f.write(f'{_}\n')
