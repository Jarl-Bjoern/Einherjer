#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from .Colors import Colors
from ..Header_Files.Variables import *
from .Logs import *

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

    def Initialien(debug_parameter):
        if (debug_parameter == False):
            if (osname == 'nt'): system('cls')
            else: system('clear')
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

    def Read_File(file_path):
        with open(file_path, 'r') as f:
            return f.read().splitlines()

    def Read_Template(template_file):
        if (exists(template_file)):
            Temp_Array = []
            for _ in Standard.Read_File(template_file):
                if ('#' not in _): Temp_Array.append(_)
            return Temp_Array
        else: Logs.Error_Message(f'The requested File {template_file} does not exist!')

    def Read_File_Special(file_path, Dict_Temp = {}, Array_Temp_Zero = [], Array_Temp_One = []):
        for _ in Standard.Read_Template(file_path):
            if (":" in _):
                Temp = _.split(':')
                try:
                    if (';' in Temp[1]):
                        Array_Value_Temp = Temp[1].split(';')
                        if (Temp[0] not in Array_Temp_Zero):
                            Dict_Temp[Temp[0]] = Temp[1].split(';')
                            Array_Temp_Zero.append(Temp[0])
                            Array_Temp_One += Array_Value_Temp
                    elif (',' in Temp[1]):
                        Array_Value_Temp = Temp[1].split(',')
                        if (Temp[0] not in Array_Temp_Zero):
                            Dict_Temp[Temp[0]] = Temp[1].split(',')
                            Array_Temp_Zero.append(Temp[0])
                            Array_Temp_One += Array_Value_Temp                       
                    else:
                        if (Temp[0] not in Array_Temp_Zero):
                            Dict_Temp[Temp[0]] = Temp[1]
                            Array_Temp_Zero.append(Temp[0])
                            Array_Temp_One.append(Temp[1])
                except IndexError:
                    if (Temp[0] not in Array_Temp_Zero):
                        Dict_Temp[Temp[0]] = Temp[1]
                        Array_Temp_Zero.append(Temp[0])
                        Array_Temp_One.append(Temp[1])

        return Array_Temp_Zero, Array_Temp_One

    def Read_Targets_XML(file_path, Array_Out = [], Array_SSL_Out = []):
        Protocol, Address, Port, Skip_Attributes = "","","",False
        for event, elem in ET.iterparse(file_path, events=("end",)):
            if (event == "end"):
                if (elem.tag == 'address'):
                    if (Skip_Attributes != True):
                        Address = elem.attrib['addr']
                elif (elem.tag == 'state'):
                    if (elem.attrib['state'] != "open"):
                        Skip_Attributes = True
                elif (elem.tag == 'service'):
                    if (Skip_Attributes != True):
                        Protocol = elem.attrib['name']
                elif (elem.tag == 'port'):
                    if (Skip_Attributes != True):
                        Port = elem.attrib['portid']
                    if (Protocol != "" and Address != "" and Port != ""):
                        Full_Target = f'{Protocol}://{Address}:{Port}'
                        Protocol, Address, Port = "","",""

                        if ('ssl://' in Full_Target):
                            if (Full_Target not in Array_SSL_Out):
                                Array_SSL_Out.append(Full_Target)
                        elif ('https://' in Full_Target):
                            if (Full_Target not in Array_SSL_Out):
                                Array_SSL_Out.append(Full_Target)
                                Array_Out.append(Full_Target)
                        else:
                            if (Full_Target not in Array_Out):
                                Array_Out.append(Full_Target)
                        Full_Target = ""

                    Skip_Attributes = False

        return Array_Out, Array_SSL_Out

    def Read_Targets_v4(file_path, Array_Out = [], Array_SSL_Out = []):
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
                        Array_SSL_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                elif ('https://' in Target):
                    if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_SSL_Out):
                        Array_SSL_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                        Array_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
                else:
                    if (f'{Target[:Position]}/{Target[Position+1:]}' not in Array_Out):
                        Array_Out.append(f'{Target[:Position]}/{Target[Position+1:]}')
            else:
                if ('ssl://' in Target):
                    if (Target not in Array_SSL_Out):
                        Array_SSL_Out.append(Target)
                elif ('https://' in Target):
                    if (Target not in Array_SSL_Out):
                        Array_SSL_Out.append(Target)
                        Array_Out.append(Target)
                else:
                    if (Target not in Array_Out):
                        Array_Out.append(Target)

        return Array_Out, Array_SSL_Out

    def Try_Remove_File(x):
        while True:
            try:
                remove(x)
                break
            except FileNotFoundError:
                break
            except PermissionError: Logs.Error_Message(f"The file {x} is already open!\nPlease close it and wait five seconds.")
            sleep(5)
