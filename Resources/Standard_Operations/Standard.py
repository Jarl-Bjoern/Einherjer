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

    def Read_File_Special(file_path, Array_Temp_Zero = [], Array_Temp_One = []):
        for _ in Standard.Read_Template(file_path):
            if (":" in _):
                Temp = _.split(':')
                if (Temp[0] not in Array_Temp_Zero): Array_Temp_Zero.append(Temp[0]), Array_Temp_One.append(Temp[1])
        return Array_Temp_Zero, Array_Temp_One
    
    def Read_Targets_v4(file_path, Array_Out = []):
        for Target in Standard.Read_File(file_path):
            if (Target.count('/') > 1):
                print (Target)
                Counter, Position = 0, ''
                for _ in range(0, len(Target)):
                    if (Counter != 3):
                        if (Target[_] == '/'):
                            Position = _
                            Counter += 1
                    else: break
                Array_Out.append(f'{Target[:Position]}/{html_encode(Target[Position+1:])}')
            else: Array_Out.append(Target)
        print (Array_Out)
        return Array_Out

    def Try_Remove_File(x):
        while True:
            try:
                remove(x)
                break
            except FileNotFoundError:
                break
            except PermissionError: Logs.Error_Message(f"The file {x} is already open!\nPlease close it and wait five seconds.")
            sleep(5)
