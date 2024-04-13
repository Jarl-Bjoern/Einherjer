#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Target_Split(input_file, output_location, Array_Temp = []):
    try:
        with open(input_file, 'r') as f:
            Temp_Array = f.read().splitlines()
    except FileNotFoundError:
        pass

    with open(f'{output_location}/Targets_A.txt', 'w') as Target_File_A:
        with open(f'{output_location}/Targets_B.txt', 'w') as Target_File_B:
            Number_Split = int(len(Temp_Array)/2)
            for i in range(0, len(Temp_Array)):
                if (i == Number_Split):
                    for _ in range(Number_Split, len(Temp_Array)):
                        Target_File_B.write(f'{Temp_Array[_]}\n')
                        Array_Temp.append(f'{output_location}/Targets_A.txt')
                    break
                else:
                    Target_File_A.write(f'{Temp_Array[i]}\n')
                    Array_Temp.append(f'{output_location}/Targets_B.txt')

    return Array_Temp
