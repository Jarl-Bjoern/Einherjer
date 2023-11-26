#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Get_Hash(Hash_Location, output_location, Array_Hashes = []):
    # Read_Files
    if (type(Hash_Location) == str):
        with open(Hash_Location, 'r', encoding='utf-8') as f:
            Array_Hashes = f.read().splitlines()
    elif (type(Hash_Location) == list)
        for _ in listdir(Hash_Location):
            Array_Temp = []
            with open(join(Hash_Location, _), 'r', encoding='utf-8') as f:
                Array_Temp = f.read().splitlines()
            for _ in array(Array_Temp):
                if (_ not in Array_Hashes):
                    Array_Hashes.append(_)
    
    # Filter_Process
    for _ in Array_Hashes:
        print (Hash)
        print (hash_detect(Hash))
