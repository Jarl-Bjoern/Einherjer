#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Hostname_Filter(Template_File, Input_File, Output_Location, Template_Array = [], Target_Array = [], Dict_DNS = {}, Array_Temp = []):
    try:
        def Read_File_Template(File_Name):
            with open(File_Name) as f:
                return f.read().splitlines()

        Target_Array = Read_File_Template(Input_File)
        for _ in Read_File_Template(Template_File):
            if (':' in _):   x = _.split(':')
            elif ('=' in _): x = _.split('=')
            Dict_DNS[str(x[0])] = str(x[1])

        with open(join(Output_Location, 'hostnames.txt'), 'w') as f:
            with open(join(Output_Location, 'affected_systems.txt'), 'w') as af:
                for _ in Target_Array:
                    # Split_Port
                    if (':' in _):
                        if (_.count(':') == 2):
                            Temp = _.split('//')[1]
                            Target, Port = Temp.split(':')
                        elif (_.count(':') == 1):
                            Target, Port = _.split(':')
                    else:
                        Target, Port = _, ""

                    # Split_Whitespace
                    if (' ' in Target):
                        for Space in Target.split(' '):
                            if (len(Space) > 0):
                                Target = Space

                    if (Target in Dict_DNS):
                        for Temp in Dict_DNS:
                            if (Target in Temp or Target == Temp):
                                f.write(f'{Dict_DNS[Temp]}\n')
                                if (Port != '' and Port != ' '):
                                    af.write(f'{Target}:{Port} ({Dict_DNS[Temp]})\n')
                                else:
                                    af.write(f'{Target} ({Dict_DNS[Temp]})\n')
                                break
                    else:
                        f.write('-\n')
                        if (Port != '' and Port != ' '):
                            af.write(f'{Target}:{Port} (-)\n')
                        else:
                            af.write(f'{Target} (-)\n')
        Array_Temp.append(join(Output_Location, 'hostnames.txt')), Array_Temp.append(join(Output_Location, 'affected_systems.txt'))
    except FileNotFoundError:
        pass

    return Array_Temp
