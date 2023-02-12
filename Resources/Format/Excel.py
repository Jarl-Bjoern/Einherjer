#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Header_Files.Variables import *

def Excel_Table(Dict_Result, location, Array_Header_Letter = ['A','B','C','D','E','F','G','H'], Array_Information_Letter = ['A','B','C','D'], Array_Flag_Letter = ['A','B','C','D','E'], Array_Files = []):
    try:
        from xlsxwriter import Workbook
        from pandas import ExcelFile, DataFrame, read_excel
    except ModuleNotFoundError as e: Module_Error(f"The module was not found\n\n{e}\n\nPlease confirm with the button 'Return'")

    def Excel_Analysis(Dict_DNS = {}):
        x1 = ExcelFile(join(location, 'Findings.xlsx'))

        with open(join(location, 'DNS_Vorlage.txt')) as f:
            Text = f.readlines()

        for i in Text:
            Address = i.split(' (')
            if (Address[0] not in Dict_DNS):
                try:
                    if ("\n" in Address[1]): Dict_DNS[Address[0]] = Address[1][:-2]
                    else: Dict_DNS[Address[0]] = Address[1][:-1]
                except IndexError: pass

        for i in x1.sheet_names:
            if (i == 'Open Ports'):
                data = read_excel(join(location, 'Findings.xlsx'), sheet_name=i)

        with open(join(location, 'filtered_DNS_hosts.txt'), 'w') as f:
            for index, row in DataFrame(data, columns=['Host']).iterrows():
                if (" " in row['Host']): Temp = row['Host'].replace(" ","")
                else: Temp = row['Host']

                if (Temp in Dict_DNS): f.write(f"{Temp} ({Dict_DNS[Temp]})\n")
                else: f.write((f"{Temp} ()\n"))

    def Generate_Excel(Excel_File):
        workbook = Workbook(Excel_File)
        worksheet = workbook.add_worksheet('HTTP-Security-Header')
        worksheet.set_column('A:A', 45), worksheet.set_column('B:H', 3)

        # Design
        bold_text = workbook.add_format({'bold': True})
        rotate_text = workbook.add_format({'bold': True})
        rotate_text.set_rotation(-90)
        center_text = workbook.add_format()
        center_text.set_center_across()
        th_cell_format = workbook.add_format()
        th_cell_format.set_bg_color('Black'), th_cell_format.set_fg_color('White')
        t2_cell_format = workbook.add_format()
        t2_cell_format.set_bg_color('Gray'), th_cell_format.set_fg_color('Black')

        # HTTP_Header
        m = 1
        worksheet.write(f'A1', 'URL', bold_text)
        worksheet.write(f'B1', 'DNS', bold_text)
        for Header in Array_Header:
            worksheet.write(f'{Array_Header_Letter[m]}1', Header, rotate_text)
            m += 1

        m = 2
        for Target in Dict_Result['Header']:
            Letter = 0
            worksheet.write(f'{Array_Header_Letter[Letter]}{m}', Target)
            for Result_Left, Result_Right in Dict_Result['Header'][Target].items():
                Letter += 1
                if ((Result_Left == "X-XSS-PROTECTION") and (Result_Right == "1" or (Result_Right == "1; MODE=BLOCK"))): Result_Right = "FEHLT"
                elif (Result_Left == "X-CONTENT-TYPE-OPTIONS" and Result_Right != "NOSNIFF"): Result_Right = "FEHLT"
                elif (Result_Left == "X-FRAME-OPTIONS" and Result_Right != "DENY"): Result_Right = "FEHLT"
                elif (Result_Left == "DNS" and Result_Right == ""): Result_Right = "FEHLT"

                if (Result_Left != "DNS" and Result_Right != "FEHLT"): worksheet.write(f'{Array_Header_Letter[Letter]}{m}', "✓", center_text)
                elif (Result_Left == "DNS" and Result_Right != "FEHLT"): worksheet.write(f'{Array_Header_Letter[Letter]}{m}', f"{Result_Right}", center_text)
                elif (Result_Left == "DNS" and Result_Right == "FEHLT"): worksheet.write(f'{Array_Header_Letter[Letter]}{m}', "-", center_text)
                else: worksheet.write(f'{Array_Header_Letter[Letter]}{m}', "X", center_text)
            m += 1
        workbook.close()

    Array_Files.append(join(location, 'Findings.xlsx'))
    if (not exists(join(location, 'Findings.xlsx'))): Generate_Excel(join(location, 'Findings.xlsx'))
    else:
        Question = input(f"The file already exists\n\n{e}\n\nDo you want to override it? (Y/N)")
        if (Question == 'Y' or Question == 'y'):
            Try_Remove_File(join(location, 'Findings.xlsx')), Generate_Excel(join(location, 'Findings.xlsx'))
        elif (Question == 'N' or Question == 'n'):
            n = 0
            for _, _, files in walk('.', topdown=False):
                for file in array(files):
                    if (file.endswith('.xlsx') and 'Findings' in file): n += 1
            Generate_Excel(join(location, f'Findings_{n}.xlsx'))
        else: Error_Message("Your decision is not acceptable.","")

    return Array_Files
