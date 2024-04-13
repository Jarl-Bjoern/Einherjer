#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Screenshot_Frame(Screen_Dir, Screenshot_Thickness, Screen_Type, Array_Temp = []):
    def Copy_To_Backup_Screenshot(scan_path, picture, screen_dir):
        if (len(listdir(scan_path)) == 0):
            copy2(join(screen_dir, picture), scan_path)
        else:
            for Check in listdir(scan_path):
                if (Check != picture):
                    copy2(join(screen_dir, picture), scan_path)

    try:
        for Picture in listdir(Screen_Dir):
            if (Picture.lower().endswith('.jpg')  or
                Picture.lower().endswith('.jpeg') or
                Picture.lower().endswith('.bmp')  or
                Picture.lower().endswith('.png')):
                    while True:
                        try:
                            try:
                                makedirs(join(Screen_Dir, 'Einherjer_Screenshot_Backup'))
                                Copy_To_Backup_Screenshot(join(Screen_Dir, 'Einherjer_Screenshot_Backup'), Picture, Screen_Dir)
                            except FileExistsError:
                                Copy_To_Backup_Screenshot(join(Screen_Dir, 'Einherjer_Screenshot_Backup'), Picture, Screen_Dir)
                            break
                        except PermissionError:
                            input (Colors.ORANGE+"\nIt seems that the path"+Colors.RED+f" {Screen_Dir} "+Colors.ORANGE+"is not writeable. Please change the permissions and try it again.\n\nPress "+Colors.CYAN+"'Return'"+Colors.ORANGE+" to continue."+Colors.RESET)
                            Standard.Print_Header()

                    if (Screen_Type == "Drawning"):
                        raw_image              = imread(join(Screen_Dir, Picture))
                        height                 = raw_image.shape[0]
                        width                  = raw_image.shape[1]
                        start_point, end_point = (-1,-1), (width, height)
                        color                  = Screenshot_Color
                        img                    = rectangle(raw_image, start_point, end_point, color, int(Screenshot_Thickness))
                        imwrite(join(Screen_Dir, Picture), img)
                    elif (Screen_Type == "Border"):
                        raw_image              = Image.open(join(Screen_Dir, Picture))
                        manipulated_image      = ImageOps.expand(raw_image, border=1, fill='black')
                        manipulated_image.save(join(Screen_Dir, Picture))
                    Array_Temp.append(join(Screen_Dir, Picture))
    except FileNotFoundError:
        pass

    return Array_Temp
