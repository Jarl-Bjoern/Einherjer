#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from ..Header_Files.Variables import *

def Screenshot_Frame(Screen_Dir, Screenshot_Thickness, Array_Temp = []):
    try:
        for Picture in listdir(Screen_Dir):
            if (Picture.lower().endswith('.jpg')  or
                Picture.lower().endswith('.jpeg') or
                Picture.lower().endswith('.bmp')  or
                Picture.lower().endswith('.png')):
                    try:
                        makedirs(join(Screen_Dir, 'Einherjer_Screenshot_Backup'))
                        copy2(join(Screen_Dir, Picture), join(Screen_Dir, 'Einherjer_Screenshot_Backup'))
                    except PermissionError:
                        input (f"It seems that the path {Screen_Dir} is not writeable. Please change the permissions and try it again.")
                        makedirs(join(Screen_Dir, 'Einherjer_Screenshot_Backup'))
                        copy2(join(Screen_Dir, Picture), join(Screen_Dir, 'Einherjer_Screenshot_Backup'))

                    raw_image              = imread(join(Screen_Dir, Picture))
                    height                 = raw_image.shape[0]
                    width                  = raw_image.shape[1]
                    start_point, end_point = (-1,-1), (width, height)
                    color                  = Screenshot_Color
                    img                    = rectangle(raw_image, start_point, end_point, color, int(Screenshot_Thickness))
                    imwrite(join(Screen_Dir, Picture), img)
                    Array_Temp.append(join(Screen_Dir, Picture))
    except FileNotFoundError:
        pass        

    return Array_Temp
