#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

# Libraries
from Resources.Header_Files.Threads import *

if (osname == 'nt'):
    system('')
else:
    system(f'sudo python3 {join(dirname(realpath(__file__)), "Resources/Start_Files/start.sh")} {args}')
