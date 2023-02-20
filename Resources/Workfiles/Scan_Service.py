#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Rainer Christian Bjoern Herold

def Port_Scan(addr, port):
    socket_defaulttimeout(1)
    with (socket(AF_INET, SOCK_STREAM)) as s:
        result = s.connect_ex((addr, port))

    return port

def Banner_Grabbing(addr, port):
    socket_defaulttimeout(1)

    with socket(AF_INET, SOCK_STREAM) as s:
        s.connect((addr, port))
        try:
           return s.recv(1024).decode()
        except TimeoutError:
           return "It was not possible to collect any kind of data"
