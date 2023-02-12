#!/bin/sh
# Rainer Christian Bjoern Herold

source venv/bin/activate
sudo python3 ../main.py "$@"
deactivate
