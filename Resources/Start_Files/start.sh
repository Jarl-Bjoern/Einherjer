#!/bin/bash
# Rainer Christian Bjoern Herold
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
FULL_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-13}
echo $FULL_PATH
source venv/bin/activate
sudo python3 "../main.py" "$@"
deactivate
