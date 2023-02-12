#!/bin/bash
# Rainer Christian Bjoern Herold
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-13}
BASE_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-23}
echo $BASE_PATH
source venv/bin/activate
#sudo python3 "$SCRIPT_PATH/main.py" "$@"
deactivate
