#!/bin/bash
# Rainer Christian Bjoern Herold

# Variables
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-16}
BASE_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-23}

echo $SCRIPT_PATH
echo $TEMP_PATH
exit

python3 -m virtualenv $BASE_PATH/venv
source $BASE_PATH/venv/bin/activate
pip3 install -r Setup/requirements.txt
deactivate

pip3 install -r Setup/requirements.txt
