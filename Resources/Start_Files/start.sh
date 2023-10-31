#!/bin/bash
# Rainer Christian Bjoern Herold

# Variables
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-13}
BASE_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-23}

# Color
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RED='\033[0;31m'
ORANGE='\033[1;33m'
NOCOLOR='\033[0m'

# Main
if [[ -d "$BASE_PATH/venv" ]]; then
        source "$BASE_PATH/"venv/bin/activate

        # Check_Proxy_File
        if [[ -f "/tmp/einherjer_proxy.ini" ]]; then
                Proxy_Mode=$(cat "/tmp/einherjer_proxy.ini")
                if [[ "$Proxy_Mode" == "proxychains" ]]; then
                        sudo proxychains python3 "$SCRIPT_PATH/main.py" "$@"
                elif [[ "$Proxy_Mode" == "proxychains4" ]]; then
                        sudo proxychains4 python3 "$SCRIPT_PATH/main.py" "$@"
                fi
                rm -f "/tmp/einherjer_proxy.ini"
        else
                sudo python3 "$SCRIPT_PATH/main.py" "$@"
        fi

        deactivate
else
        echo -e "\n${RED}Please use a virtual python environment!${NOCOLOR}\n\nInstruction:\n${CYAN}-------------------------------------\n${ORANGE}sudo virtualenv $BASE_PATH/venv\nsource $BASE_PATH/venv/bin/activate\nsudo pip3 install -r Setup/requirements.txt\ndeactivate${NOCOLOR}"
fi
