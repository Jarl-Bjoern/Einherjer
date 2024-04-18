#!/bin/bash
# Rainer Christian Bjoern Herold

# Variables
TEMP_PATH=$(readlink -f -- "$0")
SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
SCRIPT_PATH=${TEMP_PATH::-${#SCRIPT_NAME}-6}

# Color
BLUE='\033[0;34m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
ORANGE='\033[1;33m'
NORANGE='\033[0;33m'
PURPLE='\033[0;35m'
UNDERLINE='\033[0;4m'
NOCOLOR='\033[0m'

# Header
clear
echo "💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀"
echo -e "💀\t\t\t\t\t\t\t\t💀"
echo -e "💀\t\t     ${UNDERLINE}Einherjer - Installer${NOCOLOR}\t\t\t💀"
echo -e "💀\t\t\t  ${NORANGE}Version ${CYAN}0.1${NOCOLOR}   \t\t\t💀"
echo -e "💀\t\t${CYAN}Rainer Christian Bjoern Herold${NOCOLOR}\t\t\t💀"
echo -e "💀\t\t\t\t\t\t\t\t💀"
echo -e "💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀💀\n\n"
sleep 2

# Install_Missing_APT_Packages
echo -e "Installing the missing ${RED}apt packages${NOCOLOR}"
echo -e "${CYAN}-----------------------------------------------------------------${NOCOLOR}\n"
sudo apt install -y libcurl4-openssl-dev chromium chromium-driver python3-pip python3-venv
echo -e "\n\nThe ${RED}apt packages${NOCOLOR} was installed!\n"
echo -e "${CYAN}-----------------------------------------------------------------${NOCOLOR}\n\n\n"

# Virtual_Environment
echo -e "Creating the ${RED}virtual environment${NOCOLOR}"
echo -e "${CYAN}-----------------------------------------------------------------${NOCOLOR}\n"
python3 -m virtualenv "$SCRIPT_PATH/venv"
source "$SCRIPT_PATH/venv/bin/activate"
pip3 install -r "$SCRIPT_PATH/Setup/requirements.txt"
deactivate
echo -e "\n\nThe ${RED}virtual environment${NOCOLOR} was created!"
echo -e "${CYAN}-----------------------------------------------------------------${NOCOLOR}\n\n\n"

# Install_Missing_Global_Packages
echo -e "Installing the ${RED}global pip packages${NOCOLOR}"
echo -e "${CYAN}-----------------------------------------------------------------${NOCOLOR}\n"
for LINE in $(cat "$SCRIPT_PATH/Setup/requirements.txt");
do
  pip3 install $LINE || return 0
done
echo -e "\n\nThe ${RED}pip packages${NOCOLOR} was installed!"
echo -e "${CYAN}-----------------------------------------------------------------${NOCOLOR}\n\n\n"
