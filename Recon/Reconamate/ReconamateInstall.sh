#!/bin/bash

# ----------------------------------------------------------------------------
# ---------------------DISCLAIMER:--------------------------------------------
# ----------------------------------------------------------------------------
# ------- Reconamate is intended for ethical purposes only.-------------------
# ------- This script was built to be used during legal-----------------------
# ------- Bug hunting or Penetration testing only.----------------------------
# ------- I take no responsibility for end user abuse of this script.---------
# ------- Please think before you hack. --------------------------------------
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------

# =============================================================================
# ReconamateInstall.sh
# =============================================================================
# A shell script to install all required tools and dependencies for Reconamate.py.
# Designed for Ubuntu/Debian-based systems.
#
# Usage:
#   chmod +x ReconamateInstall.sh
#   ./ReconamateInstall.sh
#
# =============================================================================

# ------------------------------ Functions --------------------------------------

# Function to print colored messages
print_message() {
    COLOR=$1
    MESSAGE=$2
    RESET='\033[0m'
    case $COLOR in
        "green")
            COLOR_CODE='\033[0;32m'
            ;;
        "yellow")
            COLOR_CODE='\033[0;33m'
            ;;
        "red")
            COLOR_CODE='\033[0;31m'
            ;;
        *)
            COLOR_CODE='\033[0m'
            ;;
    esac
    echo -e "${COLOR_CODE}${MESSAGE}${RESET}"
}

# Function to install a package via apt-get
install_apt_package() {
    PACKAGE=$1
    if dpkg -s "$PACKAGE" &> /dev/null; then
        print_message "green" "[+] $PACKAGE is already installed."
    else
        print_message "yellow" "[*] Installing $PACKAGE..."
        sudo apt-get install -y "$PACKAGE"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully installed $PACKAGE."
        else
            print_message "red" "[!] Failed to install $PACKAGE."
        fi
    fi
}

# Function to install a Go-based tool
install_go_tool() {
    TOOL_IMPORT_PATH=$1
    BINARY_NAME=$2
    if command -v "$BINARY_NAME" &> /dev/null; then
        print_message "green" "[+] $BINARY_NAME is already installed."
    else
        print_message "yellow" "[*] Installing $BINARY_NAME..."
        go install "$TOOL_IMPORT_PATH@latest"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully installed $BINARY_NAME."
        else
            print_message "red" "[!] Failed to install $BINARY_NAME."
        fi
    fi
}

# Function to clone a Git repository
clone_repo() {
    REPO_URL=$1
    DEST_DIR=$2
    if [ -d "$DEST_DIR" ]; then
        print_message "green" "[+] Repository $DEST_DIR already exists."
    else
        print_message "yellow" "[*] Cloning repository $REPO_URL..."
        git clone "$REPO_URL" "$DEST_DIR"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully cloned $REPO_URL."
        else
            print_message "red" "[!] Failed to clone $REPO_URL."
        fi
    fi
}

# Function to install Python modules via pip3
install_pip_module() {
    MODULE=$1
    if pip3 show "$MODULE" &> /dev/null; then
        print_message "green" "[+] Python module '$MODULE' is already installed."
    else
        print_message "yellow" "[*] Installing Python module '$MODULE'..."
        pip3 install "$MODULE"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully installed Python module '$MODULE'."
        else
            print_message "red" "[!] Failed to install Python module '$MODULE'."
        fi
    fi
}

# Function to set up Go environment
setup_go() {
    if command -v go &> /dev/null; then
        print_message "green" "[+] Go is already installed."
    else
        print_message "yellow" "[*] Installing Go..."
        wget https://golang.org/dl/go1.20.5.linux-amd64.tar.gz -O go.tar.gz
        sudo tar -C /usr/local -xzf go.tar.gz
        rm go.tar.gz
        echo "export PATH=$PATH:/usr/local/go/bin" >> ~/.bashrc
        export PATH=$PATH:/usr/local/go/bin
        print_message "green" "[+] Go installation completed."
    fi
}

# Function to install MassDNS
install_massdns() {
    if command -v massdns &> /dev/null; then
        print_message "green" "[+] MassDNS is already installed."
    else
        print_message "yellow" "[*] Installing MassDNS..."
        git clone https://github.com/blechschmidt/massdns.git
        cd massdns || exit
        make
        sudo make install
        cd ..
        rm -rf massdns
        if command -v massdns &> /dev/null; then
            print_message "green" "[+] MassDNS installation completed."
        else
            print_message "red" "[!] MassDNS installation failed."
        fi
    fi
}

# Function to install Testssl.sh
install_testssl() {
    if [ -f "/usr/local/bin/testssl.sh" ]; then
        print_message "green" "[+] Testssl.sh is already installed."
    else
        print_message "yellow" "[*] Installing Testssl.sh..."
        git clone https://github.com/drwetter/testssl.sh.git
        sudo ln -s "$(pwd)/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
        chmod +x testssl.sh/testssl.sh
        print_message "green" "[+] Testssl.sh installation completed."
    fi
}

# Function to install EyeWitness
install_eyewitness() {
    if command -v EyeWitness.py &> /dev/null; then
        print_message "green" "[+] EyeWitness is already installed."
    else
        print_message "yellow" "[*] Installing EyeWitness..."
        git clone https://github.com/FortyNorthSecurity/EyeWitness.git
        cd EyeWitness/Python || exit
        pip3 install -r requirements.txt
        sudo ln -s "$(pwd)/EyeWitness.py" /usr/local/bin/eyewitness
        cd ../..
        rm -rf EyeWitness
        if command -v EyeWitness.py &> /dev/null; then
            print_message "green" "[+] EyeWitness installation completed."
        else
            print_message "red" "[!] EyeWitness installation failed."
        fi
    fi
}

# Function to install Aquatone
install_aquatone() {
    if command -v aquatone &> /dev/null; then
        print_message "green" "[+] Aquatone is already installed."
    else
        print_message "yellow" "[*] Installing Aquatone..."
        go install github.com/michenriksen/aquatone@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Aquatone installation completed."
        else
            print_message "red" "[!] Aquatone installation failed."
        fi
    fi
}

# Function to install Subjack
install_subjack() {
    if command -v subjack &> /dev/null; then
        print_message "green" "[+] Subjack is already installed."
    else
        print_message "yellow" "[*] Installing Subjack..."
        go install github.com/haccer/subjack@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Subjack installation completed."
        else
            print_message "red" "[!] Subjack installation failed."
        fi
    fi
}

# Function to install Subfinder
install_subfinder() {
    if command -v subfinder &> /dev/null; then
        print_message "green" "[+] Subfinder is already installed."
    else
        print_message "yellow" "[*] Installing Subfinder..."
        go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Subfinder installation completed."
        else
            print_message "red" "[!] Subfinder installation failed."
        fi
    fi
}

# Function to install FFUF
install_ffuf() {
    if command -v ffuf &> /dev/null; then
        print_message "green" "[+] FFUF is already installed."
    else
        print_message "yellow" "[*] Installing FFUF..."
        go install github.com/ffuf/ffuf@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] FFUF installation completed."
        else
            print_message "red" "[!] FFUF installation failed."
        fi
    fi
}

# Function to download resolvers for MassDNS
install_massdns_resolvers() {
    RESOLVERS_URL="https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt"
    RESOLVERS_FILE="/usr/local/share/massdns/resolvers.txt"
    
    if [ -f "$RESOLVERS_FILE" ]; then
        print_message "green" "[+] MassDNS resolvers already exist."
    else
        print_message "yellow" "[*] Downloading MassDNS resolvers..."
        sudo mkdir -p /usr/local/share/massdns
        sudo wget "$RESOLVERS_URL" -O "$RESOLVERS_FILE"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] MassDNS resolvers downloaded successfully."
        else
            print_message "red" "[!] Failed to download MassDNS resolvers."
        fi
    fi
}

# Function to install Python dependencies for EyeWitness
install_eyewitness_dependencies() {
    if [ -f "EyeWitness/requirements.txt" ]; then
        print_message "green" "[+] EyeWitness Python dependencies already installed."
    else
        print_message "yellow" "[*] Installing EyeWitness Python dependencies..."
        git clone https://github.com/FortyNorthSecurity/EyeWitness.git
        cd EyeWitness/Python || exit
        pip3 install -r requirements.txt
        cd ../..
        rm -rf EyeWitness
        print_message "green" "[+] EyeWitness Python dependencies installed."
    fi
}

# ------------------------------ Main Script -------------------------------------

print_message "yellow" "=============================================="
print_message "yellow" "   Reconamate Installation Script"
print_message "yellow" "=============================================="

# Update package list
print_message "yellow" "[*] Updating package list..."
sudo apt-get update -y
print_message "green" "[+] Package list updated."

# Install essential packages
ESSENTIAL_PACKAGES=("git" "golang" "python3-pip" "build-essential" "curl" "wget" "make")
for PACKAGE in "${ESSENTIAL_PACKAGES[@]}"; do
    install_apt_package "$PACKAGE"
done

# Set up Go environment
setup_go

# Export GOPATH and update PATH
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
echo "export GOPATH=$HOME/go" >> ~/.bashrc
echo "export PATH=\$PATH:/usr/local/go/bin:\$GOPATH/bin" >> ~/.bashrc

# Install Go-based tools
install_subfinder
install_aquatone
install_subjack
install_ffuf

# Install MassDNS
install_massdns

# Install Testssl.sh
install_testssl

# Install EyeWitness
install_eyewitness

# Install additional tools
install_eyewitness_dependencies

# Install Python modules
install_pip_module "shodan"

# Install Subfinder
install_subfinder

# Install Gobuster via apt-get (already handled above)

# Install Certspotter via pip or other methods if necessary
# Since Certspotter is integrated via API calls in the Python script, ensure dependencies are met

# Download resolvers for MassDNS
install_massdns_resolvers

# Install Ffuf
install_ffuf

# Final cleanup
print_message "green" "[+] All installations completed successfully."

print_message "yellow" "=============================================="
print_message "yellow" "Reconamate is now installed and ready to use."
print_message "yellow" "=============================================="

