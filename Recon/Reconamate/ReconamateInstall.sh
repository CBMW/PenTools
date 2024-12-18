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
# Designed for Ubuntu/Debian-based systems with enhanced reliability.
#
# Usage:
#   chmod +x ReconamateInstall.sh
#   ./ReconamateInstall.sh
#
# =============================================================================

# ------------------------------ Configuration -----------------------------------

MAX_RETRIES=3
RETRY_DELAY=5  # Initial delay in seconds

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

# Function to perform retries with exponential backoff
retry() {
    local n=1
    local max=$MAX_RETRIES
    local delay=$RETRY_DELAY
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                print_message "yellow" "[*] Command failed. Attempt $n/$max. Retrying in $delay seconds..."
                sleep $delay
                delay=$((delay * 2))
            else
                print_message "red" "[!] The command has failed after $n attempts."
                return 1
            fi
        }
    done
}

# Function to install a package via apt-get with retries
install_apt_package() {
    PACKAGE=$1
    if dpkg -s "$PACKAGE" &> /dev/null; then
        print_message "green" "[+] $PACKAGE is already installed."
    else
        print_message "yellow" "[*] Installing $PACKAGE..."
        retry sudo apt-get install -y "$PACKAGE"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully installed $PACKAGE."
        else
            print_message "red" "[!] Failed to install $PACKAGE after multiple attempts."
        fi
    fi
}

# Function to install a Go-based tool with retries and alternative methods
install_go_tool() {
    TOOL_IMPORT_PATH=$1
    BINARY_NAME=$2
    if command -v "$BINARY_NAME" &> /dev/null; then
        print_message "green" "[+] $BINARY_NAME is already installed."
    else
        print_message "yellow" "[*] Installing $BINARY_NAME..."
        retry go install "$TOOL_IMPORT_PATH@latest"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully installed $BINARY_NAME."
        else
            print_message "red" "[!] Failed to install $BINARY_NAME via 'go install'. Attempting alternative method..."
            # Alternative: Clone the repo and build manually
            TEMP_DIR=$(mktemp -d)
            git clone "$TOOL_IMPORT_PATH" "$TEMP_DIR/$BINARY_NAME"
            cd "$TEMP_DIR/$BINARY_NAME" || exit
            retry go build -o "$BINARY_NAME"
            if [ $? -eq 0 ]; then
                sudo mv "$BINARY_NAME" /usr/local/bin/
                print_message "green" "[+] Successfully installed $BINARY_NAME via alternative method."
            else
                print_message "red" "[!] Failed to install $BINARY_NAME via alternative method."
            fi
            cd - || exit
            rm -rf "$TEMP_DIR"
        fi
    fi
}

# Function to clone a Git repository with retries
clone_repo() {
    REPO_URL=$1
    DEST_DIR=$2
    if [ -d "$DEST_DIR" ]; then
        print_message "green" "[+] Repository $DEST_DIR already exists."
    else
        print_message "yellow" "[*] Cloning repository $REPO_URL..."
        retry git clone "$REPO_URL" "$DEST_DIR"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully cloned $REPO_URL."
        else
            print_message "red" "[!] Failed to clone $REPO_URL after multiple attempts."
        fi
    fi
}

# Function to install Python modules via pip3 with retries
install_pip_module() {
    MODULE=$1
    # Check if the module is already installed
    if pip3 show "$MODULE" &> /dev/null; then
        print_message "green" "[+] Python module '$MODULE' is already installed."
    else
        print_message "yellow" "[*] Installing Python module '$MODULE'..."
        # Use virtual environment or pipx if in an externally managed environment
        if [[ "$VIRTUAL_ENV" != "" ]]; then
            retry pip3 install "$MODULE"
        else
            # Check if pipx is installed
            if command -v pipx &> /dev/null; then
                retry pipx install "$MODULE"
            else
                # Install pipx
                print_message "yellow" "[*] Installing pipx for managing Python packages..."
                retry sudo apt-get install -y pipx
                if [ $? -eq 0 ]; then
                    export PATH="$PATH:$HOME/.local/bin"
                    retry pipx install "$MODULE"
                else
                    print_message "red" "[!] Failed to install pipx. Attempting to install via pip in a virtual environment..."
                    # Create a virtual environment
                    VENV_DIR="$HOME/.reconamate_venv"
                    if [ ! -d "$VENV_DIR" ]; then
                        retry python3 -m venv "$VENV_DIR"
                        if [ $? -ne 0 ]; then
                            print_message "red" "[!] Failed to create virtual environment."
                            return 1
                        fi
                    fi
                    source "$VENV_DIR/bin/activate"
                    retry pip install "$MODULE"
                    deactivate
                fi
            fi
        fi
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Successfully installed Python module '$MODULE'."
        else
            print_message "red" "[!] Failed to install Python module '$MODULE' after multiple attempts."
        fi
    fi
}

# Function to set up Go environment with retries
setup_go() {
    if command -v go &> /dev/null; then
        print_message "green" "[+] Go is already installed."
    else
        print_message "yellow" "[*] Installing Go..."
        GO_VERSION="1.20.5"
        GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
        GO_URL="https://golang.org/dl/${GO_TAR}"
        retry wget "$GO_URL" -O go.tar.gz
        if [ $? -eq 0 ]; then
            sudo tar -C /usr/local -xzf go.tar.gz
            rm go.tar.gz
            export PATH=$PATH:/usr/local/go/bin
            echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
            print_message "green" "[+] Go installation completed."
        else
            print_message "red" "[!] Failed to download Go. Please install it manually."
        fi
    fi
}

# Function to install MassDNS with retries
install_massdns() {
    if command -v massdns &> /dev/null; then
        print_message "green" "[+] MassDNS is already installed."
    else
        print_message "yellow" "[*] Installing MassDNS..."
        clone_repo "https://github.com/blechschmidt/massdns.git" "massdns"
        if [ -d "massdns" ]; then
            cd massdns || exit
            retry make
            if [ $? -eq 0 ]; then
                sudo make install
                if command -v massdns &> /dev/null; then
                    print_message "green" "[+] MassDNS installation completed."
                else
                    print_message "red" "[!] MassDNS installation failed after build."
                fi
            else
                print_message "red" "[!] MassDNS build failed."
            fi
            cd ..
            rm -rf massdns
        else
            print_message "red" "[!] MassDNS repository not found."
        fi
    fi
}

# Function to install Testssl.sh with retries
install_testssl() {
    if [ -f "/usr/local/bin/testssl.sh" ]; then
        print_message "green" "[+] Testssl.sh is already installed."
    else
        print_message "yellow" "[*] Installing Testssl.sh..."
        clone_repo "https://github.com/drwetter/testssl.sh.git" "testssl.sh"
        if [ -d "testssl.sh" ]; then
            sudo ln -s "$(pwd)/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
            chmod +x testssl.sh/testssl.sh
            if [ -f "/usr/local/bin/testssl.sh" ]; then
                print_message "green" "[+] Testssl.sh installation completed."
            else
                print_message "red" "[!] Testssl.sh installation failed."
            fi
            rm -rf testssl.sh
        else
            print_message "red" "[!] Testssl.sh repository not found."
        fi
    fi
}

# Function to install EyeWitness with retries and alternative methods
install_eyewitness() {
    if command -v EyeWitness.py &> /dev/null || command -v eyewitness &> /dev/null; then
        print_message "green" "[+] EyeWitness is already installed."
    else
        print_message "yellow" "[*] Installing EyeWitness..."
        clone_repo "https://github.com/FortyNorthSecurity/EyeWitness.git" "EyeWitness"
        if [ -d "EyeWitness/Python" ]; then
            cd EyeWitness/Python || exit
            # Use a virtual environment to avoid system package issues
            VENV_DIR="../../.eyewitness_venv"
            if [ ! -d "$VENV_DIR" ]; then
                retry python3 -m venv "$VENV_DIR"
                if [ $? -ne 0 ]; then
                    print_message "red" "[!] Failed to create virtual environment for EyeWitness."
                    cd ../..
                    rm -rf EyeWitness
                    return
                fi
            fi
            source "$VENV_DIR/bin/activate"
            retry pip install --upgrade pip
            retry pip install -r requirements.txt
            if [ $? -eq 0 ]; then
                sudo ln -s "$(pwd)/EyeWitness.py" /usr/local/bin/eyewitness
                print_message "green" "[+] EyeWitness installation completed."
            else
                print_message "red" "[!] Failed to install EyeWitness Python dependencies."
            fi
            deactivate
            cd ../..
            rm -rf EyeWitness
        else
            print_message "red" "[!] EyeWitness repository structure is unexpected."
        fi
    fi
}

# Function to install Aquatone with retries
install_aquatone() {
    if command -v aquatone &> /dev/null; then
        print_message "green" "[+] Aquatone is already installed."
    else
        print_message "yellow" "[*] Installing Aquatone..."
        retry go install github.com/michenriksen/aquatone@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Aquatone installation completed."
        else
            print_message "red" "[!] Aquatone installation failed via 'go install'. Attempting alternative method..."
            # Alternative: Clone the repo and build manually
            TEMP_DIR=$(mktemp -d)
            git clone https://github.com/michenriksen/aquatone.git "$TEMP_DIR/aquatone"
            cd "$TEMP_DIR/aquatone" || exit
            retry go build -o aquatone
            if [ $? -eq 0 ]; then
                sudo mv aquatone /usr/local/bin/
                print_message "green" "[+] Aquatone installed via alternative method."
            else
                print_message "red" "[!] Aquatone installation failed via alternative method."
            fi
            cd - || exit
            rm -rf "$TEMP_DIR"
        fi
    fi
}

# Function to install Subjack with retries
install_subjack() {
    if command -v subjack &> /dev/null; then
        print_message "green" "[+] Subjack is already installed."
    else
        print_message "yellow" "[*] Installing Subjack..."
        retry go install github.com/haccer/subjack@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Subjack installation completed."
        else
            print_message "red" "[!] Subjack installation failed via 'go install'. Attempting alternative method..."
            # Alternative: Clone the repo and build manually
            TEMP_DIR=$(mktemp -d)
            git clone https://github.com/haccer/subjack.git "$TEMP_DIR/subjack"
            cd "$TEMP_DIR/subjack" || exit
            retry go build -o subjack
            if [ $? -eq 0 ]; then
                sudo mv subjack /usr/local/bin/
                print_message "green" "[+] Subjack installed via alternative method."
            else
                print_message "red" "[!] Subjack installation failed via alternative method."
            fi
            cd - || exit
            rm -rf "$TEMP_DIR"
        fi
    fi
}

# Function to install Subfinder with retries
install_subfinder() {
    if command -v subfinder &> /dev/null; then
        print_message "green" "[+] Subfinder is already installed."
    else
        print_message "yellow" "[*] Installing Subfinder..."
        retry go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Subfinder installation completed."
        else
            print_message "red" "[!] Subfinder installation failed via 'go install'. Attempting alternative method..."
            # Alternative: Clone the repo and build manually
            TEMP_DIR=$(mktemp -d)
            git clone https://github.com/projectdiscovery/subfinder.git "$TEMP_DIR/subfinder"
            cd "$TEMP_DIR/subfinder" || exit
            retry make install
            if [ $? -eq 0 ]; then
                print_message "green" "[+] Subfinder installed via alternative method."
            else
                print_message "red" "[!] Subfinder installation failed via alternative method."
            fi
            cd - || exit
            rm -rf "$TEMP_DIR"
        fi
    fi
}

# Function to install FFUF with retries
install_ffuf() {
    if command -v ffuf &> /dev/null; then
        print_message "green" "[+] FFUF is already installed."
    else
        print_message "yellow" "[*] Installing FFUF..."
        retry go install github.com/ffuf/ffuf@latest
        if [ $? -eq 0 ]; then
            print_message "green" "[+] FFUF installation completed."
        else
            print_message "red" "[!] FFUF installation failed via 'go install'. Attempting alternative method..."
            # Alternative: Clone the repo and build manually
            TEMP_DIR=$(mktemp -d)
            git clone https://github.com/ffuf/ffuf.git "$TEMP_DIR/ffuf"
            cd "$TEMP_DIR/ffuf" || exit
            retry go build -o ffuf
            if [ $? -eq 0 ]; then
                sudo mv ffuf /usr/local/bin/
                print_message "green" "[+] FFUF installed via alternative method."
            else
                print_message "red" "[!] FFUF installation failed via alternative method."
            fi
            cd - || exit
            rm -rf "$TEMP_DIR"
        fi
    fi
}

# Function to download resolvers for MassDNS with retries
install_massdns_resolvers() {
    RESOLVERS_URL="https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt"
    RESOLVERS_FILE="/usr/local/share/massdns/resolvers.txt"
    
    if [ -f "$RESOLVERS_FILE" ]; then
        print_message "green" "[+] MassDNS resolvers already exist."
    else
        print_message "yellow" "[*] Downloading MassDNS resolvers..."
        sudo mkdir -p /usr/local/share/massdns
        retry sudo wget "$RESOLVERS_URL" -O "$RESOLVERS_FILE"
        if [ $? -eq 0 ]; then
            print_message "green" "[+] MassDNS resolvers downloaded successfully."
        else
            print_message "red" "[!] Failed to download MassDNS resolvers after multiple attempts."
        fi
    fi
}

# Function to install pipx with retries
install_pipx() {
    if command -v pipx &> /dev/null; then
        print_message "green" "[+] pipx is already installed."
    else
        print_message "yellow" "[*] Installing pipx..."
        retry sudo apt-get install -y pipx
        if [ $? -eq 0 ]; then
            export PATH="$PATH:$HOME/.local/bin"
            print_message "green" "[+] pipx installation completed."
        else
            print_message "red" "[!] Failed to install pipx."
        fi
    fi
}

# Function to install Gobuster via apt-get with retries
install_gobuster() {
    if command -v gobuster &> /dev/null; then
        print_message "green" "[+] Gobuster is already installed."
    else
        print_message "yellow" "[*] Installing Gobuster via apt-get..."
        retry sudo apt-get install -y gobuster
        if [ $? -eq 0 ]; then
            print_message "green" "[+] Gobuster installation completed."
        else
            print_message "red" "[!] Gobuster installation failed via apt-get. Attempting to install via Go..."
            install_go_tool "github.com/OJ/gobuster/v3@latest" "gobuster"
        fi
    fi
}

# Function to install Certspotter dependencies
install_certspotter_dependencies() {
    # Assuming Certspotter is integrated via API calls in the Python script
    # Ensure dependencies are installed
    # Add specific dependencies if needed
    print_message "yellow" "[*] Installing Certspotter dependencies..."
    install_pip_module "certspotter"
}

# ------------------------------ Main Script -------------------------------------

print_message "yellow" "=============================================="
print_message "yellow" "   Reconamate Installation Script"
print_message "yellow" "=============================================="

# Update package list with retries
print_message "yellow" "[*] Updating package list..."
retry sudo apt-get update -y
if [ $? -eq 0 ]; then
    print_message "green" "[+] Package list updated."
else
    print_message "red" "[!] Failed to update package list after multiple attempts."
fi

# Install essential packages with retries
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

# Install pipx for managing Python packages
install_pipx

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

# Install additional Python modules
install_pip_module "shodan"

# Install Gobuster
install_gobuster

# Install Certspotter dependencies
install_certspotter_dependencies

# Download resolvers for MassDNS
install_massdns_resolvers

# Final cleanup
print_message "green" "[+] All installations completed. Verifying installations..."

# Verification steps
TOOLS=("subfinder" "aquatone" "subjack" "ffuf" "massdns" "testssl.sh" "eyewitness" "shodan" "gobuster")
for TOOL in "${TOOLS[@]}"; do
    if command -v "$TOOL" &> /dev/null; then
        print_message "green" "[+] $TOOL is installed."
    else
        print_message "red" "[!] $TOOL is NOT installed."
    fi
done

print_message "yellow" "=============================================="
print_message "yellow" "Reconamate is now installed and ready to use."
print_message "yellow" "=============================================="
