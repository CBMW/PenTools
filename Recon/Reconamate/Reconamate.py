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

import subprocess
import os
import xml.etree.ElementTree as ET
import json
from datetime import datetime
import argparse
import threading
import requests
import shodan

# ------------------------------ Setup Functions ------------------------------

def setup_output_directory(base_dir="recon_results"):
    """
    Creates an output directory for storing reconnaissance results.
    Generates a timestamped filename for organized reporting.

    Args:
        base_dir (str): The base directory name for storing results.

    Returns:
        dict: A dictionary containing paths to various output files.
    """
    os.makedirs(base_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return {
        "nmap": os.path.join(base_dir, f"nmap_output_{timestamp}.xml"),
        "nmap_log": os.path.join(base_dir, f"nmap_log_{timestamp}.txt"),
        "nikto": os.path.join(base_dir, f"nikto_output_{timestamp}.txt"),
        "gobuster": os.path.join(base_dir, f"gobuster_output_{timestamp}.txt"),
        "amass": os.path.join(base_dir, f"amass_output_{timestamp}.txt"),
        "theharvester": os.path.join(base_dir, f"theharvester_output_{timestamp}.txt"),
        "subfinder": os.path.join(base_dir, f"subfinder_output_{timestamp}.txt"),
        "whatweb": os.path.join(base_dir, f"whatweb_output_{timestamp}.txt"),
        "testssl": os.path.join(base_dir, f"testssl_output_{timestamp}.txt"),
        "eyewitness": os.path.join(base_dir, f"eyewitness_output_{timestamp}.txt"),
        "aquatone": os.path.join(base_dir, f"aquatone_output_{timestamp}.txt"),
        "subjack": os.path.join(base_dir, f"subjack_output_{timestamp}.csv"),
        "dnsenum": os.path.join(base_dir, f"dnsenum_output_{timestamp}.txt"),
        "massdns": os.path.join(base_dir, f"massdns_output_{timestamp}.txt"),
        "fierce": os.path.join(base_dir, f"fierce_output_{timestamp}.txt"),
        "dmitry": os.path.join(base_dir, f"dmitry_output_{timestamp}.txt"),
        "certspotter": os.path.join(base_dir, f"certspotter_output_{timestamp}.txt"),
        "shodan": os.path.join(base_dir, f"shodan_output_{timestamp}.json"),
        "ffuf": os.path.join(base_dir, f"ffuf_output_{timestamp}.json"),
        "report": os.path.join(base_dir, f"final_report_{timestamp}.txt")
    }

# ------------------------------ Nmap Functions ------------------------------

def run_nmap(target, output_file, log_file, rate_limit, aggressive=True, ports="1-65535"):
    """
    Executes an extensive Nmap scan on the specified target and saves the output in XML format.

    This scan includes:
    - Service version detection
    - OS detection
    - Aggressive scan options
    - Scanning specified ports
    - Using comprehensive scripts
    - Verbose output
    - Rate limiting via timing templates

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Nmap XML output.
        log_file (str): The file path to save the verbose Nmap log.
        rate_limit (str): The timing template to control scan intensity (e.g., "T4" for faster scans).
        aggressive (bool): Whether to perform aggressive scan options.
        ports (str): The port range to scan (e.g., "1-65535").

    Raises:
        subprocess.CalledProcessError: If the Nmap scan fails.
    """
    print("[*] Running Extensive Nmap Scan...")
    nmap_command = [
        "nmap",
        "-p", ports,               # Specify port range
        "-sV",                     # Service version detection
        "-O",                      # OS detection
        "--script", "default,discovery,vuln,auth"  # Comprehensive script scan
    ]

    if aggressive:
        nmap_command.append("-A")  # Aggressive scan options

    nmap_command.extend([
        "-T", rate_limit,         # Timing template for rate limiting (T1-T5)
        "-oX", output_file,       # Output in XML format
        "-v",                      # Verbose output
        target
    ])

    with open(log_file, 'w') as log:
        subprocess.run(nmap_command, stdout=log, stderr=subprocess.STDOUT, check=True)
    print("[+] Extensive Nmap Scan Completed.")

def parse_nmap(output_file):
    """
    Parses the Nmap XML output to extract information about open ports and services.

    Args:
        output_file (str): The file path of the Nmap XML output.

    Returns:
        list: A list of dictionaries containing port, protocol, service name, product, version, extra info, and reason.
    """
    print("[*] Parsing Nmap Output...")
    services = []
    try:
        tree = ET.parse(output_file)
        root = tree.getroot()
        for host in root.findall('host'):
            status = host.find('status').get('state')
            if status != 'up':
                continue
            for port in host.find('ports').findall('port'):
                portid = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                if state != 'open':
                    continue
                service = port.find('service')
                if service is not None:
                    service_info = {
                        "port": portid,
                        "protocol": protocol,
                        "state": state,
                        "service_name": service.get('name', 'N/A'),
                        "product": service.get('product', 'N/A'),
                        "version": service.get('version', 'N/A'),
                        "extrainfo": service.get('extrainfo', 'N/A'),
                        "reason": service.get('reason', 'N/A')
                    }
                    services.append(service_info)
    except Exception as e:
        print(f"[!] Error parsing Nmap output: {e}")
    print("[+] Nmap Parsing Completed.")
    return services

# ------------------------------ Nikto Functions ------------------------------

def run_nikto(target, output_file, rate_limit):
    """
    Executes a Nikto scan on the specified target and saves the output to a text file.

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Nikto output.
        rate_limit (str): Rate limiting parameter (e.g., delay between requests).

    Raises:
        subprocess.CalledProcessError: If the Nikto scan fails.
    """
    print("[*] Running Nikto Scan...")
    nikto_command = [
        "nikto",
        "-h", target,
        "-output", output_file,
        "-Format", "txt",    # Specify output format
        "-Display", " V"     # Verbose output
    ]

    # Apply rate limiting by adding a delay between requests
    if rate_limit:
        nikto_command.extend(["-D", rate_limit])

    subprocess.run(nikto_command, check=True)
    print("[+] Nikto Scan Completed.")

def parse_nikto(output_file):
    """
    Parses the Nikto scan output to extract lines containing vulnerability information.

    Args:
        output_file (str): The file path of the Nikto scan output.

    Returns:
        list: A list of strings, each representing a vulnerability finding.
    """
    print("[*] Parsing Nikto Output...")
    findings = []
    try:
        with open(output_file, 'r', errors='ignore') as f:
            for line in f:
                if "OSVDB" in line or "VULN" in line or "Warning" in line:
                    findings.append(line.strip())
    except Exception as e:
        print(f"[!] Error parsing Nikto output: {e}")
    print("[+] Nikto Parsing Completed.")
    return findings

# ------------------------------ Gobuster Functions ------------------------------

def run_gobuster(target, output_file, wordlist, rate_limit):
    """
    Executes a Gobuster directory brute-force scan on the specified target.

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Gobuster output.
        wordlist (str): The path to the wordlist used for brute-forcing directories.
        rate_limit (int): Delay between requests in milliseconds.

    Raises:
        subprocess.CalledProcessError: If the Gobuster scan fails.
    """
    print("[*] Running Gobuster Scan...")
    gobuster_command = [
        "gobuster",
        "dir",
        "-u", f"http://{target}",
        "-w", wordlist,
        "-o", output_file,
        "-t", "50",               # Number of concurrent threads
        "-x", "php,html,js,txt"   # Extensions to search for
    ]

    if rate_limit:
        gobuster_command.extend(["-s", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(gobuster_command, check=True)
    print("[+] Gobuster Scan Completed.")

def parse_gobuster(output_file):
    """
    Parses the Gobuster scan output to extract discovered directories and their HTTP status codes.

    Args:
        output_file (str): The file path of the Gobuster scan output.

    Returns:
        list: A list of strings, each representing a discovered directory with its status.
    """
    print("[*] Parsing Gobuster Output...")
    directories = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                if line.startswith("/"):
                    parts = line.split()
                    if len(parts) >= 2:
                        directories.append(f"{parts[0]} - Status: {parts[1]}")
    except Exception as e:
        print(f"[!] Error parsing Gobuster output: {e}")
    print("[+] Gobuster Parsing Completed.")
    return directories

# ------------------------------ Amass Functions ------------------------------

def run_amass(target, output_file, rate_limit):
    """
    Executes an Amass enumeration to discover subdomains of the specified target.

    Args:
        target (str): The domain to enumerate subdomains for.
        output_file (str): The file path to save the Amass output.
        rate_limit (int): Rate limiting parameter if applicable.

    Raises:
        subprocess.CalledProcessError: If the Amass enumeration fails.
    """
    print("[*] Running Amass Enumeration...")
    amass_command = [
        "amass",
        "enum",
        "-d", target,
        "-o", output_file
    ]

    # Amass does not directly support rate limiting, but you can control concurrency via configuration
    if rate_limit:
        amass_command.extend(["-max-dns-queries", str(rate_limit)])

    subprocess.run(amass_command, check=True)
    print("[+] Amass Enumeration Completed.")

def parse_amass(output_file):
    """
    Parses the Amass enumeration output to extract discovered subdomains.

    Args:
        output_file (str): The file path of the Amass enumeration output.

    Returns:
        list: A list of discovered subdomains.
    """
    print("[*] Parsing Amass Output...")
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    subdomains.append(line)
    except Exception as e:
        print(f"[!] Error parsing Amass output: {e}")
    print("[+] Amass Parsing Completed.")
    return subdomains

# ------------------------------ theHarvester Functions ------------------------------

def run_theharvester(target, output_file, rate_limit):
    """
    Executes theHarvester to gather emails and subdomains using OSINT sources.

    Args:
        target (str): The domain to gather information for.
        output_file (str): The file path to save theHarvester output.
        rate_limit (int): Delay between requests in seconds.

    Raises:
        subprocess.CalledProcessError: If theHarvester execution fails.
    """
    print("[*] Running theHarvester...")
    theharvester_command = [
        "theharvester",
        "-d", target,
        "-b", "all",           # Using all available sources
        "-f", output_file,
        "-l", "500",           # Limit number of results
        "-s"                   # Silent mode to minimize output
    ]

    if rate_limit:
        theharvester_command.extend(["-t", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(theharvester_command, check=True)
    print("[+] theHarvester Completed.")

def parse_theharvester(output_file):
    """
    Parses theHarvester output to extract found emails and subdomains.

    Args:
        output_file (str): The file path of theHarvester output.

    Returns:
        list: A list of findings, including emails and subdomains.
    """
    print("[*] Parsing theHarvester Output...")
    findings = []
    try:
        with open(output_file, 'r', errors='ignore') as f:
            capture = False
            for line in f:
                if "Found:" in line:
                    capture = True
                    continue
                if capture:
                    if line.strip() == "":
                        break
                    findings.append(line.strip())
    except Exception as e:
        print(f"[!] Error parsing theHarvester output: {e}")
    print("[+] theHarvester Parsing Completed.")
    return findings

# ------------------------------ Subfinder Functions ------------------------------

def run_subfinder(target, output_file, rate_limit):
    """
    Executes Subfinder to discover subdomains of the specified target.

    Args:
        target (str): The domain to discover subdomains for.
        output_file (str): The file path to save the Subfinder output.
        rate_limit (int): Number of threads to limit the scan intensity.

    Raises:
        subprocess.CalledProcessError: If the Subfinder execution fails.
    """
    print("[*] Running Subfinder...")
    subfinder_command = [
        "subfinder",
        "-d", target,
        "-o", output_file,
        "-t", str(rate_limit),    # Number of concurrent threads
        "-silent"                  # Silent mode to minimize output
    ]
    subprocess.run(subfinder_command, check=True)
    print("[+] Subfinder Completed.")

def parse_subfinder(output_file):
    """
    Parses the Subfinder output to extract discovered subdomains.

    Args:
        output_file (str): The file path of the Subfinder output.

    Returns:
        list: A list of discovered subdomains.
    """
    print("[*] Parsing Subfinder Output...")
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    subdomains.append(line)
    except Exception as e:
        print(f"[!] Error parsing Subfinder output: {e}")
    print("[+] Subfinder Parsing Completed.")
    return subdomains

# ------------------------------ WhatWeb Functions ------------------------------

def run_whatweb(target, output_file, rate_limit):
    """
    Executes WhatWeb to identify web technologies used by the target.

    Args:
        target (str): The domain or IP address to analyze.
        output_file (str): The file path to save the WhatWeb output.
        rate_limit (int): Delay between requests in milliseconds.

    Raises:
        subprocess.CalledProcessError: If the WhatWeb execution fails.
    """
    print("[*] Running WhatWeb...")
    whatweb_command = [
        "whatweb",
        "-v",        # Verbose output
        "-a", "3",   # Aggressiveness level (1-5)
        target,
        "-o", output_file
    ]

    if rate_limit:
        whatweb_command.extend(["--delay", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(whatweb_command, check=True)
    print("[+] WhatWeb Completed.")

def parse_whatweb(output_file):
    """
    Parses the WhatWeb output to extract identified web technologies.

    Args:
        output_file (str): The file path of the WhatWeb output.

    Returns:
        list: A list of detected web technologies, without duplicates.
    """
    print("[*] Parsing WhatWeb Output...")
    technologies = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                # Example line: http://example.com [200 OK] {HTML5, PHP, Nginx, WordPress}
                if "[" in line and "{" in line:
                    parts = line.split("{")
                    techs = parts[1].strip("}\n").split(", ")
                    technologies.extend(techs)
    except Exception as e:
        print(f"[!] Error parsing WhatWeb output: {e}")
    print("[+] WhatWeb Parsing Completed.")
    return list(set(technologies))  # Remove duplicates

# ------------------------------ Testssl.sh Functions ------------------------------

def run_testssl(target, output_file, rate_limit):
    """
    Executes Testssl.sh to perform a comprehensive SSL/TLS scan on the target.

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Testssl.sh JSON output.
        rate_limit (int): Delay between requests in milliseconds if supported.

    Raises:
        subprocess.CalledProcessError: If the Testssl.sh execution fails.
    """
    print("[*] Running Testssl.sh...")
    testssl_command = [
        "testssl.sh",
        f"https://{target}",
        "--quiet",
        "--jsonfile", output_file
    ]

    if rate_limit:
        testssl_command.extend(["--delay", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(testssl_command, check=True)
    print("[+] Testssl.sh Completed.")

def parse_testssl(output_file):
    """
    Parses the Testssl.sh JSON output to extract SSL/TLS configurations and vulnerabilities.

    Args:
        output_file (str): The file path of the Testssl.sh JSON output.

    Returns:
        dict: A dictionary containing SSL/TLS scan details and identified vulnerabilities.
    """
    print("[*] Parsing Testssl.sh Output...")
    ssl_details = {}
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
            ssl_details = data
    except Exception as e:
        print(f"[!] Error parsing Testssl.sh output: {e}")
    print("[+] Testssl.sh Parsing Completed.")
    return ssl_details

# ------------------------------ EyeWitness Functions ------------------------------

def run_eyewitness(target, output_file, rate_limit):
    """
    Executes EyeWitness to capture screenshots of discovered web services.

    Args:
        target (str): The domain or IP address to capture screenshots for.
        output_file (str): The file path to save the EyeWitness output.
        rate_limit (int): Delay between requests in milliseconds if applicable.

    Raises:
        subprocess.CalledProcessError: If the EyeWitness execution fails.
    """
    print("[*] Running EyeWitness...")
    eyewitness_command = [
        "EyeWitness.py",
        "--web",                  # Target web URLs
        "-f", "targets.txt",      # File containing target URLs
        "--out", "eyewitness_reports",
        "--save", output_file,
        "--disable-logging",      # Disable logging to minimize output
        "--threads", "10"         # Number of concurrent threads
    ]

    # Apply rate limiting by adding a delay if supported
    if rate_limit:
        eyewitness_command.extend(["--delay", str(rate_limit)])

    # Create targets.txt with target URL
    with open("targets.txt", "w") as f:
        f.write(f"http://{target}\n")
        f.write(f"https://{target}\n")
    subprocess.run(eyewitness_command, check=True)
    print("[+] EyeWitness Completed.")

def parse_eyewitness(output_file):
    """
    Parses the EyeWitness output to list captured screenshot file paths.

    Args:
        output_file (str): The file path of the EyeWitness output.

    Returns:
        list: A list of file paths to the captured screenshots.
    """
    print("[*] Parsing EyeWitness Output...")
    screenshots = []
    try:
        report_dir = "eyewitness_reports"
        for root, dirs, files in os.walk(report_dir):
            for file in files:
                if file.endswith(".png"):
                    screenshots.append(os.path.join(root, file))
    except Exception as e:
        print(f"[!] Error parsing EyeWitness output: {e}")
    print("[+] EyeWitness Parsing Completed.")
    return screenshots

# ------------------------------ Aquatone Functions ------------------------------

def run_aquatone(target, output_file, rate_limit):
    """
    Executes Aquatone to perform subdomain screenshotting and HTTP enumeration.

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Aquatone output.
        rate_limit (int): Delay between requests in milliseconds if applicable.

    Raises:
        subprocess.CalledProcessError: If the Aquatone execution fails.
    """
    print("[*] Running Aquatone...")
    aquatone_command = [
        "aquatone",
        "-d", "aquatone_output",
        "-ports", "80,443",
        "-out", output_file,
        "-scan-timeout", "10000"
    ]
    # Collect all subdomains from relevant tools
    subdomains = set()
    tools_with_subdomains = ['amass', 'subfinder', 'dnsenum', 'fierce', 'subjack', 'certspotter']
    for tool in tools_with_subdomains:
        data = parsed_data.get(tool, [])
        if isinstance(data, list):
            subdomains.update(data)
        elif isinstance(data, dict):
            subdomains.update(data.get('subdomains', []))
    # Write to a temporary file for Aquatone input
    with open("aquatone_targets.txt", "w") as f:
        for sub in subdomains:
            f.write(f"http://{sub}\n")
            f.write(f"https://{sub}\n")
    aquatone_command.extend(["-targets", "aquatone_targets.txt"])

    # Apply rate limiting if supported
    if rate_limit:
        aquatone_command.extend(["--delay", str(rate_limit)])

    subprocess.run(aquatone_command, check=True)
    print("[+] Aquatone Completed.")

def parse_aquatone(output_file):
    """
    Parses the Aquatone output to list captured screenshot file paths.

    Args:
        output_file (str): The file path of the Aquatone output.

    Returns:
        list: A list of file paths to the captured screenshots.
    """
    print("[*] Parsing Aquatone Output...")
    screenshots = []
    try:
        report_dir = "aquatone_output/screenshots"
        for root, dirs, files in os.walk(report_dir):
            for file in files:
                if file.endswith(".png"):
                    screenshots.append(os.path.join(root, file))
    except Exception as e:
        print(f"[!] Error parsing Aquatone output: {e}")
    print("[+] Aquatone Parsing Completed.")
    return screenshots

# ------------------------------ Subjack Functions ------------------------------

def download_subjack_fingerprints(fingerprint_path="fingerprints.json"):
    """
    Downloads the latest Subjack fingerprints JSON file.

    Args:
        fingerprint_path (str): The file path to save the fingerprints JSON.

    Raises:
        Exception: If the download fails.
    """
    print("[*] Downloading Subjack fingerprints...")
    url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            with open(fingerprint_path, 'w') as f:
                f.write(response.text)
            print("[+] Subjack fingerprints downloaded.")
        else:
            print(f"[!] Failed to download fingerprints. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[!] Error downloading fingerprints: {e}")

def run_subjack(target, output_file, rate_limit):
    """
    Executes Subjack to detect potential subdomain takeovers on the specified target.

    Args:
        target (str): The domain to scan for subdomain takeovers.
        output_file (str): The file path to save the Subjack output.
        rate_limit (int): Number of threads to limit the scan intensity.

    Raises:
        subprocess.CalledProcessError: If the Subjack execution fails.
    """
    print("[*] Running Subjack...")
    # Ensure fingerprints.json is available
    if not os.path.exists("fingerprints.json"):
        download_subjack_fingerprints()

    # First, generate a list of subdomains
    subdomains_file = "subjack_subdomains.txt"
    with open(subdomains_file, 'w') as f:
        # Collect subdomains from Amass, Subfinder, Dnsenum, Fierce, Subjack, Certspotter
        tools_with_subdomains = ['amass', 'subfinder', 'dnsenum', 'fierce', 'certspotter']
        for tool in tools_with_subdomains:
            data = parsed_data.get(tool, [])
            if isinstance(data, list):
                for sub in data:
                    f.write(f"{sub}\n")
            elif isinstance(data, dict):
                for sub in data.get('subdomains', []):
                    f.write(f"{sub}\n")
    subjack_command = [
        "subjack",
        "-w", subdomains_file,
        "-t", str(rate_limit),
        "-timeout", "30",
        "-ssl",
        "-c", "fingerprints.json",  # Path to fingerprints.json
        "-v",
        "-o", output_file
    ]
    subprocess.run(subjack_command, check=True)
    print("[+] Subjack Completed.")

def parse_subjack(output_file):
    """
    Parses the Subjack output to extract potential subdomain takeover vulnerabilities.

    Args:
        output_file (str): The file path of the Subjack output.

    Returns:
        list: A list of dictionaries containing subdomain takeover details.
    """
    print("[*] Parsing Subjack Output...")
    findings = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                parts = line.strip().split(',')
                if len(parts) >= 4:
                    subdomain, provider, status, reason = parts[:4]
                    findings.append({
                        "subdomain": subdomain,
                        "provider": provider,
                        "status": status,
                        "reason": reason
                    })
    except Exception as e:
        print(f"[!] Error parsing Subjack output: {e}")
    print("[+] Subjack Parsing Completed.")
    return findings

# ------------------------------ Dnsenum Functions ------------------------------

def run_dnsenum(target, output_file, rate_limit):
    """
    Executes Dnsenum to gather DNS information about the specified target.

    Args:
        target (str): The domain to scan for DNS information.
        output_file (str): The file path to save the Dnsenum output.
        rate_limit (int): Delay between DNS queries in milliseconds if applicable.

    Raises:
        subprocess.CalledProcessError: If the Dnsenum execution fails.
    """
    print("[*] Running Dnsenum...")
    dnsenum_command = [
        "dnsenum",
        target,
        "--output", output_file,
        "--enum",               # Enumerate DNS information
        "--threads=10",         # Number of concurrent threads
        "--dnsserver=8.8.8.8",  # Specify DNS server (optional)
        "--noreverse"           # Skip reverse DNS lookups
    ]

    if rate_limit:
        dnsenum_command.extend(["--delay", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(dnsenum_command, check=True)
    print("[+] Dnsenum Completed.")

def parse_dnsenum(output_file):
    """
    Parses the Dnsenum output to extract DNS records and subdomains.

    Args:
        output_file (str): The file path of the Dnsenum output.

    Returns:
        dict: A dictionary containing DNS records and discovered subdomains.
    """
    print("[*] Parsing Dnsenum Output...")
    dns_records = {}
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            capture_subdomains = False
            for line in f:
                line = line.strip()
                if line.startswith("Subdomains found:"):
                    capture_subdomains = True
                    continue
                if capture_subdomains:
                    if line == "":
                        capture_subdomains = False
                        continue
                    subdomains.append(line)
                # Additional parsing can be added here for other DNS records
    except Exception as e:
        print(f"[!] Error parsing Dnsenum output: {e}")
    print("[+] Dnsenum Parsing Completed.")
    return {"dns_records": dns_records, "subdomains": subdomains}

# ------------------------------ Massdns Functions ------------------------------

def run_massdns(subdomains_file, output_file, resolvers_file, rate_limit):
    """
    Executes Massdns to perform DNS resolution on a list of subdomains.

    Args:
        subdomains_file (str): The file path containing subdomains to resolve.
        output_file (str): The file path to save the Massdns output.
        resolvers_file (str): The file path containing DNS resolvers.
        rate_limit (int): Number of threads to limit the scan intensity.

    Raises:
        subprocess.CalledProcessError: If the Massdns execution fails.
    """
    print("[*] Running Massdns...")
    massdns_command = [
        "massdns",
        "-r", resolvers_file,     # Path to resolvers.txt
        "-t", "A",
        "-o", "S",
        "-w", output_file,
        subdomains_file,
        "-q"                      # Quiet mode to minimize output
    ]

    if rate_limit:
        massdns_command.extend(["-t", str(rate_limit)])

    subprocess.run(massdns_command, check=True)
    print("[+] Massdns Completed.")

def parse_massdns(output_file):
    """
    Parses the Massdns output to extract resolved subdomains.

    Args:
        output_file (str): The file path of the Massdns output.

    Returns:
        list: A list of resolved subdomains.
    """
    print("[*] Parsing Massdns Output...")
    resolved_subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) >= 3 and parts[1] == "A":
                    resolved_subdomains.append(parts[0])
    except Exception as e:
        print(f"[!] Error parsing Massdns output: {e}")
    print("[+] Massdns Parsing Completed.")
    return resolved_subdomains

# ------------------------------ Fierce Functions ------------------------------

def run_fierce(target, output_file, rate_limit):
    """
    Executes Fierce DNS scanner to discover additional subdomains and DNS records.

    Args:
        target (str): The domain to scan.
        output_file (str): The file path to save the Fierce output.
        rate_limit (int): Delay between requests in milliseconds if applicable.

    Raises:
        subprocess.CalledProcessError: If the Fierce execution fails.
    """
    print("[*] Running Fierce DNS Scanner...")
    fierce_command = [
        "fierce",
        "-dns", target,
        "-file", output_file
    ]

    if rate_limit:
        fierce_command.extend(["--delay", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(fierce_command, check=True)
    print("[+] Fierce DNS Scanner Completed.")

def parse_fierce(output_file):
    """
    Parses the Fierce output to extract discovered subdomains and DNS records.

    Args:
        output_file (str): The file path of the Fierce output.

    Returns:
        list: A list of discovered subdomains.
    """
    print("[*] Parsing Fierce Output...")
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith("Found host") and ":" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        subdomain = parts[1].strip()
                        if subdomain and subdomain not in subdomains:
                            subdomains.append(subdomain)
    except Exception as e:
        print(f"[!] Error parsing Fierce output: {e}")
    print("[+] Fierce Parsing Completed.")
    return subdomains

# ------------------------------ Dmitry Functions ------------------------------

def run_dmitry(target, output_file, rate_limit):
    """
    Executes Dmitry to gather information about the specified target.

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Dmitry output.
        rate_limit (int): Delay between requests in milliseconds if applicable.

    Raises:
        subprocess.CalledProcessError: If the Dmitry execution fails.
    """
    print("[*] Running Dmitry Information Gathering...")
    dmitry_command = [
        "dmitry",
        "-winsepfua",  # Flags: WHOIS, web, SNMP, enumerate, fingerprint, username, etc.
        "-o", output_file,
        target
    ]

    if rate_limit:
        dmitry_command.extend(["--delay", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(dmitry_command, check=True)
    print("[+] Dmitry Completed.")

def parse_dmitry(output_file):
    """
    Parses the Dmitry output to extract gathered information.

    Args:
        output_file (str): The file path of the Dmitry output.

    Returns:
        dict: A dictionary containing gathered information such as emails, subdomains, etc.
    """
    print("[*] Parsing Dmitry Output...")
    gathered_info = {}
    try:
        with open(output_file, 'r', errors='ignore') as f:
            current_section = None
            for line in f:
                line = line.strip()
                if line.endswith(":"):
                    current_section = line[:-1].lower().replace(" ", "_")
                    gathered_info[current_section] = []
                    continue
                if current_section and line:
                    gathered_info[current_section].append(line)
    except Exception as e:
        print(f"[!] Error parsing Dmitry output: {e}")
    print("[+] Dmitry Parsing Completed.")
    return gathered_info

# ------------------------------ Certspotter Functions ------------------------------

def run_certspotter(target, output_file, rate_limit):
    """
    Executes Certspotter to find subdomains via Certificate Transparency logs.

    Args:
        target (str): The domain to search for subdomains.
        output_file (str): The file path to save the Certspotter output.
        rate_limit (int): Delay between requests in milliseconds if applicable.

    Raises:
        Exception: If the Certspotter query fails.
    """
    print("[*] Running Certspotter...")
    url = f"https://api.certspotter.com/v1/issuances?domain={target}&include_subdomains=true&expand=dns_names"
    headers = {"User-Agent": "Automated Recon Script"}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        with open(output_file, 'w') as f:
            for entry in data:
                dns_names = entry.get('dns_names', [])
                for dns in dns_names:
                    if dns.endswith(target):
                        f.write(f"{dns}\n")
        print("[+] Certspotter Completed.")
    except Exception as e:
        print(f"[!] Certspotter error: {e}")

def parse_certspotter(output_file):
    """
    Parses the Certspotter output to extract discovered subdomains.

    Args:
        output_file (str): The file path of the Certspotter output.

    Returns:
        list: A list of discovered subdomains.
    """
    print("[*] Parsing Certspotter Output...")
    subdomains = []
    try:
        with open(output_file, 'r') as f:
            for line in f:
                subdomain = line.strip()
                if subdomain and subdomain not in subdomains:
                    subdomains.append(subdomain)
    except Exception as e:
        print(f"[!] Error parsing Certspotter output: {e}")
    print("[+] Certspotter Parsing Completed.")
    return subdomains

# ------------------------------ Shodan Functions ------------------------------

def run_shodan(api_key, target, output_file, rate_limit):
    """
    Executes Shodan queries to gather information about the target's IP addresses.

    Args:
        api_key (str): Shodan API key.
        target (str): The domain or IP address to query.
        output_file (str): The file path to save the Shodan output.
        rate_limit (int): Number of concurrent threads to limit the scan intensity.

    Raises:
        shodan.APIError: If the Shodan query fails.
    """
    print("[*] Running Shodan Scan...")
    api = shodan.Shodan(api_key)
    try:
        # Resolve target to IP if necessary
        ip = target
        if not target.replace('.', '').isdigit():
            response = requests.get(f"https://dns.google/resolve?name={target}&type=A")
            if response.status_code == 200:
                dns_data = response.json()
                ip = dns_data.get('Answer', [{}])[0].get('data', target)
            else:
                print(f"[!] DNS resolution failed for {target}. Using target as IP.")
        # Get host information
        host = api.host(ip)
        with open(output_file, 'w') as f:
            json.dump(host, f, indent=4)
        print("[+] Shodan Scan Completed.")
    except shodan.APIError as e:
        print(f"[!] Shodan error: {e}")
    except Exception as e:
        print(f"[!] Shodan unexpected error: {e}")

def parse_shodan(output_file):
    """
    Parses the Shodan output to extract relevant information about open ports and services.

    Args:
        output_file (str): The file path of the Shodan output.

    Returns:
        dict: A dictionary containing open ports and service information.
    """
    print("[*] Parsing Shodan Output...")
    shodan_data = {}
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
            shodan_data['ip_str'] = data.get('ip_str', 'N/A')
            shodan_data['hostnames'] = data.get('hostnames', [])
            shodan_data['country_name'] = data.get('country_name', 'N/A')
            shodan_data['ports'] = data.get('ports', [])
            shodan_data['services'] = []
            for service in data.get('data', []):
                shodan_data['services'].append({
                    "port": service.get('port', 'N/A'),
                    "product": service.get('product', 'N/A'),
                    "version": service.get('version', 'N/A'),
                    "banner": service.get('banner', 'N/A')
                })
    except Exception as e:
        print(f"[!] Error parsing Shodan output: {e}")
    print("[+] Shodan Parsing Completed.")
    return shodan_data

# ------------------------------ Ffuf Functions ------------------------------

def run_ffuf(target, output_file, wordlist, rate_limit):
    """
    Executes Ffuf to perform directory fuzzing on the specified target.

    Args:
        target (str): The domain or IP address to scan.
        output_file (str): The file path to save the Ffuf output.
        wordlist (str): The path to the wordlist used for fuzzing.
        rate_limit (int): Delay between requests in milliseconds.

    Raises:
        subprocess.CalledProcessError: If the Ffuf execution fails.
    """
    print("[*] Running Ffuf Directory Fuzzing...")
    ffuf_command = [
        "ffuf",
        "-u", f"http://{target}/FUZZ",
        "-w", wordlist,
        "-o", output_file,
        "-of", "json",
        "-mc", "200,301,302,403,404",
        "-t", "50"
    ]

    if rate_limit:
        ffuf_command.extend(["-r", str(rate_limit)])  # Example: Custom flag for rate limiting if supported

    subprocess.run(ffuf_command, check=True)
    print("[+] Ffuf Directory Fuzzing Completed.")

def parse_ffuf(output_file):
    """
    Parses the Ffuf JSON output to extract discovered directories.

    Args:
        output_file (str): The file path of the Ffuf output.

    Returns:
        list: A list of discovered directories with their status codes.
    """
    print("[*] Parsing Ffuf Output...")
    directories = []
    try:
        with open(output_file, 'r') as f:
            data = json.load(f)
            for result in data.get('results', []):
                url = result.get('url', 'N/A')
                status = result.get('status', 'N/A')
                directories.append(f"{url} - Status: {status}")
    except Exception as e:
        print(f"[!] Error parsing Ffuf output: {e}")
    print("[+] Ffuf Parsing Completed.")
    return directories

# ------------------------------ Subjack Helper Function ------------------------------

def download_subjack_fingerprints(fingerprint_path="fingerprints.json"):
    """
    Downloads the latest Subjack fingerprints JSON file.

    Args:
        fingerprint_path (str): The file path to save the fingerprints JSON.

    Raises:
        Exception: If the download fails.
    """
    print("[*] Downloading Subjack fingerprints...")
    url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            with open(fingerprint_path, 'w') as f:
                f.write(response.text)
            print("[+] Subjack fingerprints downloaded.")
        else:
            print(f"[!] Failed to download fingerprints. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[!] Error downloading fingerprints: {e}")

# ------------------------------ Compile Report Function ------------------------------

def compile_report(output_files, parsed_data):
    """
    Compiles all parsed reconnaissance data into a structured and readable final report.

    Args:
        output_files (dict): A dictionary containing paths to various output files.
        parsed_data (dict): A dictionary containing parsed data from each tool.
    """
    print("[*] Compiling Final Report...")
    with open(output_files['report'], 'w') as report:
        report.write(f"Reconnaissance Report for {TARGET}\n")
        report.write("="*50 + "\n\n")
        
        # Nmap Section
        report.write("Nmap Scan Results:\n")
        report.write("-"*20 + "\n")
        for service in parsed_data['nmap']:
            report.write(f"Port: {service['port']}/{service['protocol']}\n")
            report.write(f"State: {service['state']}\n")
            report.write(f"Service Name: {service['service_name']}\n")
            report.write(f"Product: {service.get('product', 'N/A')}\n")
            report.write(f"Version: {service.get('version', 'N/A')}\n")
            report.write(f"Extra Info: {service.get('extrainfo', 'N/A')}\n")
            report.write(f"Reason: {service.get('reason', 'N/A')}\n")
            report.write("\n")
        
        # Nikto Section
        report.write("\nNikto Scan Results:\n")
        report.write("-"*20 + "\n")
        for finding in parsed_data['nikto']:
            report.write(f"{finding}\n")
        
        # Gobuster Section
        report.write("\nGobuster Scan Results:\n")
        report.write("-"*20 + "\n")
        for directory in parsed_data['gobuster']:
            report.write(f"{directory}\n")
        
        # Amass Section
        report.write("\nAmass Enumeration Results:\n")
        report.write("-"*20 + "\n")
        for subdomain in parsed_data['amass']:
            report.write(f"{subdomain}\n")
        
        # theHarvester Section
        report.write("\ntheHarvester Results:\n")
        report.write("-"*20 + "\n")
        for finding in parsed_data['theharvester']:
            report.write(f"{finding}\n")
        
        # Subfinder Section
        report.write("\nSubfinder Enumeration Results:\n")
        report.write("-"*20 + "\n")
        for subdomain in parsed_data['subfinder']:
            report.write(f"{subdomain}\n")
        
        # WhatWeb Section
        report.write("\nWhatWeb Technology Fingerprinting:\n")
        report.write("-"*20 + "\n")
        for tech in parsed_data['whatweb']:
            report.write(f"{tech}\n")
        
        # Testssl.sh Section
        report.write("\nTestssl.sh SSL/TLS Scan Results:\n")
        report.write("-"*20 + "\n")
        ssl_details = parsed_data['testssl']
        if ssl_details:
            report.write(json.dumps(ssl_details, indent=4))
        else:
            report.write("Testssl.sh results not available.\n")
        
        # EyeWitness Section
        report.write("\nEyeWitness Scan Results (Screenshots):\n")
        report.write("-"*20 + "\n")
        for screenshot in parsed_data['eyewitness']:
            report.write(f"{screenshot}\n")
        
        # Aquatone Section
        report.write("\nAquatone Scan Results (Screenshots):\n")
        report.write("-"*20 + "\n")
        for screenshot in parsed_data['aquatone']:
            report.write(f"{screenshot}\n")
        
        # Subjack Section
        report.write("\nSubjack Scan Results:\n")
        report.write("-"*20 + "\n")
        for vuln in parsed_data['subjack']:
            report.write(f"Subdomain: {vuln['subdomain']}\n")
            report.write(f"Provider: {vuln['provider']}\n")
            report.write(f"Status: {vuln['status']}\n")
            report.write(f"Reason: {vuln['reason']}\n")
            report.write("\n")
        
        # Dnsenum Section
        report.write("\nDnsenum Scan Results:\n")
        report.write("-"*20 + "\n")
        for subdomain in parsed_data['dnsenum']['subdomains']:
            report.write(f"{subdomain}\n")
        
        # Massdns Section
        report.write("\nMassdns Scan Results:\n")
        report.write("-"*20 + "\n")
        for sub in parsed_data['massdns']:
            report.write(f"{sub}\n")
        
        # Fierce Section
        report.write("\nFierce DNS Scan Results:\n")
        report.write("-"*20 + "\n")
        for subdomain in parsed_data['fierce']:
            report.write(f"{subdomain}\n")
        
        # Dmitry Section
        report.write("\nDmitry Information Gathering Results:\n")
        report.write("-"*20 + "\n")
        for key, values in parsed_data['dmitry'].items():
            report.write(f"{key.capitalize()}:\n")
            for value in values:
                report.write(f"- {value}\n")
            report.write("\n")
        
        # Certspotter Section
        report.write("\nCertspotter Scan Results:\n")
        report.write("-"*20 + "\n")
        for subdomain in parsed_data['certspotter']:
            report.write(f"{subdomain}\n")
        
        # Shodan Section
        report.write("\nShodan Scan Results:\n")
        report.write("-"*20 + "\n")
        shodan_data = parsed_data['shodan']
        if shodan_data:
            report.write(f"IP: {shodan_data.get('ip_str', 'N/A')}\n")
            report.write(f"Hostnames: {', '.join(shodan_data.get('hostnames', []))}\n")
            report.write(f"Country: {shodan_data.get('country_name', 'N/A')}\n")
            report.write("Open Ports and Services:\n")
            for service in shodan_data.get('services', []):
                report.write(f"- Port: {service['port']}\n")
                report.write(f"  Product: {service['product']}\n")
                report.write(f"  Version: {service['version']}\n")
                report.write(f"  Banner: {service['banner']}\n\n")
        else:
            report.write("Shodan results not available.\n")
        
        # Ffuf Section
        report.write("\nFfuf Directory Fuzzing Results:\n")
        report.write("-"*20 + "\n")
        for directory in parsed_data['ffuf']:
            report.write(f"{directory}\n")
        
    print(f"[+] Final Report Compiled: {output_files['report']}")

# ------------------------------ Main Function ------------------------------

def main():
    """
    The main function orchestrates the execution of all reconnaissance tools in parallel threads,
    parses their outputs, and compiles a comprehensive final report.
    """
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Script for Bug Bounty Hunting")
    parser.add_argument("-t", "--target", help="Target domain or IP address")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Path to Gobuster wordlist")
    parser.add_argument("-o", "--output", default="recon_results", help="Output directory")
    args = parser.parse_args()

    # Interactive Prompts for Rate Limiting and Scope Requirements
    print("=== Automated Reconnaissance Script ===\n")

    # Prompt for Target if not provided
    if not args.target:
        TARGET = input("Enter the target domain or IP address: ").strip()
    else:
        TARGET = args.target.strip()

    # Prompt for Rate Limiting
    print("\n--- Rate Limiting Configuration ---")
    rate_limit_input = input("Enter the desired rate limit (e.g., requests per second or delay in ms) or press Enter to skip: ").strip()
    if rate_limit_input:
        try:
            # Assuming the user inputs delay in milliseconds
            rate_limit = int(rate_limit_input)
        except ValueError:
            print("[!] Invalid rate limit input. Proceeding without rate limiting.")
            rate_limit = None
    else:
        rate_limit = None

    # Prompt for Scan Intensity
    print("\n--- Scan Intensity Configuration ---")
    intensity = input("Choose scan intensity (low/medium/high): ").strip().lower()
    if intensity == "low":
        timing_template = "T2"  # Slower scan
        threads = 20
        aggressive_scan = False
    elif intensity == "high":
        timing_template = "T5"  # Fastest scan
        threads = 100
        aggressive_scan = True
    else:
        timing_template = "T3"  # Default scan
        threads = 50
        aggressive_scan = True

    # Prompt for Tools Selection
    print("\n--- Tool Selection ---")
    tools = {
        "nmap": True,
        "nikto": True,
        "gobuster": True,
        "amass": True,
        "theharvester": True,
        "subfinder": True,
        "whatweb": True,
        "testssl": True,
        "eyewitness": True,
        "aquatone": True,
        "subjack": True,
        "dnsenum": True,
        "massdns": True,
        "fierce": True,
        "dmitry": True,
        "certspotter": True,
        "shodan": True,
        "ffuf": True
    }

    print("Select tools to include in the scan (comma-separated, e.g., nmap,nikto,amass). Press Enter to include all:")
    selected_tools = input("Tools: ").strip()
    if selected_tools:
        selected_tools = [tool.strip().lower() for tool in selected_tools.split(",")]
        for tool in tools.keys():
            tools[tool] = tool in selected_tools

    # Prompt for Shodan API Key
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY and tools.get("shodan", False):
        SHODAN_API_KEY = input("Enter your Shodan API key (leave blank to skip Shodan scan): ").strip()
        if not SHODAN_API_KEY:
            tools["shodan"] = False
            print("[!] Shodan API key not provided. Skipping Shodan scan.")

    # Setup Output Directory
    output_files = setup_output_directory(args.output)

    parsed_data = {
        "nmap": [],
        "nikto": [],
        "gobuster": [],
        "amass": [],
        "theharvester": [],
        "subfinder": [],
        "whatweb": [],
        "testssl": {},
        "eyewitness": [],
        "aquatone": [],
        "subjack": [],
        "dnsenum": [],
        "massdns": [],
        "fierce": [],
        "dmitry": [],
        "certspotter": [],
        "shodan": {},
        "ffuf": []
    }

    # Define threads for parallel execution
    threads = []

    # Nmap Thread
    if tools.get("nmap", False):
        def nmap_task():
            try:
                run_nmap(
                    TARGET,
                    output_files['nmap'],
                    output_files['nmap_log'],
                    rate_limit=timing_template,
                    aggressive=aggressive_scan,
                    ports="1-65535"
                )
                parsed_data['nmap'] = parse_nmap(output_files['nmap'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Nmap failed: {e}")

        threads.append(threading.Thread(target=nmap_task))

    # Nikto Thread
    if tools.get("nikto", False):
        def nikto_task():
            try:
                run_nikto(TARGET, output_files['nikto'], rate_limit=rate_limit)
                parsed_data['nikto'] = parse_nikto(output_files['nikto'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Nikto failed: {e}")

        threads.append(threading.Thread(target=nikto_task))

    # Gobuster Thread
    if tools.get("gobuster", False):
        def gobuster_task():
            try:
                run_gobuster(TARGET, output_files['gobuster'], args.wordlist, rate_limit=rate_limit)
                parsed_data['gobuster'] = parse_gobuster(output_files['gobuster'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Gobuster failed: {e}")

        threads.append(threading.Thread(target=gobuster_task))

    # Amass Thread
    if tools.get("amass", False):
        def amass_task():
            try:
                run_amass(TARGET, output_files['amass'], rate_limit=threads)
                parsed_data['amass'] = parse_amass(output_files['amass'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Amass failed: {e}")

        threads.append(threading.Thread(target=amass_task))

    # theHarvester Thread
    if tools.get("theharvester", False):
        def theharvester_task():
            try:
                run_theharvester(TARGET, output_files['theharvester'], rate_limit=rate_limit)
                parsed_data['theharvester'] = parse_theharvester(output_files['theharvester'])
            except subprocess.CalledProcessError as e:
                print(f"[!] theHarvester failed: {e}")

        threads.append(threading.Thread(target=theharvester_task))

    # Subfinder Thread
    if tools.get("subfinder", False):
        def subfinder_task():
            try:
                run_subfinder(TARGET, output_files['subfinder'], rate_limit=threads)
                parsed_data['subfinder'] = parse_subfinder(output_files['subfinder'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Subfinder failed: {e}")

        threads.append(threading.Thread(target=subfinder_task))

    # WhatWeb Thread
    if tools.get("whatweb", False):
        def whatweb_task():
            try:
                run_whatweb(TARGET, output_files['whatweb'], rate_limit=rate_limit)
                parsed_data['whatweb'] = parse_whatweb(output_files['whatweb'])
            except subprocess.CalledProcessError as e:
                print(f"[!] WhatWeb failed: {e}")

        threads.append(threading.Thread(target=whatweb_task))

    # Testssl.sh Thread
    if tools.get("testssl", False):
        def testssl_task():
            try:
                run_testssl(TARGET, output_files['testssl'], rate_limit=rate_limit)
                parsed_data['testssl'] = parse_testssl(output_files['testssl'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Testssl.sh failed: {e}")

        threads.append(threading.Thread(target=testssl_task))

    # EyeWitness Thread
    if tools.get("eyewitness", False):
        def eyewitness_task():
            try:
                run_eyewitness(TARGET, output_files['eyewitness'], rate_limit=rate_limit)
                parsed_data['eyewitness'] = parse_eyewitness(output_files['eyewitness'])
            except subprocess.CalledProcessError as e:
                print(f"[!] EyeWitness failed: {e}")

        threads.append(threading.Thread(target=eyewitness_task))

    # Aquatone Thread
    if tools.get("aquatone", False):
        def aquatone_task():
            try:
                run_aquatone(TARGET, output_files['aquatone'], rate_limit=rate_limit)
                parsed_data['aquatone'] = parse_aquatone(output_files['aquatone'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Aquatone failed: {e}")

        threads.append(threading.Thread(target=aquatone_task))

    # Subjack Thread
    if tools.get("subjack", False):
        def subjack_task():
            try:
                run_subjack(TARGET, output_files['subjack'], rate_limit=threads)
                parsed_data['subjack'] = parse_subjack(output_files['subjack'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Subjack failed: {e}")

        threads.append(threading.Thread(target=subjack_task))

    # Dnsenum Thread
    if tools.get("dnsenum", False):
        def dnsenum_task():
            try:
                run_dnsenum(TARGET, output_files['dnsenum'], rate_limit=rate_limit)
                parsed_data['dnsenum'] = parse_dnsenum(output_files['dnsenum'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Dnsenum failed: {e}")

        threads.append(threading.Thread(target=dnsenum_task))

    # Massdns Thread
    if tools.get("massdns", False):
        def massdns_task():
            try:
                run_massdns("all_subdomains.txt", output_files['massdns'], resolvers_file="/path/to/resolvers.txt", rate_limit=threads)
                parsed_data['massdns'] = parse_massdns(output_files['massdns'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Massdns failed: {e}")

        threads.append(threading.Thread(target=massdns_task))

    # Fierce Thread
    if tools.get("fierce", False):
        def fierce_task():
            try:
                run_fierce(TARGET, output_files['fierce'], rate_limit=rate_limit)
                parsed_data['fierce'] = parse_fierce(output_files['fierce'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Fierce failed: {e}")

        threads.append(threading.Thread(target=fierce_task))

    # Dmitry Thread
    if tools.get("dmitry", False):
        def dmitry_task():
            try:
                run_dmitry(TARGET, output_files['dmitry'], rate_limit=rate_limit)
                parsed_data['dmitry'] = parse_dmitry(output_files['dmitry'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Dmitry failed: {e}")

        threads.append(threading.Thread(target=dmitry_task))

    # Certspotter Thread
    if tools.get("certspotter", False):
        def certspotter_task():
            try:
                run_certspotter(TARGET, output_files['certspotter'], rate_limit=rate_limit)
                parsed_data['certspotter'] = parse_certspotter(output_files['certspotter'])
            except Exception as e:
                print(f"[!] Certspotter failed: {e}")

        threads.append(threading.Thread(target=certspotter_task))

    # Shodan Thread
    if tools.get("shodan", False):
        def shodan_task():
            if shodan_enabled:
                try:
                    run_shodan(SHODAN_API_KEY, TARGET, output_files['shodan'], rate_limit=rate_limit)
                    parsed_data['shodan'] = parse_shodan(output_files['shodan'])
                except Exception as e:
                    print(f"[!] Shodan failed: {e}")
            else:
                print("[!] Skipping Shodan scan as API key is not provided.")
        
        threads.append(threading.Thread(target=shodan_task))

    # Ffuf Thread
    if tools.get("ffuf", False):
        def ffuf_task():
            try:
                run_ffuf(TARGET, output_files['ffuf'], args.wordlist, rate_limit=rate_limit)
                parsed_data['ffuf'] = parse_ffuf(output_files['ffuf'])
            except subprocess.CalledProcessError as e:
                print(f"[!] Ffuf failed: {e}")

        threads.append(threading.Thread(target=ffuf_task))

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Collect all subdomains for Massdns
    if tools.get("massdns", False):
        collect_all_subdomains(parsed_data, "all_subdomains.txt")

    # Compile Report
    compile_report(output_files, parsed_data)
    print("[+] Reconnaissance Phase Completed Successfully.")

def collect_all_subdomains(parsed_data, file_path="all_subdomains.txt"):
    """
    Collects all discovered subdomains from various tools and writes them to a file for Massdns processing.

    Args:
        parsed_data (dict): A dictionary containing parsed data from each tool.
        file_path (str): The file path to save the collected subdomains.

    Returns:
        None
    """
    print("[*] Collecting all discovered subdomains for Massdns...")
    subdomains = set()
    tools_with_subdomains = ['amass', 'subfinder', 'dnsenum', 'fierce', 'certspotter']
    for tool in tools_with_subdomains:
        data = parsed_data.get(tool, [])
        if isinstance(data, list):
            subdomains.update(data)
        elif isinstance(data, dict):
            subdomains.update(data.get('subdomains', []))
    # Write to file
    with open(file_path, 'w') as f:
        for sub in subdomains:
            f.write(f"{sub}\n")
    print("[+] Subdomains collected and written to all_subdomains.txt")

# ------------------------------ Script Execution ------------------------------

if __name__ == "__main__":
    main()
