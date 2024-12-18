# Reconamate

**Reconamate** is a comprehensive, automated reconnaissance tool designed for bug bounty hunters and penetration testers. It integrates multiple industry-standard reconnaissance tools to provide a holistic view of a target's attack surface. By automating the reconnaissance phase, Reconamate streamlines the initial steps of vulnerability assessment, enabling security professionals to focus on analysis and remediation.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [1. Clone the Repository](#1-clone-the-repository)
  - [2. Run the Installation Script](#2-run-the-installation-script)
- [Configuration](#configuration)
  - [Setting Up Environment Variables](#setting-up-environment-variables)
- [Usage](#usage)
  - [Running Reconamate](#running-reconomate)
  - [Interactive Prompts](#interactive-prompts)
- [Output](#output)
  - [Report](#report)
  - [Individual Tool Outputs](#individual-tool-outputs)
- [Integrated Tools](#integrated-tools)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Features

- **Parallel Execution:** Runs multiple reconnaissance tools concurrently to save time.
- **Rate Limiting:** Allows configuration of scan intensity to comply with target policies.
- **Tool Selection:** Users can choose which tools to include in the scan based on their requirements.
- **Comprehensive Reporting:** Compiles findings from all tools into a structured, readable report.
- **Modular Design:** Easily extendable to incorporate additional tools or functionalities.

## Prerequisites

Before installing Reconamate, ensure that your system meets the following requirements:

- **Operating System:** Ubuntu/Debian-based Linux distribution.
- **Permissions:** `sudo` privileges for installing packages and tools.
- **Internet Connection:** Required for downloading tools and dependencies.
- **Go Programming Language:** Required for installing Go-based tools.
- **Python 3:** Required for running Python-based tools and scripts.

## Installation

Follow the steps below to install Reconamate and all its dependencies.

### 1. Clone the Repository

Begin by cloning the Reconamate repository to your local machine:

```bash
git clone https://github.com/CBMW/PenTools/Reconamate/Reconamate.git
cd Reconamate
```

### 2. Run the Installation Script

Reconamate provides an installation script, `ReconamateInstall.sh`, which automates the installation of all required tools and dependencies.

1. **Make the Script Executable:**

   ```bash
   chmod +x ReconamateInstall.sh
   ```

2. **Execute the Script:**

   ```bash
   ./ReconamateInstall.sh
   ```

The script performs the following actions:

- Updates the package list.
- Installs essential packages via apt-get.
- Sets up the Go environment.
- Installs Go-based tools such as Subfinder, Aquatone, Subjack, and FFUF.
- Installs additional tools like MassDNS, Testssl.sh, EyeWitness.
- Installs Python modules required for Reconamate.
- Downloads DNS resolvers for MassDNS.

**Note:** Some installations may take several minutes depending on your system's performance and internet speed. Ensure you have an active internet connection throughout the process.

## Configuration

### Setting Up Environment Variables

After installation, configure necessary environment variables to ensure all tools function correctly.

1. **Go Environment:**

   The installation script appends Go-related environment variables to your `~/.bashrc`. To apply the changes immediately, run:

   ```bash
   source ~/.bashrc
   ```

2. **Shodan API Key:**

   Reconamate integrates Shodan for advanced reconnaissance. To utilize Shodan's capabilities:

   - **Obtain Shodan API Key:** Register at Shodan to receive your API key.

   - **Set Environment Variable:**

     ```bash
     export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"
     ```

   - **Make it Permanent:** Add the above line to your `~/.bashrc`:

     ```bash
     echo 'export SHODAN_API_KEY="YOUR_SHODAN_API_KEY"' >> ~/.bashrc
     source ~/.bashrc
     ```

   Replace `YOUR_SHODAN_API_KEY` with your actual Shodan API key.

## Usage

Reconamate is designed to be user-friendly, providing interactive prompts to customize your reconnaissance scans based on specific requirements.

### Running Reconamate

To initiate a reconnaissance scan, execute the `Reconamate.py` script:

```bash
python3 Reconamate.py
```

Ensure you are in the directory containing `Reconamate.py` or provide the full path to the script.

### Interactive Prompts

Upon execution, Reconamate will prompt you for various configurations:

1. **Target Specification:**

   - **Prompt:** `Enter the target domain or IP address:`
   - **Description:** Specify the domain or IP address you intend to scan.

2. **Rate Limiting Configuration:**

   - **Prompt:** `Enter the desired rate limit (e.g., delay in ms between requests) or press Enter to skip:`
   - **Description:** Define a delay between requests to control the intensity of scans, ensuring compliance with target policies and avoiding detection.

3. **Scan Intensity Configuration:**

   - **Prompt:** `Choose scan intensity (low/medium/high):`
   - **Description:** Select the desired scan intensity.

4. **Tool Selection:**

   - **Prompt:** `Select tools to include in the scan (comma-separated, e.g., nmap,nikto,amass). Press Enter to include all:`
   - **Description:** Choose which reconnaissance tools to include.

5. **Shodan API Key (if not set as environment variable):**

   - **Prompt:** `Enter your Shodan API key (leave blank to skip Shodan scan):`
   - **Description:** Provide your Shodan API key to enable Shodan-based reconnaissance.

## Output

Reconamate organizes its findings into structured output files and a comprehensive final report.

### Report

- **Location:** Specified output directory (default: `recon_results`).
- **Filename:** `final_report_YYYYMMDD_HHMMSS.txt` (timestamped for uniqueness).
- **Contents:**
  - Aggregated findings from all selected tools.
  - Structured sections detailing results from each tool, such as open ports, discovered subdomains, detected technologies, vulnerabilities, screenshots, etc.

### Individual Tool Outputs

Reconamate saves individual tool outputs in the specified output directory for reference and further analysis. Examples include:

- **Nmap:** `nmap_output_YYYYMMDD_HHMMSS.xml`
- **Nikto:** `nikto_output_YYYYMMDD_HHMMSS.txt`
- **Gobuster:** `gobuster_output_YYYYMMDD_HHMMSS.txt`
- **Amass:** `amass_output_YYYYMMDD_HHMMSS.txt`
- **EyeWitness:** `eyewitness_output_YYYYMMDD_HHMMSS.txt`
- **Aquatone:** `aquatone_output_YYYYMMDD_HHMMSS.txt`

## Integrated Tools

Reconamate integrates a suite of reconnaissance tools to provide a comprehensive assessment of the target. Below is a list of the tools included:

- **Nmap:** Network exploration and security auditing.
- **Nikto:** Web server scanner for vulnerabilities.
- **Gobuster:** Directory and file brute-forcing tool.
- **Amass:** Subdomain enumeration and attack surface mapping.
- **theHarvester:** Email and subdomain gathering using OSINT.
- **Subfinder:** Subdomain discovery tool.
- **WhatWeb:** Web technology fingerprinting tool.
- **Testssl.sh:** SSL/TLS scanning tool.
- **EyeWitness:** Captures screenshots of web services.
- **Aquatone:** Subdomain screenshotting and HTTP enumeration.
- **Subjack:** Detects potential subdomain takeovers.

## License

Reconamate is released under the [MIT License](LICENSE). You are free to use, modify, and distribute this software in accordance with the terms of the license.

## Support

For support, questions, or issues, please open an [issue](https://github.com/CBMW/PenTools/Reconamate/issues) on the Reconamate GitHub repository.

---

**Disclaimer:** Reconamate is intended for authorized security assessments and penetration testing only. Unauthorized use of this tool is strictly prohibited and may be unlawful.

