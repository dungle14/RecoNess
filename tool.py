import subprocess
import json
import requests
import datetime
import socket
from urllib.parse import urlparse
import re

print(" _____                _   _")
print("|  __ \\              | \\ | |")
print("| |__) |___  ___ ___ |  \\| | ___  ___ ___")
print("|  _  // _ \\/ __/ _ \\| . ` |/ _ \\/ __/ __|")
print("| | \\ \\  __/ (_| (_) | |\\  |  __/\\__ \\__ \\")
print("|_|  \\_\\___|\\___\\___/|_| \\_|\\___||___/___/")
print("\n")
print("__________________________________________")
print("Welcome to RecoNess tool, this is a recon tool which helps you automate recon process and improve testing efficiency!")
print("Usage: $ python tool.py")
auto = input("Do you want to automatically scan your target? (yes/no): ")

def remove_ansi_escape_sequences(text):
    ansi_escape_pattern = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    return ansi_escape_pattern.sub('', text)

def generate_filename(tool, target):
    # Normalize the target to create a valid filename
    # Replace protocol prefixes (http://, https://) with 'http_' or 'https_', and dots with underscores
    normalized_target = target.replace('http://', 'http_').replace('https://', 'https_').replace('.', '_')
    
    # Replace slashes with underscores to ensure a valid filename
    normalized_target = normalized_target.replace('/', '_')
    
    # Construct the filename using the tool name and the normalized target
    filename = f"{tool}_{normalized_target}.txt"
    return filename

def parse_url(target):
    # Use urlparse to parse the target URL
    parsed = urlparse(target)
    # Check if the parsed URL has both a scheme and a network location (netloc)
    if parsed.scheme and parsed.netloc:
        return "URL"  # Return "URL" if both components are present
    return None  # Return None if either component is missing

def is_ip_address(target):
    try:
        # Attempt to convert the target into an IPv4 address
        socket.inet_aton(target)
        return True  # Return True if conversion is successful
    except socket.error:
        return False  # Return False if conversion fails

def print_file(filename):
    with open(filename, 'r') as file:
        for line in file:
            print(line, end='')
def search_cve(filename, keyword):
    with open(filename, 'r') as f:
        data = json.load(f)
    for vuln in data['vulnerabilities']:
        descriptions = vuln['cve']['descriptions']
        for desc in descriptions:
            if keyword.lower() in desc['value'].lower():
                print(f"CVE ID: {vuln['cve']['id']}")
                print(f"Description: {desc['value']}\n")
def print_cve_details(cve_data):
    # Extract the first vulnerability's CVE details from the provided data
    vuln = cve_data['vulnerabilities'][0]['cve']

    # Print the descriptions associated with the CVE, if any
    if 'descriptions' in vuln:
        print("Descriptions:")
        for desc in vuln['descriptions']:
            # Print each description's language and text
            print(f"  Language: {desc['lang']}")
            print(f"  Value: {desc['value']}")

    # Print the references for the CVE, if any are provided
    if 'references' in vuln:
        print("References:")
        for ref in vuln['references']:
            # Print each reference's URL, source, and associated tags
            print(f"  URL: {ref['url']}")
            print(f"  Source: {ref['source']}")
            print(f"  Tags: {', '.join(ref['tags'])}")  # Join tags with commas for readability

    # Print CVSS metrics for the CVE, if available
    if 'metrics' in vuln and 'cvssMetricV31' in vuln['metrics']:
        print("Metrics:")
        for metric in vuln['metrics']['cvssMetricV31']:
            # Print the source, type, and CVSS data for each metric
            print(f"  Source: {metric['source']}")
            print(f"  Type: {metric['type']}")
            print(f"  CVSS Data: {metric['cvssData']}")

    # Print other CVE details such as ID, publication date, and last modification date
    if 'id' in vuln:
        print(f"CVE ID: {vuln['id']}")
    if 'sourceIdentifier' in vuln:
        print(f"Source Identifier: {vuln['sourceIdentifier']}")
    if 'published' in vuln:
        print(f"Published: {vuln['published']}")
    if 'lastModified' in vuln:
        print(f"Last Modified: {vuln['lastModified']}")
    if 'vulnStatus' in vuln:
        print(f"Vulnerability Status: {vuln['vulnStatus']}")

    # Print information on any weaknesses associated with the CVE
    if 'weaknesses' in vuln:
        print("Weaknesses:")
        for weakness in vuln['weaknesses']:
            # Print the source, type, and description for each weakness
            print(f"  Source: {weakness['source']}")
            print(f"  Type: {weakness['type']}")
            print(f"  Description: {weakness['description']}")
            
        # Check if the 'configurations' key exists in the vulnerability data
    if 'configurations' in vuln:
        print("Configurations:")
        # Iterate through each configuration associated with the vulnerability
        for config in vuln['configurations']:
            # Print the nodes involved in this configuration
            print(f"  Nodes: {config['nodes']}")

if auto.lower() == 'yes':
    target = input("Enter your target (URL/domain/IP): ")
    if parse_url(target) == "URL":
        print(f"{target} is a URL so you can only use these tools: ffuf, Dirsearch, Arjun, Whatweb.")
        print("Scanning the target...")
        print("Running ffuf scan...")
        filename = generate_filename("ffuf", target)
        
                # Further processing for URL...
        if target.startswith("http://"):
            modified_target = target.replace("http://", "http://FUZZ.")
        elif target.startswith("https://"):
            modified_target = target.replace("https://", "https://FUZZ.")
        else:
            # Default to http if no protocol is specified
            modified_target = "http://FUZZ." + target
        command = ["sudo","ffuf", "-u", modified_target, "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-t", "50", "-mc", "200", "-fc", "301", "-of", "csv"]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
        with open(filename, 'w') as file:
            file.write(result.stdout)
        print(f"ffuf result saved to {filename}")
        print("Running dirsearch scan...")
        filename = generate_filename("dirsearch", target)
        command = ["dirsearch", "-u", target, "-e", "php,html,js,css,txt", "-t", "50"]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
        with open(filename, 'w') as file:
            file.write(result.stdout)
        print(f"dirsearch result saved to {filename}")
        print("Running arjun scan...")
        filename = generate_filename("arjun", target)
        command = ["arjun", "-u", target]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
        print(result.stdout)
        with open(filename, 'w') as file:
            file.write(result.stdout)
        print(f"arjun result saved to {filename}")
        print("Running whatweb scan...")
        filename = generate_filename("whatweb", target)
        command = ["whatweb", target]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
        clean_output = remove_ansi_escape_sequences(result.stdout)  # Clean the output
        with open(filename, 'w') as file:
            file.write(clean_output)
        print(f"whatweb result saved to {filename}")
    elif is_ip_address(target):
        print(f"{target} is an IP address so you can only use these tools: Nmap, Whatweb.")
        print("Scanning the target...")
        print("Running nmap scan...")
        filename = generate_filename("nmap", target)
        command = ["sudo", "nmap", "-O", "-sS", "-sV", target, "-v"]
        result = subprocess.run(command, capture_output=True, text=True)    
        print(result.stdout)
        with open(filename, 'w') as file:
            file.write(result.stdout)
        print(f"nmap result saved to {filename}")
        print("Running whatweb scan...")
        filename = generate_filename("whatweb", target)
        command = ["whatweb", target]
        result = subprocess.run(command, capture_output=True, text=True)
        print(result.stdout)
        clean_output = remove_ansi_escape_sequences(result.stdout)  # Clean the output
        with open(filename, 'w') as file:
            file.write(clean_output)
        print(f"whatweb result saved to {filename}") 
    else:
        print(f"{target} is a domain name so you can only use these tools: Nmap, Whatweb")
        print("Scanning the target...")
        print("Running nmap scan...")
        filename = generate_filename("nmap", target)
        command = ["sudo", "nmap", "-O", "-sS", "-sV", target, "-v"]
        result = subprocess.run(command, capture_output=True, text=True)
        with open(filename, 'w') as file:
            file.write(result.stdout)
        print(f"nmap result saved to {filename}")
        print("Running whatweb scan...")
        filename = generate_filename("whatweb", target)
        command = ["whatweb", target]
        result = subprocess.run(command, capture_output=True, text=True)
        clean_output = remove_ansi_escape_sequences(result.stdout)  # Clean the output
        with open(filename, 'w') as file:
            file.write(clean_output)
        print(f"whatweb result saved to {filename}")

elif auto == "no":
    while True:
        command = input("Enter the command you want to run (enter help for more information): ")
        if command.lower() == "help":
            print("Command:")
            print("\tping: To check the connectivity of the IP address")
            print("\tffuf: To run ffuf scan on the URL (Scanning for subdomains)")
            print("\tdirsearch: To run dirsearch scan on the URL (Scanning for directories)")
            print("\tnmap: To run nmap scan on the IP address (Scanning for ports, OS, services)")
            print("\tarjun: To run arjun scan on the URL (Scanning for hidden parameters)")
            print("\twhatweb: To run whatweb scan on the URL (Scanning for web technologies)")
            print("\tcvesearch: To search for CVEs in the NVD database")
            print("\texit: To exit the tool")

        elif command.lower() == "ping":
            ip = input("Enter the IP address: ")
            subprocess.run(["ping", "-c", "4", ip])
        elif command.lower() == "ffuf":
            url = input("Enter the URL: ")
            wordlist = input("Enter the wordlist path: ")
            flags = []
            while True:
                flag = input("Enter a flag you want to use (-h for more, or 'done' when finished): ")
                if flag == "-h":
                    print_file('ffuf.txt')
                elif flag.lower() == 'done':
                    break
                else:
                    flags.append(flag)
            subprocess.run(["ffuf", "-u", url, "-w", wordlist, *flags]) 
        elif command.lower() == "dirsearch":
            url = input("Enter the URL: ")
            flags = []
            while True:
                flag = input("Enter a flag you want to use (-h for more, or 'done' when finished): ")
                if flag == "-h":
                    print_file('dirsearch.txt')
                elif flag.lower() == 'done':
                    break
                else:
                    flags.append(flag)
            subprocess.run(["dirsearch", "-u", url, *flags])
        elif command.lower() == "nmap":
            ip = input("Enter the IP address or domain name: ")
            flags = []
            while True:
                flag = input("Enter a flag you want to use (-h for more, or 'done' when finished): ")
                if flag == "-h":
                    print_file('nmap.txt')
                elif flag.lower() == 'done':
                    break
                else:
                    flags.append(flag)
            sudo_required_flags = ["-sS", "-O", "-sU", "-sA", "-sW", "-sM", "-sN", "-sF", "-sX", "-sI", "-sY", "-sZ", "-sO"]
            for flag in flags:
                if flag in sudo_required_flags:
                    subprocess.run(["sudo", "nmap", flag, ip])
                else:
                    subprocess.run(["nmap", flag, ip])
        elif command.lower() == "arjun":
            url = input("Enter the URL: ")
            flags = []
            while True:
                flag = input("Enter a flag you want to use (-h for more, or 'done' when finished): ")
                if flag == "-h":
                    print_file('arjun.txt')  # Assuming this function prints help from a file named arjun.txt
                elif flag.lower() == 'done':
                    break
                else:
                    flags.append(flag)
            subprocess.run(["arjun", "-u", url, *flags])
        elif command.lower() == "whatweb":
            url = input("Enter the URL, IP address or domain name: ")
            flags = []
            while True:
                flag = input("Enter a flag you want to use (-h for more, or 'done' when finished): ")
                if flag == "-h":
                    print_file('whatweb.txt')
                elif flag.lower() == 'done':
                    break
                else:
                    flags.append(flag)
            subprocess.run(["whatweb", url, *flags])
        elif command.lower() == "cvesearch":
            keyword = input("Enter keyword for the CVE you want to search: ")
            url_keyword = "https://services.nvd.nist.gov/rest/json/cves/2.0/?keywordSearch={}".format(keyword)
            keyword_response = requests.get(url_keyword)
            data = keyword_response.json()
            with open('test', 'w') as f:
                json.dump(data, f)
            search_cve('test', keyword)

            id = input("Enter id of the CVE you want to search:")
            url_id = "https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId={}".format(id)
            id_response = requests.get(url_id)
            data = id_response.json()
            with open('test2', 'w') as f:
                json.dump(data, f)

            # Call the function with the CVE data
            print_cve_details(data)
        elif command.lower() == "exit":
            break
        else:
            print("Invalid command. Please try again.")
        
