import json
import requests

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
    vuln = cve_data['vulnerabilities'][0]['cve']

    # Print description
    if 'descriptions' in vuln:
        print("Descriptions:")
        for desc in vuln['descriptions']:
            if desc['lang'].lower() == 'en':
                print(f"  Language: {desc['lang']}")
                print(f"  Value: {desc['value']}")
    # Print references
    if 'references' in vuln:
        print("References:")
        for ref in vuln['references']:
            print(f"  URL: {ref['url']}")
            print(f"  Source: {ref['source']}")
            print(f"  Tags: {ref['tags']}")

    # Print CVSS metrics
    if 'metrics' in vuln and 'cvssMetricV31' in vuln['metrics']:
        print("Metrics:")
        for metric in vuln['metrics']['cvssMetricV31']:
            print(f"  Source: {metric['source']}")
            print(f"  Type: {metric['type']}")
            print(f"  CVSS Data: {metric['cvssData']}")

    # Print other details
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

    if 'weaknesses' in vuln:
        print("Weaknesses:")
        for weakness in vuln['weaknesses']:
            print(f"  Source: {weakness['source']}")
            print(f"  Type: {weakness['type']}")
            print(f"  Description: {weakness['description']}")

    if 'configurations' in vuln:
        print("Configurations:")
        for config in vuln['configurations']:
            print(f"  Nodes: {config['nodes']}")

keyquot = input("Enter keyaoeu: ")
url_keyword = "https://services.nvd.nist.gov/rest/json/cves/2.0/?keywordSearch={}".format(keyquot)
keyword_response = requests.get(url_keyword)
data = keyword_response.json()
with open('test', 'w') as f:
    json.dump(data, f)
search_cve('test', keyquot)

id = input("Enter id:")
url_id = "https://services.nvd.nist.gov/rest/json/cves/2.0/?cveId={}".format(id)
id_response = requests.get(url_id)
data = id_response.json()
with open('test2', 'w') as f:
    json.dump(data, f)

# Call the function with the CVE data
print_cve_details(data)