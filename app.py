from flask import Flask, render_template, request
import requests
import json

app = Flask(__name__)

def fetch_cpe_data(software_name, version=None):
    """
    Fetch CPE data from the NVD API based on software name and version.
    """
    cpe_match_string = f"cpe:2.3:*:*:{software_name.lower()}"

    if version:
        cpe_match_string += f":{version}"
    else:
        cpe_match_string += ":*"

    cpe_api_url = f"https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString={cpe_match_string}"

    print(f"CPE API URL: {cpe_api_url}")  # Debug statement

    response = requests.get(cpe_api_url)
    if response.status_code == 200:
        cpe_data = response.json()
        print("CPE API Response JSON:", json.dumps(cpe_data, indent=2))  # Debugging
        return cpe_data.get('products', [])
    else:
        print(f"Failed to fetch CPE data. Status code: {response.status_code}")  # Debug statement
    return None

def fetch_cve_data(cpe_uri):
    """
    Fetch CVE data from the NVD API based on a CPE URI.
    """
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_uri}"

    print(f"CVE API URL: {api_url}")  # Debug statement

    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        print("CVE API Response JSON:", json.dumps(data, indent=2))  # Debugging
        return data
    else:
        print(f"Failed to fetch data. Status code: {response.status_code}")  # Debug statement
        return None

def get_impact_score(cve):
    """
    Extract the CVSS impact score from the CVE data.
    """
    metrics = cve.get('metrics', {}).get('cvssMetricV31', [])
    if metrics:
        score = metrics[0].get('cvssData', {}).get('baseScore', 0)
        return score
    return 0

def software_check(software_list, cve_data):
    """
    Match the CVE data with the provided software list and return applicable CVEs.
    """
    applicable_cves = []

    for software_name, software_version in software_list:
        for item in cve_data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'N/A')
            published = cve.get('published', 'N/A')
            last_modified = cve.get('lastModified', 'N/A')
            impact_score = get_impact_score(cve)
            
            applicable_cves.append({
                'id': cve_id,
                'published': published,
                'last_modified': last_modified,
                'impact_score': impact_score
            })

    return applicable_cves

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        software_input = request.form.get('software')
        parts = software_input.split(maxsplit=1)
        if len(parts) < 1:
            return "Error: Please provide software name and optionally a version", 400

        software_name = parts[0]
        version = parts[1] if len(parts) > 1 else None
        print(f"Software Name: {software_name}, Version: {version}")  # Debug statement

        cpe_data = fetch_cpe_data(software_name, version)
        if cpe_data:
            applicable_cves = []
            for product in cpe_data:
                cpe_uri = product.get('cpe', {}).get('cpeName')
                print(f"Found CPE: {cpe_uri}")  # Debugging

                if cpe_uri:
                    cve_data = fetch_cve_data(cpe_uri)
                    if cve_data:
                        software_list = [(software_name, version)]
                        applicable_cves.extend(software_check(software_list, cve_data))
            
            return render_template('results.html', cves=applicable_cves, keywords=software_input)
        else:
            return "Failed to fetch CPE data", 500

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
