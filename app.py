from flask import Flask, render_template, request
import requests
import json

app = Flask(__name__)

def fetch_cve_data(keywords):
    keywords_str = ' '.join(keywords)
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={keywords_str}"
    print(f"API URL: {api_url}")  # Debug statement
    response = requests.get(api_url)
    if response.status_code == 200:
        data = response.json()
        print("API Response JSON:", json.dumps(data, indent=2))  # Print the raw JSON response
        return data
    else:
        print(f"Failed to fetch data. Status code: {response.status_code}")  # Debug statement
        return None

def match_cpe(software_name, software_version, cpe_criteria):
    cpe_parts = cpe_criteria.split(':')
    if len(cpe_parts) >= 7:
        cpe_name = cpe_parts[3]
        cpe_version = cpe_parts[4]
        if cpe_name.lower() == software_name.lower():
            if cpe_version == '*' or cpe_version == software_version:
                return True
            elif cpe_version == '*' and software_version:
                return True
    return False

def get_impact_score(cve):
    metrics = cve.get('metrics', {}).get('cvssMetricV31', [])
    if metrics:
        score = metrics[0].get('cvssData', {}).get('baseScore', 0)
        return score
    return 0

def software_check(software_list, cve_data):
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
        keywords = request.form.get('keywords').split()  # Split input keywords by spaces
        print(f"Keywords: {keywords}")  # Debug statement
        cve_data = fetch_cve_data(keywords)
        if cve_data:
            software_list = [('windows', ''), ('macos', ''), ('debian', '')]
            applicable_cves = software_check(software_list, cve_data)
            return render_template('results.html', cves=applicable_cves, keywords=' '.join(keywords))
        else:
            return "Failed to fetch CVE data", 500

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
