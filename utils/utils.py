import json
import requests
import pandas as pd


def read_predefined_rules(path="/home/ghufranbarcha/Desktop/Freelance Task/CyberAI_Analysis/api/data/predefined roles.csv"):
    """Will read the predefined rule and create a formated string for LLM

    Args:
        path (str, optional): _description_. Defaults to "/home/ghufranbarcha/Desktop/Freelance Task/CyberAI_Analysis/api/data/predefined roles.csv".

    Returns:
        _type_: _str
    """
    df = pd.read_csv(path)
    df.columns = ["asset_criticality", "safety_impact", "vulnerability_severity", "hosting", "risk_level"]
    data_list = df.to_dict(orient="records")
    json_str = ",\n".join(json.dumps(entry) for entry in data_list)
    return json_str


def get_security_description(cve_id, api_keys):
    """
    Fetch the security description for a given CVE ID.
    Loops through the provided list of API keys and returns the description from the first key that yields a result.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cve_id = cve_id.replace(" ", "").strip()
    url = f"{base_url}?cveId={cve_id}"

    for api_key in api_keys:
        headers = {"apiKey": api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data.get('totalResults', 0) > 0:
                cve_data = data['vulnerabilities'][0]['cve']
                description = cve_data['descriptions'][0]['value']
                return description
    # If all API keys fail to return a description, return None.
    return None