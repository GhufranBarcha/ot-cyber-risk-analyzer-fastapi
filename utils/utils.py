import json
import pandas as pd



def read_predefined_rules(path = "/home/ghufranbarcha/Desktop/Freelance Task/CyberAI_Analysis/api/data/predefined roles.csv"):
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
    
    