from langchain_core.prompts import ChatPromptTemplate
from langchain.chat_models import init_chat_model


class LLMParser:
    def __init__(self, model_name = "deepseek-r1-distill-llama-70b", model_provider = "groq"):
        self.model = init_chat_model(model_name, model_provider=model_provider).with_structured_output(method="json_mode")
    
    
    def risk_analyzer(self, merge_df, rule_str):
        columns = ["Classification", "\tSafety Impact", "Vulnerability Severity", "Hosting1"]
        df = merge_df[columns]
        text_input = ""

        for index, row in df.iterrows():
            text_input += f"\n{index}. Asset Criticality: {row.iloc[0]}, Safety Impact: {row.iloc[1]}, Vulnerability Severity: {row.iloc[2]}, Hosting: {row.iloc[3]}"
  
        system_template = """
        # System Prompt: OT Cybersecurity Risk Level Assessor

        ## Role:
        You are an AI assistant specialized in Operational Technology (OT) Cybersecurity risk assessment. Your sole purpose is to determine the 'Risk Level' based on a predefined, hardcoded set of rules.

        ## Task:
        Given list containing multiple four input parameters ('Asset Criticality', 'Safety Impact', 'Vulnerability Severity', 'Hosting'), you must determine the corresponding 'Risk Level' for each parameter by strictly following the hardcoded rules provided below.

        ## Input Parameters:
        You will receive the following four string inputs:
        1.  `asset_criticality`: (e.g., "Low", "Medium", "High", "Critical")
        2.  `safety_impact`: (e.g., "Low", "Medium", "High")
        3.  `vulnerability_severity`: (e.g., "Low", "Medium", "High", "Critical")
        4.  `hosting`: (e.g., "Isolated" and Anything, Anything means both Isolated as well as others)

        ## Hardcoded Rules:
        You MUST use the following list of rules, represented as dictionaries. This is your complete knowledge base for determining the Risk Level.
        #### Rules start here:

        {json_str}

        #### Rules end here:


        ## Logic for Determining Risk Level:

            Exact Match: Compare the input parameters (asset_criticality, safety_impact, vulnerability_severity, hosting) against each rule in the rules list.

                If a rule matches exactly on all four input parameters, return the risk_level from that rule

            Most Similar Match (If No Exact Match):

                If no exact match is found, iterate through the rules select the most similar.

        ## Output Format:

        Return ONLY a valid JSON object containing:

            risk_level: The determined risk level string (e.g., "Low", "Medium", "High", "Isolated", "Critical").


        ## Example Output:


        {{
            "risk_level1": "Medium",
            "risk_level2": "Low",
            ...
        }}


        """


        user_template = """
        Please determine the Risk Level for the following sets of OT Cybersecurity parameters based on the rules defined in the system prompt. Generate a JSON output with keys 'risk_level1', 'risk_level2', etc., corresponding to each input set below:

        ## Input Sets Start Here:
        {text_input}
        ## Input Sets End Here:


        """
    
        prompt_template = ChatPromptTemplate.from_messages(
            [("system", system_template), ("user", user_template)]
        )
        prompt = prompt_template.invoke({"json_str": rule_str, "text_input": text_input})
        response = self.model.invoke(prompt)
        predefined_severity = [res for res in response.values()]
        merge_df["Predefined Severity"] = predefined_severity
        return merge_df   
    
    
    
    def refine_risk_level(self, merge_df):
        columns = [ "Predefined Severity", "Note" ,"security_description"]
        df = merge_df[columns]
        text_input = ""

        for index, row in df.iterrows():
            text_input += f"\n{index}. CVE Description from the API: {row.iloc[2]},    Asset Classification Note: {row.iloc[1]},    Predefined Severity: {row.iloc[0]},"        
        
        system_prompt = """
        ## Role:
        You are an expert OT Cybersecurity Analyst specializing in vulnerability assessment and risk classification for Operational Technology (OT) assets.

        ## Task:
        Evaluate the severity of a detected vulnerability (`CVE Description`) in the context of a specific OT asset (`Asset Classification Note`). Your goal is to determine the most appropriate risk level while reducing false positives.

        ## Input Parameters:
        You will receive the following inputs:

        1. CVE Description:
        - A detailed technical description of the vulnerability, its mechanism, and potential impact (from sources like NIST NVD or VulDB).

        2. Asset Classification Note:
        - Contextual information about the asset, including its function, connectivity, hosting environment, criticality, and existing security controls.

        3. Predefined Severity (From Rule-Based Method):
        - A predefined severity rating derived from rule-based calculations using asset criticality, safety impact, and hosting classification.

        ## Assessment Process:

        1. Impact Analysis (Based on CVE Description)
        - Determine the potential technical impact (e.g., remote code execution, privilege escalation, denial of service).
        - Assess exploitability, including prerequisites and attack complexity.
        - Identify whether the vulnerability has known exploits.

        2. Asset Context (Based on Asset Classification Note)
        - Determine if the asset is critical (e.g., safety systems, real-time controllers, high business impact).
        - Identify network exposure (e.g., isolated, air-gapped, internet-facing).
        - Consider existing mitigations (e.g., strict firewall rules, limited access, monitoring controls).

        3. Severity Adjustment (Using Predefined Severity)
        - If predefined severity is already high, confirm if the LLM’s analysis supports it or suggests a lower severity based on mitigations.
        - If predefined severity is moderate or low, escalate severity only if exploitability or asset sensitivity suggests a higher risk.
        - Ensure false positives are minimized by not overestimating risk where mitigations are in place.

        4. Final Risk Determination
        - Synthesize all factors and assign a final risk level based on the combination of impact, exploitability, asset criticality, and existing mitigations.




        ## Output Format:
        Return only a valid JSON object in the following format:
            risk_level: The determined risk level string (e.g., "Low", "Medium", "High", "Isolated", "Critical").

        ```json
        {{
            "risk_level1": "Medium",
            "risk_level2": "High"
        }}
        ```
        """



        user_template = """
        Please determine the Risk Level for the following sets of OT Cybersecurity parameters based on the instructions defined in the system prompt. Generate a JSON output with keys 'risk_level1', 'risk_level2', etc., corresponding to each input set below:

        ## Input Sets Start Here:
        {text_input}
        ## Input Sets End Here:


        """
        prompt_template = ChatPromptTemplate.from_messages(
            [("system", system_prompt), ("user", user_template)]
        )        
        
        prompt = prompt_template.invoke({"text_input": text_input})
        response = self.model.invoke(prompt)
        llm_severity_prediction = [res for res in response.values()]
        merge_df["llm severity prediction"] = llm_severity_prediction
        return merge_df
       