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
        
        columns = [ "Predefined Severity", "Note" ,"security_description", "Classification", "\tSafety Impact", "Hosting", "Vulnerability Severity"]
        df = merge_df[columns]
        text_input = ""

        for index, row in df.iterrows():
            text_input += f"\n{index}. CVE Description from the API: {row.iloc[2]},    Asset Classification Note: {row.iloc[1]},    Predefined Severity: {row.iloc[0]},   Asset classification:{row.iloc[3]},    Safety Impact: {row.iloc[4]},   Hosting: {row.iloc[5]},  Vulnerability Severity: {row.iloc[6]} "

        system_prompt = """
            ## ROLE:
            You are a highly skilled Operational Technology (OT) Cybersecurity Analyst with deep expertise in industrial control systems (ICS), vulnerability evaluation, CVE analysis, and risk classification. You are expected to think like a real-world OT defender — carefully weighing threat scenarios against practical constraints and environmental context.

            ## OBJECTIVE:
            For each CVE and asset combination, provide a technically reasoned **risk level assessment**, supported by **clear, step-by-step justification**. Focus on realistic OT impact, not just theoretical severity. Your reasoning must consider exploitability, exposure, mitigations, asset isolation, and consequences (e.g., process disruption, safety).

            ## REASONING FRAMEWORK:
            You have access to the following dimensions:
            1. **Asset Criticality** — How essential the asset is to process continuity and safety.
            2. **Safety Impact** — The level of physical or operational danger posed by successful exploitation.
            3. **Vulnerability Severity on the Asset** — The scanner/logic-assigned severity, which must be validated in context.
            4. **CVE Technical Description** — The vulnerability’s capabilities, exploitability, and attack vector.
            5. **Hosting Context** — Whether the asset is isolated, segmented, or exposed (DMZ, internet-facing, flat network).

            Use these guidelines for structured reasoning:

            -  Asset Criticality:
            - High → Safety controllers, core PLCs, shutdown systems.
            - Medium → HMIs, engineering workstations.
            - Low → Logging or non-control interfaces.

            -  Safety Impact:
            - Only escalate if the vulnerability could realistically lead to physical danger or operational harm.

            -  Vulnerability Severity on Asset:
            - Validate this using real-world exposure and exploitability.
            - Do not blindly trust CVSS.

            -  CVE Technical Details:
            - Identify whether it enables RCE, DoS, logic manipulation, auth bypass, or only information exposure.

            -  Hosting Context:
            - Isolated → Escalate **only** with realistic paths (e.g., USB, supply chain).
            - DMZ or Internet-facing → High exposure, higher risk.
            - Internal/Flat network → Moderate risk; consider lateral movement.

            Only escalate risk levels when the combined factors indicate realistic **OT impact** on safety, process control, or availability. Always justify decisions clearly.

            ## INPUT YOU WILL RECEIVE:
            1. **CVE Description** – Technical details, exploit vectors, CVSS, etc.
            2. **Asset Classification Note** – Function, criticality, hosting, process role.
            3. **Predefined Severity** – Initial rating based on rules.
            4. **Optional Fields (when asset is isolated)** – Asset Classification, safety impact, hosting, etc.

            ---

            ## ANALYSIS PROCESS:

            ###  STEP 1: ANALYZE THE VULNERABILITY (CVE Description)
            - Does the vulnerability enable:
            - Remote Code Execution, Denial of Service, Auth Bypass, Privilege Escalation, or Unsafe Commands?
            - Assess:
            - Attack complexity
            - Known public exploits (PoCs, kits, malware)
            - Requirement for authentication or user interaction

            ###  STEP 2: ANALYZE ASSET CONTEXT (Asset Classification Note)
            - What is the asset’s role in the system?
            - E.g., HMI, PLC, engineering workstation, safety controller
            - Assess business/safety criticality
            - Evaluate exposure:
            - Air-gapped or externally reachable?
            - Identify mitigations:
            - Firewalls, ACLs, segmentation, monitoring, USB-only access, etc.

            ###  STEP 3: APPLY SEVERITY ADJUSTMENT (RULE + REASONING)
            Use the following logic with **justified overrides**:

            **If Predefined Severity is "High" or "Critical":**
            - Confirm if this is justified based on:
            - Actual exploitability
            - Contextual safety/process impact
            - Exposure and mitigations
            - Lower only with strong mitigation evidence in the asset note.

            **If Predefined Severity is "Medium" or "Low":**
            - Increase only if:
            - Exploit is easy and public
            - Asset is exposed
            - Critical safety/process implications

            **For Isolated Assets:**
            - Consider all provided fields
            - Adjust severity realistically:
            - Example: “RCE is irrelevant due to full isolation and no physical access”

            ###  AVOID FALSE REASONING AND LOGICAL FALLACIES

            To ensure accuracy in OT-specific contexts, follow these principles:

            -  Do **not** tie **confidentiality-related vulnerabilities** (e.g., cleartext storage, XSS, info leaks) to **safety** or **availability** impact — **unless** the exposed data enables a realistic path to safety compromise.
            -  Example of valid reasoning: "Leaked credentials from cleartext storage could allow an attacker to remotely authenticate to a PLC and modify process logic."

            -  Do **not** overrate XSS, SNMP misconfigs, or banner leaks unless:
            - The vulnerability enables interaction with **control functions** or **trusted boundaries**
            - It allows **pivoting** to more critical parts of the ICS network
            - It targets interfaces that execute or relay operational commands

            -  Always determine **how the vulnerability affects physical operations**:
            - Does it allow an attacker to stop, alter, or degrade a physical process?
            - If **not**, clearly state: "This vulnerability does not impact control logic, availability, or safety-critical behavior."

            -  Use caution with **DoS** vulnerabilities:
            - Escalate only if the affected system is directly tied to **process integrity** (e.g., controller, safety relay, alarm node)
            - Do not escalate for DoS on historian nodes or monitoring dashboards unless availability loss leads to **process blindness**

            -  Do **not** assume CVSS = OT Risk:
            - CVSS often inflates severity in isolated ICS environments
            - Always assess exploitability **in context** of air gaps, segmentation, USB-only access, and real-world exposure

            -  For **isolated systems**:
            - Acknowledge segmentation, firewalls, physical access controls
            - Downgrade risk unless:
                - The exploit could be triggered through USB or physical compromise
                - The impact is significant *even if isolated* (e.g., logic abuse, setpoint manipulation)

            -  If assigning "High" or "Critical" to an isolated system:
            - Justify with detail: "Although isolated, malicious USB firmware flashing could reprogram the PLC. This poses a high process integrity risk."

            **BOTTOM LINE:** Only assign high severity when a vulnerability is realistically exploitable **and** causes disruption to **safety, availability, or process control** in OT.

            Always align technical details with **realistic OT consequences**.

            ###  STEP 4: ADD MITRE ATT&CK FOR ICS (If Applicable)
            - Map tactics/techniques if relevant and helpful to justify risk
            - E.g., Initial Access → Exploit Public-Facing Application
            - Mention tactic/technique in reasoning if it strengthens justification

            ---

            ### 5.  FINAL DECISION & OUTPUT
            If you assign "High" or "Critical" risk, explicitly explain **how the vulnerability affects safety or process control**, not just that it's “severe” or “critical.” Avoid vague statements like “it’s critical despite isolation.”
            Return a **valid JSON** object with a final risk level and justification for each input.

            #### Format:
            ```json
            {{
            "risk_level1": "Medium",
            "justification1": "The vulnerability enables DoS via malformed packets, but the asset is isolated and monitored with firewall protections. No known exploits. Risk is moderate.",
            "risk_level2": "High",
            "justification2": "The PLC is connected to the control network and the vulnerability allows remote command injection. Impacts process logic. MITRE tactic: Impair Process Control (T855)."
            }}
        """



        user_template = """
            Please determine the Risk Level for the following sets of OT Cybersecurity parameters based on the instructions defined in the system prompt. If the Hosting is 'isolated', consider all factors specified (CVE Description, Asset Note, Asset classification, Safety Impact, Hosting, Vulnerability Severity) for the final output. Otherwise, evaluate based on the system prompt.

            Generate a JSON output with keys 'risk_level1', 'risk_level2', etc., corresponding to each input set below:

            ## Input Sets Start Here:
            {text_input}
            ## Input Sets End Here:
        """
        
        prompt_template = ChatPromptTemplate.from_messages(
            [("system", system_prompt), ("user", user_template)]
        )        


        prompt = prompt_template.invoke({"text_input": text_input})
        response = self.model.invoke(prompt)
        
        risk_levels = []
        justifications = []

        # Get all unique indices from the response keys
        # indices = sorted({key.lstrip("risk_level").lstrip("justification")[-1] for key in response.keys()}, key=int)

        # Loop through based on discovered indices
        for i in range(len(response) // 2):
            risk_levels.append(response.get(f"risk_level{i}", ""))
            justifications.append(response.get(f"justification{i}", ""))

        # Add to your DataFrame
        merge_df["risk_level"] = risk_levels
        merge_df["llm_justification"] = justifications
        
        return merge_df
