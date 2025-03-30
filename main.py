import io
import os

from dotenv import load_dotenv
import pandas as pd
import pymupdf

from fastapi import FastAPI, File
from fastapi.responses import JSONResponse
from typing_extensions import Annotated

from utils.utils import read_predefined_rules, get_security_description
from llm import LLMParser



app =  FastAPI(title = "OT Data Preprocessing API",
               description="Upload Asset Classification Excel and Vulnerability Scan PDF to get a preprocessed DataFrame.")

load_dotenv()

# Get individual keys
API_KEY_1 = os.getenv("API_KEY_1")
api_key_2 = os.getenv("API_KEY_2")
API_KEY_3 = os.getenv("API_KEY_3")

## Column Name which will be returned
columns_name = ["CVE ID", "CVE Name", "Asset Name", "IP Address", "Vulnerability Severity", "Predefined Severity", "llm severity prediction"]

# Create a list of API keys
API_KEYS = [API_KEY_1, API_KEY_2, API_KEY_3]
PATH_RULE = "/home/ghufranbarcha/Desktop/Freelance Task/CyberAI_Analysis/api/data/predefined roles.csv"

llm = LLMParser(model_name = "deepseek-r1-distill-llama-70b", model_provider = "groq")

def string_converter(text):
  clearned = text.replace("\n", " ")
  return clearned.strip()

@app.get("/")
def root():
    return {
        "OT Analysis FastAPI Endpoints , Check documentation at /8000/docs"
    }
    
    
@app.post("/getLlmResults") 
def main(assetfile: Annotated[bytes, File(description = "An excel file with .xlsx extension")],
         scan_report: Annotated[bytes, File(description = "A pdf file with .pdf extension")]):
    
    ## Read both file first
    excel_stream = io.BytesIO(assetfile)
    df1 = pd.read_excel(excel_stream)
    df1.columns = df1.iloc[0]
    df1 = df1.iloc[1:].reset_index(drop=True)
    excel_stream.close()
    
    pdf_doc = pymupdf.open(stream = scan_report, filetype = "pdf")
    
    pdf_table = []
    for page in pdf_doc:
        tables =  page.find_tables()  # Assign the result to 'tables'
        if tables:  # Check if any tables were found
            for table in tables:  # Iterate through each TableFinder object
                table_data = table.extract()  # Extract data from the table
                pdf_table.extend(table_data) 
    pdf_table = [[string_converter(text) for text in row] for row in pdf_table]    
    
    df2 = pd.DataFrame(pdf_table)
    df2.columns = df2.iloc[0]
    df2 = df2.iloc[1:].reset_index(drop=True)
    
    ## Merge Dataframes
    merge_df = pd.merge(df1, df2 , on = ["Asset Name", "Asset Name"], how = "right")
    merge_df.dropna(inplace = True) # Removes rows with any missing values
    merge_df = merge_df.set_index("#") # Sets the '#' column as the index. Assigned back to merge_df
    merge_df.reset_index(drop = True, inplace = True)
    
    ## Preprocssing of hosting
    merge_df["Hosting1"] = merge_df["Hosting"].apply(lambda x: "Isolated" if "Isolated" in x else "Anything")
    
    
    merge_df["security_description"] = merge_df["CVE ID"].apply(lambda cve: get_security_description(cve, API_KEYS))
    rule_str = read_predefined_rules(PATH_RULE)
    
    merge_df = llm.risk_analyzer(merge_df, rule_str)
    merge_df = llm.refine_risk_level(merge_df)
    
    merge_df.to_csv("merge_df.csv")
    
    
    merge_df = merge_df[columns_name]
    

    # Return the data as JSON
    return JSONResponse(
        content={
            "status": "success",
            "data": merge_df.to_dict(orient="records"),
            "columns": columns_name
        }
    )