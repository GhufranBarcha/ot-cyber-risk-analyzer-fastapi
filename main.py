import io
import os
from pathlib import Path

import pandas as pd
import pymupdf
from dotenv import load_dotenv
from fastapi import FastAPI, File
from fastapi.responses import JSONResponse
from typing_extensions import Annotated

from model.llm_process import LLMParser
from utils.utils import get_security_description, read_predefined_rules

# Initialize FastAPI app
app = FastAPI(
    title="OT Data Preprocessing API",
    description="Upload Asset Classification Excel and Vulnerability Scan PDF to get a preprocessed DataFrame."
)

# Load environment variables
load_dotenv()

# API configuration
API_KEYS = [
    os.getenv("API_KEY_1"),
    os.getenv("API_KEY_2"),
    os.getenv("API_KEY_3")
]

# File paths and constants
BASE_DIR = Path(__file__).parent
PATH_RULE = BASE_DIR / "data" / "predefined roles.csv"

# Output columns
RESULT_COLUMNS = ["CVE ID", "CVE Name", "Asset Name", "IP Address", "Vulnerability Severity", "Predefined Severity", "risk_level", "llm_justification"]

# Initialize LLM model
llm = LLMParser(model_name="deepseek-r1-distill-llama-70b", model_provider="groq")


def clean_text(text):
    """Remove newlines and strip whitespace from text."""
    return text.replace("\n", " ").strip()


@app.get("/")
def root():
    """Root endpoint that returns API information."""
    return {
        "message": "OT Analysis FastAPI Endpoints, Check documentation at /docs"
    }


@app.post("/getLlmResults")
def process_files(
    assetfile: Annotated[bytes, File(description="An excel file with .xlsx extension")],
    scan_report: Annotated[bytes, File(description="A pdf file with .pdf extension")]
):
    """
    Process asset classification file and vulnerability scan report.
    
    Args:
        assetfile: Excel file containing asset data
        scan_report: PDF file containing vulnerability scan results
    
    Returns:
        JSON response with processed data
    """
    # Process asset classification Excel file
    asset_df = load_excel_file(assetfile)
    
    # Process vulnerability scan PDF file
    scan_df = load_pdf_tables(scan_report)
    
    # Merge and process dataframes
    result_df = process_data(asset_df, scan_df)
    
    # Return the data as JSON
    return JSONResponse(
        content={
            "status": "success",
            "data": result_df.to_dict(orient="records"),
            "columns": RESULT_COLUMNS
        }
    )


def load_excel_file(file_bytes):
    """Load and preprocess Excel file."""
    excel_stream = io.BytesIO(file_bytes)
    df = pd.read_excel(excel_stream)
    df.columns = df.iloc[0]
    df = df.iloc[1:].reset_index(drop=True)
    excel_stream.close()
    return df


def load_pdf_tables(file_bytes):
    """Extract tables from PDF file."""
    pdf_doc = pymupdf.open(stream=file_bytes, filetype="pdf")
    
    pdf_table = []
    for page in pdf_doc:
        tables = page.find_tables()
        if tables:
            for table in tables:
                table_data = table.extract()
                pdf_table.extend(table_data)
    
    # Clean text in table cells
    pdf_table = [[clean_text(text) for text in row] for row in pdf_table]
    
    df = pd.DataFrame(pdf_table)
    df.columns = df.iloc[0]
    df = df.iloc[1:].reset_index(drop=True)
    return df


def process_data(asset_df, scan_df):
    """Merge and process the dataframes."""
    # Merge dataframes
    merged_df = pd.merge(asset_df, scan_df, on=["Asset Name", "Asset Name"], how="right")
    merged_df.dropna(inplace=True)
    merged_df = merged_df.set_index("#")
    merged_df.reset_index(drop=True, inplace=True)
    
    # Process hosting information
    merged_df["Hosting1"] = merged_df["Hosting"].apply(
        lambda x: "Isolated" if "Isolated" in x else "Anything"
    )
    
    # Get security descriptions and analyze risks
    merged_df["security_description"] = merged_df["CVE ID"].apply(
        lambda cve: get_security_description(cve, API_KEYS)
    )
    
    rule_str = read_predefined_rules(PATH_RULE)
    
    # Apply LLM processing
    merged_df = llm.risk_analyzer(merged_df, rule_str)
    merged_df = llm.refine_risk_level(merged_df)
    
    # # Save intermediate result (consider making this optional or removing in production)
    # merged_df.to_csv("merge_df.csv")
    
    # Select only the required columns
    return merged_df[RESULT_COLUMNS]