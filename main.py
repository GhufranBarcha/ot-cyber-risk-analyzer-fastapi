import io
import os

import pandas as pd
import pymupdf

from fastapi import FastAPI, File
from typing_extensions import Annotated



app =  FastAPI(title = "OT Data Preprocessing API",
               description="Upload Asset Classification Excel and Vulnerability Scan PDF to get a preprocessed DataFrame.")


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
    

    
    return None  