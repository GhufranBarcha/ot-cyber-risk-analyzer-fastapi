# OT Cybersecurity Analysis API

This API processes asset classification data and vulnerability scan reports to analyze cybersecurity risks in Operational Technology (OT) environments. The system combines rule-based risk assessment with LLM-powered vulnerability analysis.

## Setup Instructions

### 1. Create and Activate a Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# For Windows
venv\Scripts\activate
# For Linux/Mac
source venv/bin/activate
```

### 2.  Install Dependencies
```bash
# Install all required packages
pip install -r requirements.txt
```

### 3.  Configure Environment Variables

Make sure your `.env` file is properly set up with:

- `GROQ_API_KEY`: API key for the LLM service
- `API_KEY_1`, `API_KEY_2`, `API_KEY_3`: NVD API keys for vulnerability data retrieval


### 4. Run the FastAPI Server
```bash
# Start the FastAPI server
uvicorn main:app --reload
```
The server will start on http://127.0.0.1:8000 by default.

## API Endpoints
### Documentation
- URL: `http://127.0.0.1:8000/docs`
- Interactive Swagger UI documentation for all endpoints

### Root Endpoint
- URL: `http://127.0.0.1:8000/`
- Returns basic API information

### Process Files Endpoint
- URL: `http://127.0.0.1:8000/getLlmResults`
- Method: POST
- Parameters:
    - assetfile: Excel file (.xlsx) containing asset classification data
    - scan_report: PDF file containing vulnerability scan results
- Returns: JSON response with processed data including risk severity assessmen


## Usage Example
You can test the API using curl:
```bash
curl -X 'POST' \
  'http://127.0.0.1:8000/getLlmResults' \
  -H 'accept: application/json' \
  -H 'Content-Type: multipart/form-data' \
  -F 'assetfile=@/path/to/your/asset_file.xlsx' \
  -F 'scan_report=@/path/to/your/scan_report.pdf'
```
Or use the interactive documentation at `/docs` to test the endpoints directly from your browser.