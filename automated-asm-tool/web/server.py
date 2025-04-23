import sys
import os
import json
import logging
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

# Add parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from asm_tool import run_scan  # Now works

app = FastAPI()
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=HTMLResponse)
async def perform_scan(request: Request, domain: str = Form(...)):
    try:
        logging.info(f"Starting web scan for {domain}")
        report = run_scan(domain)
        return templates.TemplateResponse("index.html", {
            "request": request,
            "domain": domain,
            "report": json.dumps(report, indent=2)
        })
    except Exception as e:
        logging.error(f"Web scan failed: {str(e)}")
        return templates.TemplateResponse("index.html", {
            "request": request,
            "error": f"Scan failed: {str(e)}"
        })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)