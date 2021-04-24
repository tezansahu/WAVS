import uvicorn
from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from starlette.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
import v1

app = FastAPI()

app.add_middleware(
    CORSMiddleware, allow_origins=["http://localhost:8000"], allow_methods=["*"], allow_headers=["*"]
)

@app.get("/", tags=["root"])
def get_root():
    return RedirectResponse("/v1/")


app.include_router(
    v1.router,
    prefix="/v1",
    tags=["vulnerability scanning (version 1)"],
    responses={404: {"description": "Not found"}},
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="WAVS: Web App Vulnerability Scanner",
        version="0.0.1",
        description="""WAVS (Web App Vulnerability Scanner) is a tool to scan & test URLs for certain vulnerabilities & 
        security issues by simply inspecting the corresponding client-side website. The overall system would include a 
        virtual server with modules for detecting the different vulnerabilities, along with a proxy server, to direct 
        requests from a browser to the virtual server first while visiting a website. The proxy could warn the user before 
        redirecting to the website if some vulnerabilities are found during the scan done by our virtual server.
        \nWe identify & assess the following security issues that a website may suffer from: _Absence of Valid TLS Certificates_, 
        _Cross-Site Scripting (XSS)_, _Potential Phishing Attempts_ & _Open Redirection_
        """,
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

if __name__ == "__main__":
    uvicorn.run("main:app", host="localhost", port=9000)