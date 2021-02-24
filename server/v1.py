from fastapi import APIRouter
from pydantic import BaseModel
from phishing_detection import detector

router = APIRouter()

class ScanOptions(BaseModel):
    tls_cert: bool = True
    xss: bool = True
    phishing: bool = True
    open_redirect: bool = True


@router.get("/")
def get_v1_root():
    return "This is the RESTful API for WAVS (Web App Vulnerability Scanner)"


@router.post("/scan/")
def vulnerablity_scan(url: str, options: ScanOptions):
    response = {"url": url}
    if options.tls_cert:
        pass
    if options.xss:
        pass
    if options.phishing:
        pwd = detector.PhishingWebsiteDetector()
        pwd_res = pwd.detect_phishing(url)
        response["phishing"] = pwd_res
    if options.open_redirect:
        pass
    
    return response