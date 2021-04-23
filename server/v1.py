import re
from fastapi import APIRouter
from pydantic import BaseModel

from phishing_detection import detector
from tls_cert_detection import cert_checker
from open_redirect_detection import or_detector
from xss_detection import xss_scanner

router = APIRouter()

tls_cc = cert_checker.CertChecker()
pwd = detector.PhishingWebsiteDetector()
or_d = or_detector.OpenRedirectsDetector()
xss_d = xss_scanner.XSSDetector()

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
    if not re.match(r"^https?", url):
        url = "https://" + url
    response = {"url": url}
    
    if options.tls_cert:
        tls_res = tls_cc.checkCertChain(url)
        response["tls_cert"] = tls_res
    if options.xss:
        xss_res = xss_d.detect_xss(url)
        response["xss"] = xss_res
    if options.phishing:
        pwd_res = pwd.detect_phishing(url)
        response["phishing"] = pwd_res
    if options.open_redirect:
        ord_res = or_d.detect_or(url)
        response["open_redir"] = ord_res
    return response