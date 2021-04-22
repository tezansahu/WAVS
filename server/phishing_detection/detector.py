import pickle
import os
from .extractor import WebsiteFeatureExtractor

class PhishingWebsiteDetector:
    def __init__(self, rel_model_path="./phishing_detection_model/phishing_website_detection_model.sav"):
        self.model = pickle.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), rel_model_path), "rb"))
        self.wfe = None

        self.interpretation = {
            -1: "Phishing",
            1: "Legitimate",
            0: "Suspicious"
        }

    def detect_phishing(self, url):
        self.wfe = WebsiteFeatureExtractor(url)
        
        precheck_res = self.__prechecks()
        
        if precheck_res["passed"]:
            feature_vec = self.wfe.extract_features()
            res = self.interpretation[self.model.predict([feature_vec])[0]]
            response = {
                "result": res
            }
            

            details = {
                "prechecks": "passed",
                "features": []
            }
            for feature, desc, val in zip(self.wfe.feature_names, self.wfe.feature_desc, feature_vec):
                details["features"].append({
                    "feature": feature,
                    "desc": desc,
                    "value": self.interpretation[val]
                })
            response["details"] = details
            
            return response
        else:
            return {"result": "Phishing", "details": {"prechecks": "failed", "failed_prechecks": precheck_res["details"]["failed_prechecks"]}}

    def __prechecks(self):
        res = {
            "passed": True,
            "details": {
                "failed_prechecks": []
            }
        }
        if self.wfe.soup == -999:
            res["passed"] = False
            res["details"]["failed_prechecks"].append("Unable to fetch website")
        else:
            if len(self.wfe.soup.find_all(["html"])) == 0:
                res["passed"] = False
                res["details"]["failed_prechecks"].append("No HTML Tag")
        
        return res
   