import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import os

class XSSDetector:
    def __init__(self):
        self.url = None

    def detect_xss(self, url):
        self.url = url
        result = self.scan_xss()
        return result

    def get_all_forms(self): 
        # Returns forms from the static website
        try:
            res = requests.get(self.url, timeout=5).content
            soup = bs(res, "html.parser")
            form_tag = soup.find_all("form")
        except Exception:
            form_tag = []
        return form_tag

    def get_form_details(self,form):
        # This function extracts all possible useful information about an HTML `form`
        details = {}
        # get the form action (target url)
        try: 
            action = form.attrs.get("action").lower()
            # get the form method (POST, GET, etc.)
            method = form.attrs.get("method", "get").lower()
        except: 
            action = []
            method = []
        # get all the input details such as type and name
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        
        for textarea in form.find_all("textarea"):
            input_type = "textarea"
            input_name = textarea.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        # put everything to the resulting dictionary
        details["action"] = action
        details["method"] = method
        details["inputs"] = inputs
        return details

    def submit_form(self,form_details, value):
        """
        Submits a form given in `form_details`
        Params:
            form_details (list): a dictionary that contain form information
            url (str): the original URL that contain that form
            value (str): this will be replaced to all text and search inputs
        Returns the HTTP Response after form submission
        """
        # construct the full URL (if the url provided in action is relative)
        target_url = urljoin(self.url, form_details["action"])
        # get the inputs
        inputs = form_details["inputs"]
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search" or input["type"] == "textarea":
                input["value"] = value
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value

        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            
            return requests.get(target_url, params=data)

    def scan_xss(self):
        """
        Given a `url`, it prints all XSS vulnerable forms and 
        returns True if any is vulnerable, False otherwise
        """
        forms = self.get_all_forms()
        # print(f"[+] Detected {len(forms)} forms on {url}.")
        with open (os.path.join(os.path.dirname(__file__), "payload_basic.txt")) as x:
            return_details = []
            # is_vulnerable = False
            for form in forms:
                for line in x:  
                    js_script = line
                    form_details = self.get_form_details(form)
                    try: 
                        content = self.submit_form(form_details, js_script).content.decode()
                    except:
                        content = []
                    if js_script in content:
                        form_details["vulnerable"] = True
                        break
                    else:
                        form_details["vulnerable"] = False
                return_details.append(form_details)

        return_val = {}
        if return_details:
            first = True            
            for form in return_details:
                if form["vulnerable"] == True:
                    if first: 
                        return_val["result"] = "XSS Detected"
                        return_val["details"] = [form]
                        first = False
                    else: 
                        return_val["details"].append(form)
            if first == True: 
                return_val["result"] = "XSS Not Detected"
                return_val["details"] = []
                    
        else: 
            return_val["result"] = "XSS Not Detected"
            return_val["details"] = []

        return return_val

def xss_main():
    # url = "https://xss-game.appspot.com/level1/frame"
    # url = "https://bugslayers-cs416-open-redirect.herokuapp.com/"
    url = "https://www.google.com/"
    obj = XSSDetector()
    print(obj.detect_xss(url)) 

if __name__ == "__main__":
    xss_main()
