import warnings,ssl,requests
import urllib.parse as urlparse
warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context
#----------------------------------------------------------------------------------#

class OpenRedirectsDetector:
    def __init__(self):
        self.url = None
    
    def detect_or(self, url):
        self.url = url
        result = self.request()
        return result

    def request(self):
        request = requests.Session()
        try:
            page = request.get(self.url, allow_redirects=False, timeout=10, verify=False, params='')
        except requests.exceptions.Timeout:
            return {"result": "TimeOut", "details": {"url": self.url}}
        except requests.exceptions.ConnectionError:
             return {"result": "Connection Error", "details": {"url": self.url}}

        result = self.check(page,page.request.url)
        return result

    def check(self, PageVar,FinalUrl):
        RedirectCodes = [i for i in range(300,311,1)]
        values = ['url', 'rurl', 'u','next', 'link', 'lnk', 'go', 'target', 'dest', 'destination', 'redir', 
        'redirect_uri', 'redirect_url', 'redirect', 'view', 'loginto', 'image_url', 'return', 'returnTo', 'return_to',
        'continue', 'return_path', 'path']

        parsed = urlparse.urlparse(FinalUrl)
        params = urlparse.parse_qsl(parsed.query)

        if PageVar.status_code in RedirectCodes:
            details = {}
            for x,y in params:
                if(x in values):
                    details = {"parameter": x, "redirect_url": y }
                    break

            if(details):
                return {"result": "Header Based Redirection", "details": details}

            elif('/r/' in FinalUrl):
                details = {"parameter": 'r'}
                return {"result": "Header Based Redirection", "details": details}
            else:
                return {"result": "Open Redirect Vulnerable", "details": {}}

        elif PageVar.status_code==404:
            return {"result": "Error [404]", "details": {}}
        elif PageVar.status_code==403:
            return {"result": "Error [403]", "details": {}}
        elif PageVar.status_code==400:
            return {"result": "Error [400]", "details": {}}

        else:
            return {"result": "Not Vulnerable", "details": {}}

def main():
    o = OpenRedirectsDetector()
    print(o.detect_or("https://medium.com/r/?url=www.google.com"))

if __name__ == "__main__":
    main()