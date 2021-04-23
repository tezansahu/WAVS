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
        result = self.check()
        return result

    def check(self):
        values = ['url', 'rurl', 'u','next', 'link', 'lnk', 'go', 'target', 'dest', 'destination', 'redir', 
        'redirect_uri', 'redirect_url', 'redirect', 'view', 'loginto', 'image_url', 'return', 'returnTo', 'return_to',
        'continue', 'return_path', 'path']

        parsed = urlparse.urlparse(self.url)
        params = urlparse.parse_qsl(parsed.query)

        details = {}
        for x,y in params:
            if(x in values):
                details = {"parameter": x, "redirect_url": y }
                break

        if(details):
            return {"result": "Header Based Redirection", "details": details}

        # elif('/r/' in FinalUrl):
        #     details = {"parameter": 'r'}
        #     return {"result": "Header Based Redirection", "details": details}
        else:
            payload = "google.co.in"
            query = ["url", "redirect_url"]
            RedirectCodes = [i for i in range(300,311,1)]
            for x in query:
                url = self.url+"?"+x+"="+payload
                print(url)
                request = requests.Session()
                try:
                    page = request.get(url, allow_redirects=False, timeout=10, verify=False, params='')
                    if page.status_code in RedirectCodes:
                        return {"result": "Header Based Redirection", "details": {"parameter": x}}

                    elif page.status_code==404:
                        return {"result": "Error [404]", "details": {}}
                    elif page.status_code==403:
                        return {"result": "Error [403]", "details": {}}
                    elif page.status_code==400:
                        return {"result": "Error [400]", "details": {}}
                except requests.exceptions.Timeout:
                    return {"result": "TimeOut", "details": {"url": self.url}}
                except requests.exceptions.ConnectionError:
                    return {"result": "Connection Error", "details": {"url": self.url}}
            return {"result": "Not Vulnerable", "details": {}}


def main():
    o = OpenRedirectsDetector()
    print(o.detect_or("https://bugslayers-cs416-open-redirect.herokuapp.com/"))

if __name__ == "__main__":
    main()