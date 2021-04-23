import warnings,ssl,requests
import urllib.parse as urlparse
warnings.filterwarnings('ignore')
ssl._create_default_https_context = ssl._create_unverified_context
#----------------------------------------------------------------------------------#

class OpenRedirectsDetector:
    def __init__(self):
        self.url = None
    
    def detect_or(self, url):
        if urlparse.urlparse(url).scheme == '':
            url = 'http://' + url
        self.url = url
        result = self.check()
        return result

    def check(self):
        values = ['url', 'rurl', 'u','next', 'link', 'lnk', 'go', 'target', 'dest', 'destination', 'redir', 
        'redirect_uri', 'redirect_url', 'redirect', 'view', 'loginto', 'image_url', 'return', 'returnTo', 'return_to',
        'continue', 'return_path', 'path']
        RedirectCodes = [i for i in range(300,311,1)]
        
        request = requests.Session()
        parsed = urlparse.urlparse(self.url)
        params = urlparse.parse_qsl(parsed.query)
        if(params):
            try:
                page = request.get(self.url, allow_redirects=False, timeout=10, verify=False, params='')
                page2 = request.get(self.url, allow_redirects=True, timeout=10, verify=False, params='')
                # print(page2.request.url)
                if page.status_code in RedirectCodes:
                    details = {}
                    for x,y in params:
                        if(x in values and y==page2.request.url):
                            details = {"parameter": x, "redirect_url": y }
                            break
                    if(details):
                        return {"result": "Header Based Redirection", "details": details}
                    elif('/r/' in self.url):
                        details = {"parameter": 'r'}
                        return {"result": "Header Based Redirection", "details": details}
                    else:
                        return {"result": "Open Redirection", "details": {}}
                elif page.status_code==404:
                    return {"result": "404 Not Found", "details": {}}
                elif page.status_code==403:
                    return {"result": "403 Forbidden", "details": {}}
                elif page.status_code==400:
                    return {"result": "400 Bad Request", "details": {}}
            except requests.exceptions.Timeout:
                return {"result": "TimeOut", "details": {"url": self.url}}
            except requests.exceptions.ConnectionError:
                return {"result": "Connection Error", "details": {"url": self.url}}

        payload = "https://www.google.co.in"
        query = ["url", "redirect_url"]
        for x in query:
            url = self.url+"?"+x+"="+payload            
            try:
                page = request.get(url, allow_redirects=False, timeout=10, verify=False, params='')
                page2 = request.get(url, allow_redirects=True, timeout=10, verify=False, params='')
                if(page.status_code in RedirectCodes and page2.request.url == payload):
                    return {"result": "Header Based Redirection", "details": {"parameter": x}}
                elif page.status_code==404:
                    return {"result": "404 Not Found", "details": {}}
                elif page.status_code==403:
                    return {"result": "403 Forbidden", "details": {}}
                elif page.status_code==400:
                    return {"result": "400 Bad Request", "details": {}}
            except requests.exceptions.Timeout:
                return {"result": "TimeOut", "details": {"url": self.url}}
            except requests.exceptions.ConnectionError:
                return {"result": "Connection Error", "details": {"url": self.url}}
        return {"result": "Not Vulnerable", "details": {}}


def main():
    o = OpenRedirectsDetector()
    # print(o.detect_or("https://bugslayers-cs416-open-redirect.herokuapp.com/?url=https://www.google.com"))
    # print(o.detect_or("https://medium.com/r/?url=https://phising-malicious.com"))
    # print(o.detect_or("google.co.in"))

if __name__ == "__main__":
    main()