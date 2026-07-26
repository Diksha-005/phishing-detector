import requests

def resolve_final_url(url):
    try:
        response=requests.head(url,allow_redirects=True)
        if response.status_code==200:
            return response.url
    except requests.exceptions.RequestException:
        pass
    
    #if head not work then use get
    try:
        response=requests.get(url,allow_redirects=True)
        return response.url
    except requests.exceptions.RequestException:
        return url # both failed, just return the original URL unresolved
    
    