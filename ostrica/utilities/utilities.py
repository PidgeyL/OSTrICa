# Imports
import gzip
import sys
import ssl

if sys.version_info < (3, 0):
    import httplib
    import StringIO as io
else:
    import http.client as httplib
    import io

from ostrica.utilities.cfg import Config as cfg

#############
# Constants #
#############
is_py2 = (sys.version_info < (3, 0))

#############
# Functions #
#############

# Python 2.x - 3.x compatibility functions
def ensure_str(data):
    return data if type(data) is str else data.decode('utf-8')

def extract_zip(data):
    fZip = io.StringIO(data) if is_py2 else io.BytesIO(data)
    return gzip.GzipFile(fileobj=fZip).read()

# General functions
def get_page(domain, query, SSL=False, ref=None, accept=None):
    try:
        if not SSL:
            h = httplib.HTTPConnection(domain, timeout=cfg.timeout)
        else:
            ssl_cont = ssl._create_unverified_context()
            h = httplib.HTTPSConnection(domain, timeout=cfg.timeout, context=ssl_cont)
        h.putrequest('GET', query)
        h.putheader('Connection', 'keep-alive')
        h.putheader('Accept', '*/*')
        if ref:
            h.putheader('referer', ref)
        h.putheader('Accept-Encoding', 'gzip, deflate, sdch')
        h.putheader('User-Agent', cfg.user_agent)
        h.putheader('Accept-Language', 'en-GB,en-US;q=0.8,en;q=0.6')
        h.endheaders()

        response = h.getresponse()
        if response.status == 200:
            if response.getheader('Content-Encoding') == 'gzip':
                return ensure_str(extract_zip(response.read()))
            else:
                return ensure_str(response.read())
    except:
        # To be replaced with log later on
        print("Could not reach %s"%domain)
    return None
