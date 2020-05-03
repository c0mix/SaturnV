import ssl
import socket
import re
from time import sleep
import OpenSSL
import urllib3
import requests
from saturnV import logger
urllib3.disable_warnings()
socket.setdefaulttimeout(3)


def bing(host, output):
    pattern = re.compile("<li class=\"b_algo\"(.+?)</li>")
    http = urllib3.PoolManager()
    try:
        response = http.request('GET', 'https://www.bing.com/search?q=ip%%3a%s' % host.get_ip(), decode_content=True).data.decode('utf-8')
        bing_results = re.findall(pattern, response)
        with open(output, 'a') as out:
            for item in bing_results:
                full_resource = re.sub('\"', '', re.findall('(http(s)?://[^\s]+)', item)[0][0])
                out.write(full_resource+'\n')
                host_name = re.sub('/(.)*', '', re.sub('(http(s)?://)', '', full_resource))
                if (host_name == '') or (host_name in host.get_name()):
                    pass
                else:
                    host.set_name(host_name+'\n')
    except:
        logger.error(f"Error connecting with Bing.com")
    finally:
        http.clear()


def sslGrabber(host, service):
    try:
        cert = ssl.get_server_certificate((host.get_ip(), service.get_port()))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_hostname = x509.get_subject().CN
        if cert_hostname is not None:
            for host_name in cert_hostname.split('\n'):
                if (host_name == "") or (host_name in host.get_name()):
                    pass
                else:
                    service.set_info(host_name+'\n')
    except (urllib3.exceptions.ReadTimeoutError, requests.ConnectionError, urllib3.connection.ConnectionError, urllib3.exceptions.MaxRetryError, urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.TimeoutError, socket.error, socket.timeout) as e:
        pass


def queryAPI(host):
    try:
        r2 = requests.get("https://api.hackertarget.com/reverseiplookup/?q="+host.get_ip()).text
        if (r2.find("No DNS A records found") == -1) and (r2.find("API count exceeded") == -1 and r2.find("error") == -1):
            for host_name in r2.split('\n'):
                if (host_name == "") or (host_name in host.get_name()):
                    pass
                else:
                    host.set_name(host_name+'\n')
    except:
        logger.error(f"Error connecting with HackerTarget.com API")
    finally:
        sleep(0.5)
