import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import socket
import ipaddress
import warnings

class Crt:
    """Get the subdomains from CRT.sh"""
    def __init__(self, domain):
        self.domain = domain
        self.url = "https://crt.sh/?q={}".format(self.domain)
        
    def GetData(self):    
        responseCRT = requests.get(url=self.url)
        if responseCRT.status_code == 200:
            return responseCRT.content
        else:
            print("CRT.sh Not Responding")
    def filterdata(self,data):
        # print(str(data))
        subdomains = []
        domains = re.findall(br'<TD>.*?</TD>',data)
        for domain in domains:
            domain = domain.replace(b'<TD>',b'')
            domain = domain.replace(b'</TD>',b'')
            if self.domain in str(domain):    
                if b'<BR>' in domain:
                    for i in domain.split(b'<BR>'):
                        subdomains.append(i)
                else:
                    subdomains.append(domain)
            else:
                continue 
        return subdomains      
    def sortanduniqe(self,lst):
        sorted = list(set(lst))
        final = []
        for i in sorted:
            final.append(i.decode("utf-8"))
        return final
    def execute(self):
        data=self.GetData()
        subs = self.filterdata(data=data)
        subdomains = self.sortanduniqe(subs)
        for i in subdomains:
            print(i)
class DNSBrute:
    """Bruteforce Subdomains"""
    def __init__(self, domain):
        self.domain = domain
    def resolve(self,hostname):
        try:
            ipaddress = socket.gethostbyname(hostname)
            return ipaddress
        except Exception as error:
            return False
    def BruteForce(self):
        with open("wordlists/DNSlist.txt", 'r') as f:
            wordlist = f.readlines()
        subdomains = []
        subdomainIP = []
        for word in wordlist:
            word = word.strip('\n')
            hostname = "{}.{}".format(word,self.domain)
            ip = self.resolve(hostname=hostname)
            if ip:
                subdomains.append(hostname)
                subdomainIP.append((hostname,ip))
            else:
                continue    
        return subdomains    
    def execute(self):
        self.BruteForce()
        

class waybackmachine:
    """Get the WayBackmachine URLs and Subdomains"""
    def __init__(self, domain):
        self.domain = domain
    def GetData(self):
        url = "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey".format(self.domain)
        responseWBM = requests.get(url=url)
        return responseWBM.content.decode('utf-8').split('\n')
    def FilterSubdomains(self,lst):
        subdomains = []
        for link in lst:
            if 'https://' in link:
                subdomains.append(link.replace('https://','').split('/')[0])
            elif 'http://' in link:
                subdomains.append(link.replace('http://','').split('/')[0])
            else:
                subdomains.append(link)
        for i in list(set(subdomains)):
            print(i)
        return list(set(subdomains))
    def execute(self):
        data = self.GetData()
        self.FilterSubdomains(data)






class Reverse_IP_lookup:
    """Reverse DNS lookups"""
    def __init__(self, domain):
        self.domain = domain
    def GetIPRange(self):
        url = "https://bgp.he.net/dns/{}#_ipinfo".format(self.domain)
        responseRIL = requests.get(url=url)
        IPrange = re.findall(br'/net/\d+.\d+.\d+.\d+/\d+',responseRIL.content)
        IPRanges = []
        for IP in IPrange:
            IPRanges.append(IP.decode('utf-8').replace('/net/',''))
        return IPRanges
    def GetHostByIP(self,IPaddress):
        try:
            host = socket.gethostbyaddr(IPaddress)
            return host
        except Exception as error:
            return False
    def bruteforceit(self,lst):
        for i in lst:
            for ip in ipaddress.IPv4Network(i):
                print(self.GetHostByIP(ip))
    def execute(self):
        ips = self.GetIPRange()
        self.bruteforceit(ips)

class Mobile_lookup:
    """Mobile analysis"""
    def __init__(self, domain):
        self.domain = domain
    def SearchMainPage(self):
        try:
            url = f"https://www.{self.domain}"
            ResponseMainPage = requests.get(url=url)
            AndroidSearch = re.findall(br'(https://play\.google\.com/[^"]*)',ResponseMainPage.content)
            IOSSearch = re.findall(br'(https://apps\.apple\.com/[^"]*)',ResponseMainPage.content)
            print(ResponseMainPage.content)
            if b'https://play.google.com' in AndroidSearch:
                print("APK Found Starting analysis...")
                AndroidSearch = AndroidSearch[0].decode('utf-8')
                print(f"Donwloading {AndroidSearch} ......")
                packagename = AndroidSearch.split('id=')[1]
                print("possible apk for the application you can download it from APKpure for example and hit again with option --apk=<apk file>")
                # self.DownloadAPK(packagename=packagename)
            else:
                print("No Mobile Found in the main page you can search and hit again with option --apk=<apk file> for mobile analysis")
        except Exception as error:
            print("[-] An exception occurred: ",error)
    #TODO: i can do this after web crowling
    #TODO: autmatic download to the app            
    # def DownloadAPK(self,packagename):
    #     try:    
    #         url = f"https://apkpure.net/search?q={packagename}&t=app"
    #         responseGetAPK = requests.get(url=url)
    #         soup = BeautifulSoup(responseGetAPK.text, 'html.parser')
    #         target_div = soup.find('div', class_="first-apk")
    #         if target_div:
    #             anchor_tags = target_div.find_all('a')
    #             for i in anchor_tags:
    #                 links = re.findall(r'<a\s+class="da"\s+href="([^"]+)"',str(i))
    #                 if links:
    #                     responseGetlink = requests.get(url=links[0]+"/download")
    #                     soup = BeautifulSoup(responseGetlink.text, 'html.parser')
    #                     target_div2 = soup.find('a', class_="download-start-btn")
    #                     download_link = re.findall(r'<a\s+class="btn download-start-btn"[^>]*\s+href="([^"]+)"',str(target_div2))
    #         else:
    #             print("Not Found")
    #     except Exception as error:
    #             print("[-] An exception occurred: ",error)
    # def execute(self):
    #     self.SearchMainPage()    
    
# By package or using search main page ex https://play.google.com/store/apps/details?id=com.amc.cinemas.ksa, https://apps.apple.com/us/app/amc-cinemas-movies-more/id1490487307?ls=1
# web Crawler
class Web_Crawler:
    """Web Crawler"""
    def __init__(self, domain):
        self.domain = domain
    def checkHttp():
        pass
    def collectwords():
        pass
    def Takescreenshot():
        pass
    def headers():
        pass
    def checkforKnownpaths():
        pass
    
# Class Cloud Enum
# whois Database Lookup
# Google dork site:pastebin.com | site:paste2.org | site:pastehtml.com | site:codebeautify.io | site:slexy.org | site:justpaste.it | site:codepen.io | site:github | site: gitlab.com   "domain"
# Checking http or https                  

#
# test = Crt("iairgroup.com")
# Crt.execute(self=test)
# test = DNSBrute("iairgroup.com")
# test.execute()
# test = waybackmachine("iairgroup.com")
# test.execute()
        
# test = Reverse_IP_lookup("iairgroup.com")
# test.execute()
# test = Mobile_lookup("instagram.com")
# test.execute()
