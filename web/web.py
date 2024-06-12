from time import sleep
import requests
import os
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager




requests.packages.urllib3.disable_warnings()
class colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
def print_color(text, color):
    print(color + text + colors.RESET)
class webCrawl:
    def __init__(self, domains, dom,extensive):
        self.domains = domains
        self.dom = dom
        self.extensive = extensive
        self.known = [
		"Cache-Control",
		"Content-Type",
		"Content-Length",
		"Strict-Transport-Security",
		"X-Content-Type-Options",
		"X-XSS-Protection",
		"X-Frame-Options",
		"Content-Security-Policy",
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Last-Modified",
		"Etag",
		"Expires",
		"Date",
		"Retry-After",
		"Content-Encoding",
		"Connection",
		"Vary",
		"Referrer-Policy",
		"Permissions-Policy",
		"X-Flying-Press-Cache",
        "Transfer-Encoding",
        "Age",
        "Cross-Origin-Resource-Policy",
        "Cross-Origin-Opener-Policy",
        "X-Cache",
        "Accept-Ranges",
        "content-security-policy",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-ratelimit-limit-minute",
        "x-ratelimit-remaining-minute",
        "ratelimit-limit",
        "link",
        "x-content-security-policy",
        
        "Accept-Ranges",
        
	]
        self.live80 = []
        self.live443 = []
        self.liveDomains = []
        self.characteres = []

    def removeNull(self):
        temp=[]
        for item in self.domains:
            if item != '' and item != '0.0.0.0':
                temp.append(item)
        self.domains=list(set(temp))

    def SearchAPKMainPage(self):
        try:
            url = f"https://www.{self.dom}"
            ResponseMainPage = requests.get(url=url)
            AndroidSearch = re.findall(br'(https://play\.google\.com/[^"]*)',ResponseMainPage.content)
            IOSSearch = re.findall(br'(https://apps\.apple\.com/[^"]*)',ResponseMainPage.content)
            if b'https://play.google.com' in AndroidSearch or  b'https://apps.apple.com' in IOSSearch:
                print("Mobile Application Found...")
                AndroidSearch = AndroidSearch[0].decode('utf-8')
                print(f"Found {AndroidSearch} ......")
                print("possible mobile application for the company. you can download it from APKpure for example and hit again with option --apk=<apk file>")
            else:
                print("No Mobile Found in the main page you can search and hit again with option apk --apk=<apk file> for mobile analysis")
        except Exception as error:
            print_color("[-] An exception occurred4: "+ error,colors.RED)

    def live(self):
        hed80 = []
        hed443 = []
        print_color("[+] Subdomains Enumeration Started",color=colors.BOLD)
        self.known = [x.lower() for x in self.known]
        print_color('\n[+] Active HTTP Subdomains', colors.BOLD)
        mobilelinks = []
        for domain in self.domains:
            try:
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
                r80 = requests.get('http://'+domain,verify=False, timeout=10,headers=headers)
        
                if r80.status_code > 100 and r80.status_code <= 500:
                    AndroidSearch = re.findall(br'(https://play\.google\.com/[^"]*)',r80.content)
                    IOSSearch = re.findall(br'(https://apps\.apple\.com/[^"]*)',r80.content)
                    if len(AndroidSearch) != 0:
                        AndroidSearch = AndroidSearch[0].decode('utf-8')
                        mobilelinks.append(AndroidSearch)
                        
                    if len(IOSSearch) != 0:
                        IOSSearch = IOSSearch[0].decode('utf-8')
                        mobilelinks.append(IOSSearch)
                   
                    print_color("http://"+domain,colors.PURPLE)
                    self.live80.append(domain)
                    self.liveDomains.append(domain)
                    head = r80.headers
                    head = dict(head)
                    temp = []
                    for key, value in head.items():
                        if key.lower() in self.known:
                            pass
                        else:
                            temp.append(key + ': ' + value)
                    hed80.append(temp)
            except Exception as error:
                pass
                
            try:        
                r443 = requests.get('https://'+domain, verify=True, timeout=10,headers=headers)
                if r443.status_code > 100 and r443.status_code <= 500:
                    AndroidSearch = re.findall(br'(https://play\.google\.com/[^"]*)',r443.content)
                    IOSSearch = re.findall(br'(https://apps\.apple\.com/[^"]*)',r443.content)
                    if len(AndroidSearch) != 0:
                        AndroidSearch = AndroidSearch[0].decode('utf-8')
                        mobilelinks.append(AndroidSearch)
                        
                    if len(IOSSearch) != 0:
                        IOSSearch = IOSSearch[0].decode('utf-8')
                        mobilelinks.append(IOSSearch)
                        
                    self.live443.append(domain)
                    self.liveDomains.append(domain)
                    print_color("https://"+domain,colors.PURPLE)
                    head = r443.headers
                    head = dict(head)
                    temp = []
                    for key, value in head.items():
                        if key.lower() in self.known:
                            pass
                        else:
                            temp.append(key + ': ' + value)
                            
                    hed443.append(temp)
                    
            except Exception as error:
                pass
        print()
        if mobilelinks != None:
            print_color("[+] Mobile Application Found...",colors.BOLD)
            for i in set(mobilelinks):
                print_color(f"Found {i} ......",colors.GREEN)
        print_color("[+] Possible mobile application for the company. you can download it from APKpure for example and hit again with option --apk=<apk file>",colors.BOLD)

        print()
        
        print_color("[+] Printing Interesting Headers...",colors.BOLD)
        for i in range(len(self.live80)):
            print_color(f"\n[+] Reading headers from {self.live80[i]} running on port 80:",colors.CYAN)
            for j in hed80[i]:    
                print_color(f"{j}",colors.GREEN)
        for i in range(len(self.live443)):
            print_color(f"\n[+] Reading headers from {self.live443[i]} running on port 443:",colors.CYAN)
            for j in hed443[i]:    
                print_color(f"{j}",colors.GREEN)    
    
    
    def KnownPaths(self):
        print()
        print_color("[+] Checking Known Paths..",colors.BOLD)    
        with open("./wordlists/KnownPaths.txt") as Paths:
            files = Paths.readlines()
        if len(self.live80) != 0:
            for file in files:
                for domain in self.live80:
                    try: 
                        res = requests.get(f"http://{domain}/{file[:-1]}",allow_redirects=False)
                        if res.status_code == 200 or res.status_code == 301 or res.status_code == 403:
                            print_color(f"[{res.status_code}] {res.url}",colors.GREEN)    
                    except Exception as e:
                        pass

        if len(self.live443) != 0:
                for file in files:
                    for domain in self.live443:
                        try:
                            res = requests.get(f"https://{domain}/{file[:-1]}",allow_redirects=False)
                            if res.status_code == 200 or res.status_code == 301 or res.status_code == 403:
                                print_color(f"[{res.status_code}] {res.url}",colors.GREEN)
                        except Exception as e:
                            pass
        for domain in self.live443:
            try:
                r = requests.get('http://'+domain+':443', verify=False)
                print_color(f"\n[+] Reading headers from {domain} running on port 443:",colors.CYAN)
                head = r.headers
                head = dict(head)
                for key, value in head.items():
                    if key.lower() in self.known:
                        pass
                    else:
                        print_color(key + ': ' + value,colors.GREEN)
            except Exception as e:
                pass
        print()


    def screenshot(self):
        print_color("\n[+] Taking screenshots started",colors.BOLD)
        path = "./Screenshots/"

      
        if os.path.exists(path):
            files=os.listdir(path)
            for file in files:
                name=path+file
                os.remove(name)
        else:
            os.mkdir(path)
        for domain in set(self.liveDomains):
            try:
                Chrome_options = Options()
                Chrome_options.add_argument("--headless=new")
                Chrome_options.add_argument("--disable-extensions")
                Chrome_options.add_argument('--ignore-certificate-errors')
                Chrome_options.add_argument('--no-sandbox')
                Chrome_options.add_argument('--disable-dev-shm-usage')
                Chrome_options.add_argument('--log-level=3')
                driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()),options=Chrome_options)
                driver.set_page_load_timeout(30)
                driver.get('http://'+domain)
                driver.save_screenshot(path+domain+'.png')
                driver.quit()
                sleep(1)
            except Exception as e:
                print_color(f"couldn't take a screenshot for {domain} due to issues with the server!!",colors.RED)
        print_color("[+] Done getting screenshots",colors.BOLD)  


    def links(self):
        temp = []
        for domain in self.live80:
            try:
                r = requests.get('http://'+domain, verify=False)
                res = r.text
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', res)
                for item in urls:
                    temp.append(item)

            except Exception as e:
                print_color(f"An error occurred for the domain {domain}: {e}",colors.RED)
        print()

        for domain in self.live443:
            try:
                r = requests.get('https://'+domain, verify=False)
                res = r.text
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', res)
                for item in urls:
                    temp.append(item)
            except Exception as e:
                pass
        with open('./links.txt', 'w')as f:
            for i in range(len(temp)):
                if self.dom in temp[i].split('/')[2]:    
                    f.write(temp[i])
                    f.write('\n')
        print_color(f"\n[+] crawled links for the live domains can be found in \'links.txt\': ",colors.BOLD)
        print()    


    def execute(self):
        self.removeNull()
        self.live()
        if self.extensive != True:
            self.KnownPaths()
        self.screenshot()
        self.links()

