import sys
import requests
import re
import socket
import ipaddress
import csv
import json
import argparse
import whois
from dns import zone, resolver, query, exception, rdatatype
import Mobile
import threading
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

class Crt:
    """Get the subdomains from CRT.sh"""
    def __init__(self, domain):
        self.domain = domain
        self.url = "https://crt.sh/?q={}".format(self.domain)
        
    def GetData(self):
        try:    
            responseCRT = requests.get(url=self.url)
            if responseCRT.status_code == 200:
                return responseCRT.content
            else:
                print_color("CRT.sh Not Responding",colors.RED)
        except Exception as error:
            print("[-] An exception occurred6: ",error)        
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
        return subdomains
class DNSBrute:
    """Bruteforce Subdomains"""
    def __init__(self, domain):
        self.domain = domain
        self.subdomains = []

    def listprep(self,wordlist,numOfChunks):
        for i in range(0, len(wordlist), numOfChunks):
            yield wordlist[i:i + numOfChunks]     
    def resolvehost(self,listt):
        for word in listt:
            try:             
                    hostname = "{}.{}".format(word.strip('\n'),self.domain)
                    res = resolver.Resolver()
                    answers = res.resolve(hostname)

                    if answers:
                        
                        ip_addresses = [rdata.address for rdata in answers]
                        print_color(f"Found: {hostname} - IP Addresses: {', '.join(ip_addresses)}",colors.PURPLE)
                        self.subdomains.append([hostname,', '.join(ip_addresses)])  
            except resolver.NXDOMAIN:
                pass
            except resolver.NoAnswer:
                pass
            except Exception as e:    
                print(f"Error occurred for {hostname}: {e}")
                pass
    def BruteForce(self,numofthreads,wordlist):
        threads = []
        print_color("[+] Wordlist: "+wordlist,colors.GREEN )
        with open(wordlist, 'r') as f:
             wordlist = f.readlines()
        if numofthreads>len(wordlist) or numofthreads<0:
            print_color("\n[-] Too High Value for Threads with Respect to Input Word-list\n",colors.RED)
            sys.exit(-1)
        numOfChunks=len(wordlist)//numofthreads
        listt = self.listprep(wordlist,numOfChunks)        
        for l in listt:
            threads.append(threading.Thread(target=self.resolvehost, args=(l,),daemon=True))
          
        for thread in threads:
            try:
                thread.start()
                
            except KeyboardInterrupt:
                print_color("\n[-] Received Keyboard Interrupt  , Terminating threads\n",colors.RED)
                sys.exit()
            
        for thread in threads:
            try:
               
                thread.join()
            except KeyboardInterrupt:
                print_color("\n[-] Received Keyboard Interrupt  , Terminating threads\n",colors.RED)
                sys.exit()    


    def execute(self,wordlist="./wordlists/DNSlist.txt",numofthreads=10):
        self.BruteForce(numofthreads,wordlist)
        return self.subdomains
        

class waybackmachine:
    """Get the WayBackmachine URLs and Subdomains"""
    def __init__(self, domain):
        self.domain = domain
    def GetData(self):
        try:
            url = "https://web.archive.org/cdx/search/cdx?url=*.{}/*&output=text&fl=original&collapse=urlkey".format(self.domain)
            responseWBM = requests.get(url=url)
            return responseWBM.content.decode('utf-8').split('\n')
        except Exception as error:
            print("[-] An exception occurred1: ",error)
    def FilterSubdomains(self,lst):
        subdomains = []
        for link in lst:
            if 'https://' in link:
                subdomains.append(link.replace('https://','').split('/')[0])
            elif 'http://' in link:
                subdomains.append(link.replace('http://','').split('/')[0])
            else:
                subdomains.append(link)
        # for i in list(set(subdomains)):
        #     print(i)
        return list(set(subdomains))
    def execute(self):
        data = self.GetData()
        subdomains = self.FilterSubdomains(data)
        for i in range(len(subdomains)):
            if ':' in subdomains[i]:
                subdomains[i] = subdomains[i].split(':')[0]
        return subdomains    






class Reverse_IP_lookup:
    """Reverse DNS lookups"""
    def __init__(self, domain):
        self.domain = domain
    def GetIPRange(self):
        try:
            url = "https://bgp.he.net/dns/{}#_ipinfo".format(self.domain)
            responseRIL = requests.get(url=url)
            IPrange = re.findall(br'/net/\d+.\d+.\d+.\d+/\d+',responseRIL.content)
            IPRanges = []
            for IP in IPrange:
                IPRanges.append(IP.decode('utf-8').replace('/net/',''))
            return IPRanges
        except Exception as error:
            print("[-] An exception occurred2: ",error)
    def GetHostByIP(self,IPaddress):
        try:
            host = socket.gethostbyaddr(IPaddress)
            return host
        except Exception as error:
            return False
    def bruteforceit(self,lst):
        subdomains = []
        for i in lst:
            for ip in ipaddress.IPv4Network(i):
                subdomains.append(self.GetHostByIP(ip))
        return(subdomains)        
    def execute(self):
        ips = self.GetIPRange()
        subdomains = self.bruteforceit(ips)
        return subdomains

class alienvault_lookup:
    """Getting subdomains from alienvault"""
    def __init__(self, domain):
        self.domain = domain
    def Request(self):
        try:
            url = "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns".format(self.domain)
            respalienvault = requests.get(url=url)
            subdomains = self.filterdata(respalienvault.text)
            return set(subdomains)
        except Exception as error:
            print("[-] An exception occurred3: ",error)
    def filterdata(self,content):
        subdomains = []
        for i in json.loads(content)["passive_dns"]:
            subdomains.append(i["hostname"])
        return subdomains
    def execute(self):
        subdomains = self.Request()
        return subdomains
class rapiddns:
    """rapiddns subdoains"""
    def __init__(self, domain):
        self.domain = domain
    def GetData(self):
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}#result"
            resprapiddns = requests.get(url=url)
            pattern = f'[\.a-zA-Z0-9-]+\.{self.domain}'
            subdomainslist = re.findall(pattern,resprapiddns.content.decode('utf-8'))   
            return subdomainslist 
        except Exception as error:
            print_color("Error",colors.Red)
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
                print(f"Found {AndroidSearch} ......")
                print("possible mobile application for the company. you can download it from APKpure for example and hit again with option --apk=<apk file>")
            else:
                print("No Mobile Found in the main page you can search and hit again with option apk --apk=<apk file> for mobile analysis")
        except Exception as error:
            print_color("[-] An exception occurred4: "+ error,colors.RED)
    
# web Crawler
class Web_Crawler:
    """Web Crawler"""
    def __init__(self, subdomainlst):
        self.Sublst = subdomainlst
    def checkHttp(self):
        pass            
    def collectwords():
        pass
    def Takescreenshot():
        pass
    def headers():
        pass
    def checkforKnownpaths():
        pass

def VerifySubdomains(subdomainlst):
    IPsAndSub = []
    for host in list(set(subdomainlst)):
        test =[]
        try:
            ipaddress = socket.gethostbyname(host)
            if ipaddress:
                test.append(host)
                test.append(ipaddress)
                IPsAndSub.append(test)
            else:
                continue
        except socket.gaierror:
            print_color(f"Unable to resolve hostname: {host}",colors.RED)  
        except Exception as error:
            print_color(f"An exception occurred6: {error}",colors.RED)     

       
    return IPsAndSub               
       
           
def WriteInCSV(lst,filepath):
    with open('{}.csv'.format(filepath), 'w',newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Hostnames,IP addresses"])
        for i in lst:
            writer.writerow(i)
def query_whois(domain):
    try:
        whois_info = whois.whois(domain)
        print_color(f"WHOIS information for domain: {domain}\n",colors.BOLD)
        for key, value in whois_info.items():
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            print_color(f"[+] {key.capitalize()}: {value}",colors.PURPLE)
    except whois.parser.PywhoisError as e:
        print(f"Error: {e}")
def perform_zone_transfer(domain, nameserver):
    try:
        resolvers = resolver.Resolver()
        ip_answer = resolvers.resolve(str(nameserver), rdtype=rdatatype.A)
        print_color(str(nameserver), colors.PURPLE)
        zone_transfer = zone.from_xfr(query.xfr(ip_answer.rrset[0].to_text(), domain, timeout=10))
        for name in zone_transfer.nodes.keys():
            print(zone_transfer[name].to_text(name))

    except exception.FormError:
        print_color("Zone transfer failed: Not Authorized or Zone Transfer not allowed.",colors.RED)
    except exception.Timeout:
        print_color("Zone transfer failed: Timeout",colors.RED)
    except Exception as e:
        print_color(f"Error: {e}",colors.RED)
def get_name_servers(domain):
    try:
        resolvers = resolver.Resolver()
        name_servers = resolvers.resolve(domain, 'NS')
        print_color(f"Name servers for {domain}:",colors.BOLD)
        for ns in name_servers:
            print_color(ns.to_text(),colors.PURPLE)
        return name_servers    
    except resolver.NoNameservers:
        print_color(f"No name servers found for {domain}",colors.RED)
    except Exception as e:
        print_color(f"Error: {e}",colors.RED)
def check_dns_records(domain):
    try:
        resolvers = resolver.Resolver()
           # Query TXT record
        txt_records = resolvers.resolve(domain, "TXT")
        if txt_records.response.answer:
            print_color("\nTXT Records:",colors.BOLD)
            for record in txt_records:
                print_color(record.to_text(),colors.PURPLE)
        # Query DMARC record
        dmarc_records = resolvers.resolve(f"_dmarc.{domain}", "TXT")
        if dmarc_records.response.answer:
            print_color("DMARC Records:",colors.BOLD)
            for record in dmarc_records:
                print_color(record.to_text(),colors.PURPLE)

     
    except resolver.NoAnswer:
        print("No records found.")
    except resolver.NXDOMAIN:
        print("Domain not found.")
    except Exception as e:
        print(f"Error: {e}")
# Site:pastebin.com | site:paste2.org | site:pastehtml.com | site:codebeautify.io | site:slexy.org | site:justpaste.it | site:codepen.io | site:github | site: gitlab.com   "wizardcyber.com"
# Class Cloud Enum
# Google dork site:pastebin.com | site:paste2.org | site:pastehtml.com | site:codebeautify.io | site:slexy.org | site:justpaste.it | site:codepen.io | site:github | site: gitlab.com   "domain"
# Checking http or https                  
# linkedin2username

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon Tool")
    subparsers = parser.add_subparsers(dest="mode", help="Modes of reconnaissance")

    # Passive subparser
    passive_parser = subparsers.add_parser("passive", help="Passive reconnaissance mode which include collecting subdomains, checking whois database, zonetransfer, DNSrecordcheck, reverseDNS lookup, getting ip address range")
    passive_parser.add_argument("-d", "--domain", required=True, help="Domain for active reconnaissance")
    passive_parser.add_argument("--csv",help="Specify the filename,to save the subdomains in csv")
    # Active subparser
    active_parser = subparsers.add_parser("active", help="Active reconnaissance mode which include collecting subdomains(passive and active), cloud enumeration , web crawling and analysis, taking screenshots, headers check, and the passive stuff")
    active_parser.add_argument("-d", "--domain", required=True, help="Domain for active reconnaissance")
    active_parser.add_argument("--csv",help="Specify the filename,to save the subdomains in csv")
    active_parser.add_argument("--threads","-t",help="Specify the number of threads for dns bruteforcing. DEFAULT=10")
    active_parser.add_argument("--wordlist","-w",help="Specify the wordlist for dns bruteforcing. DEFAULT=./wordlists/DNSlist.txt")
    # APK subparser
    apk_parser = subparsers.add_parser("apk", help="apk reconnaissance mode which include collecting URLs, root detection check, certificate check, SDK version check, decompiling APK to smali and java, extracting sensitive information, checking if the app is in debuggable mode, checking permissions, checking activities and (Exported Activites),  Check if backup is allowed, collecting strings.xml files")
    apk_parser.add_argument("--apk",required=True, help="apk for mobile reconnaissance")
    args = parser.parse_args()

    if args.mode == "passive":
        AllColSubDom = []
        rapiddnss = rapiddns(args.domain)
        rapiddnsSub = rapiddnss.GetData()
        for i in rapiddnsSub:
            AllColSubDom.append(i)    
        crt = Crt(args.domain)
        CrtSub = Crt.execute(self=crt)
        for i in CrtSub:
            AllColSubDom.append(i)
        wayback = waybackmachine(args.domain)
        waybackSub = wayback.execute()
        for i in waybackSub:
            AllColSubDom.append(i)
        alienvault = alienvault_lookup(args.domain)
        alienvaultSub = alienvault.execute()
        for i in alienvaultSub:
            AllColSubDom.append(i)
        print_color("All Collected Subdomains:",colors.BOLD)
        for i in list(set(AllColSubDom)):
            print_color(i,colors.PURPLE)
        print_color("[+] Verifying each on of them....",colors.GREEN)    
        Finallst = VerifySubdomains(AllColSubDom)
        print_color("[+] verified Subdomains List: ",colors.BOLD)  
        for i in Finallst:
            print_color(f"{i[0]}\t\t{i[1]}",colors.PURPLE)    
        if args.csv != None:
            WriteInCSV(list(set(AllColSubDom)),args.csv)
        revdnslookup = Reverse_IP_lookup(args.domain)
        ipranges = revdnslookup.GetIPRange()
        print_color(f"{args.domain} IP address ranges:",colors.BOLD)
        for i in ipranges:
            print_color(i,colors.PURPLE)
        print_color("[+] reversing it...",colors.GREEN)
        subdomrev = revdnslookup.execute()
        for i in subdomrev:
            if i != False:
                print_color(i, colors.PURPLE)
        query_whois(args.domain)
        namservers  = get_name_servers(args.domain)
        print_color("[+] Performing zone transfer",colors.BOLD)
        for i in namservers:
            perform_zone_transfer(args.domain,i)  
        check_dns_records(args.domain)      
    elif args.mode == "active":
        AllColSubDom = []
        rapiddnss = rapiddns(args.domain)
        rapiddnsSub = rapiddnss.GetData()
        for i in rapiddnsSub:
            AllColSubDom.append(i)      
        crt = Crt(args.domain)
        CrtSub = Crt.execute(self=crt)
        for i in CrtSub:
            AllColSubDom.append(i)
        wayback = waybackmachine(args.domain)
        waybackSub = wayback.execute()
        for i in waybackSub:
            AllColSubDom.append(i)
        alienvault = alienvault_lookup(args.domain)
        alienvaultSub = alienvault.execute()
        for i in alienvaultSub:
            AllColSubDom.append(i)
        print_color("All Collected Subdomains:",colors.BOLD)
        for i in list(set(AllColSubDom)):
            print_color(i,colors.PURPLE)
        print_color("[+] Verifying each on of them....",colors.GREEN)    
        Finallst = VerifySubdomains(AllColSubDom)
        print_color("[+] verified Subdomains List: ",colors.BOLD)  
        for i in Finallst:
            print_color(f"{i[0]}\t\t{i[1]}",colors.PURPLE)    
        revdnslookup = Reverse_IP_lookup(args.domain)
        ipranges = revdnslookup.GetIPRange()
        print_color(f"{args.domain} IP address ranges:",colors.BOLD)
        for i in ipranges:
            print_color(i,colors.PURPLE)
        print_color("[+] reversing it...",colors.GREEN)
        subdomrev = revdnslookup.execute()
        for i in subdomrev:
            if i != False:
                print_color(i, colors.PURPLE)
        query_whois(args.domain)
        namservers  = get_name_servers(args.domain)
        print_color("[+] Performing zone transfer",colors.BOLD)
        for i in namservers:
            perform_zone_transfer(args.domain,i)  
        check_dns_records(args.domain) 
        print_color("[+] Subdomains BruteForcing Started: ",colors.BOLD)
        print_color("Go Get Some Coffeee it will take time (:",colors.YELLOW)
        DNSbrt = DNSBrute(args.domain)
        if args.wordlist != None and args.threads != None:
            DNSbrtSub = DNSbrt.execute(wordlist=args.wordlist,numofthreads=int(args.threads))
        elif args.wordlist != None:
            DNSbrtSub = DNSbrt.execute(wordlist=args.wordlist)    
        elif args.threads != None:
            DNSbrtSub = DNSbrt.execute(numofthreads=int(args.threads))
        else:
            DNSbrtSub = DNSbrt.execute()
        for i in DNSbrtSub:
            Finallst.append(i)
        if args.csv != None:
            WriteInCSV(Finallst,args.csv)                
    elif args.mode == "apk":
        MobileAn = Mobile.Mobile_analysis(args.apk)
        MobileAn.execute()

