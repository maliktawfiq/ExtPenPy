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
from web.web import webCrawl
from cloud.aws import AWS_Buckets
from cloud.azure import azure_blobs
from cloud.gcp import GCP_Buckets
import itertools
import time


#animation Function
done=False
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            sys.stdout.write("\033[F")  
            sys.stdout.write("\033[F") 
            sys.stdout.write("\033[K") 
            break

        sys.stdout.write('\033[92m\rCollecting subdomains ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    

#colors class
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


#CRT.sh enumeration
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
        try:
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
        except:
            pass      
    def sortanduniqe(self,lst):
        try:
            sorted = list(set(lst))
            final = []
            for i in sorted:
                final.append(i.decode("utf-8"))
            return final
        except:
            pass
    def execute(self):
        data=self.GetData()
        subs = self.filterdata(data=data)
        subdomains = self.sortanduniqe(subs)
        return subdomains


#Bruteforce Subdomains
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
        
# waybackmachine enumeration
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
        if lst != None:
            for link in lst:
                if 'https://' in link:
                    subdomains.append(link.replace('https://','').split('/')[0])
                elif 'http://' in link:
                    subdomains.append(link.replace('http://','').split('/')[0])
                else:
                    subdomains.append(link)
        return list(set(subdomains))
    def execute(self):
        data = self.GetData()
        subdomains = self.FilterSubdomains(data)
        for i in range(len(subdomains)):
            if ':' in subdomains[i]:
                subdomains[i] = subdomains[i].split(':')[0]
        return subdomains    





# Reverse DNS lookups
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
    
# alienvault enumeration
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
            print_color(f"[-] An exception occurred3: {error}",colors.RED)
    def filterdata(self,content):
        subdomains = []
        for i in json.loads(content)["passive_dns"]:
            subdomains.append(i["hostname"])
        return subdomains
    def execute(self):
        subdomains = self.Request()
        return subdomains
    
# rapiddns enumeration
class rapiddns:
    """rapiddns subdomains"""
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
            print_color("Error",colors.RED)

            

    
# Regex Class
def Regex(domain):
    pastebins = f'site:pastebin.com | site:paste2.org | site:pastehtml.com | site:codebeautify.io | site:slexy.org | site:justpaste.it | site:codepen.io "{domain}"'
    print_color("1- Pastebins check:",colors.BOLD)
    print_color(pastebins,colors.PURPLE)
    SenExt = f'site:"{domain}" ext:log | ext:txt | ext:json | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:htapasswd | ext:htaccess'
    print_color("2- senstive extenstions check:",colors.BOLD)
    print_color(SenExt,colors.PURPLE)
    AdminPages= f'inurl:admin site:"{domain}"'
    print_color("3- Admin pages check:",colors.BOLD)
    print_color(AdminPages,colors.PURPLE)
    APIDOCS = f'inurl:apidoc | inurl:api-doc | inurl:swagger | inurl:api-explorer site:"{domain}"'
    print_color("4- API documentation check:",colors.BOLD)
    print_color(APIDOCS,colors.PURPLE)
    CloudStor = f'site:s3.amazonaws.com | site:blob.core.windows.net | site:googleapis.com | site:drive.google.com | site:dev.azure.com | site:onedrive.live.com | site:digitaloceanspases.com | site:sharepoint.com "{domain}"'
    print_color("5- Cloud storages check:",colors.BOLD)
    print_color(CloudStor,colors.PURPLE)


# subdomains verification
def VerifySubdomains(subdomainlst,flag):
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
            if flag:
                pass
                
            else:
                pass  
        except Exception as error:
            if flag:
                print_color(f"An exception occurred6: {error}",colors.RED)     
            else:
                pass
       
    return IPsAndSub               
       
# writing to CSV           
def WriteInCSV(lst,filepath):
    with open('{}.csv'.format(filepath), 'w',newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Hostnames","IP addresses"])
        for i in lst:
            writer.writerow(i)

#whois Database check
def query_whois(domain):
    try:
        whois_info = whois.whois(domain)
        print_color(f"WHOIS information for domain: {domain}\n",colors.BOLD)
        for key, value in whois_info.items():
            if isinstance(value, list):
                value = ', '.join(map(str, value))
            print_color(f"[+] {key.capitalize()}: {value}",colors.PURPLE)
        print()    
    except Exception as e:
        print_color(f"Error: {e}",colors.RED)

# Zone Transfer        
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

# nameservers enumeration        
def get_name_servers(domain):
    try:
        resolvers = resolver.Resolver()
        name_servers = resolvers.resolve(domain, 'NS')
        print_color(f"Name servers for {domain}:",colors.BOLD)
        for ns in name_servers:
            print_color(ns.to_text(),colors.PURPLE)
        print()    
        return name_servers    
    except resolver.NoNameservers:
        print_color(f"No name servers found for {domain}",colors.RED)
    except Exception as e:
        print_color(f"Error: {e}",colors.RED)

# dns records check        
def check_dns_records(domain):
    try:
        resolvers = resolver.Resolver()
        txt_records = resolvers.resolve(domain, "TXT")
        if txt_records.response.answer:
            print_color("\nTXT Records:",colors.BOLD)
            for record in txt_records:
                print_color(record.to_text(),colors.PURPLE)
        print()        
        dmarc_records = resolvers.resolve(f"_dmarc.{domain}", "TXT")
        if dmarc_records.response.answer:
            print_color("DMARC Records:",colors.BOLD)
            for record in dmarc_records:
                print_color(record.to_text(),colors.PURPLE)
        print()
     
    except resolver.NoAnswer:
        print("No records found.")
    except resolver.NXDOMAIN:
        print("Domain not found.")
    except Exception as e:
        print(f"Error: {e}")

# passive module with pip
def PipFunctionsCall():
    AllColSubDom = []
    rapiddnss = rapiddns(args.domain)
    rapiddnsSub = rapiddnss.GetData()
    if rapiddnsSub != None:
        for i in rapiddnsSub:
            AllColSubDom.append(i)                
    crt = Crt(args.domain)
    CrtSub = Crt.execute(self=crt)
    if CrtSub != None:
        for i in CrtSub:
            AllColSubDom.append(i)
    wayback = waybackmachine(args.domain)
    waybackSub = wayback.execute()
    if waybackSub != None:
        for i in waybackSub:
            AllColSubDom.append(i)
    alienvault = alienvault_lookup(args.domain)
    alienvaultSub = alienvault.execute()
    if alienvaultSub != None:    
        for i in alienvaultSub:
            AllColSubDom.append(i)  
    Finallst = VerifySubdomains(AllColSubDom,False) 
    for i in range(1,len(Finallst)):
            print_color(f"{Finallst[i][0]}",colors.PURPLE)  

# passive module without pip
def PassiveFunctionCall():
    t = threading.Thread(target=animate)
    t.start()
    AllColSubDom = []
    rapiddnss = rapiddns(args.domain)
    rapiddnsSub = rapiddnss.GetData()
    if rapiddnsSub != None:
        for i in rapiddnsSub:
            AllColSubDom.append(i) 
    crt = Crt(args.domain)
    CrtSub = Crt.execute(self=crt)
    if CrtSub != None:
        for i in CrtSub:
            AllColSubDom.append(i)

    wayback = waybackmachine(args.domain)
    waybackSub = wayback.execute()
    if waybackSub != None:
        for i in waybackSub:
            AllColSubDom.append(i)

    alienvault = alienvault_lookup(args.domain)
    alienvaultSub = alienvault.execute()
    if alienvaultSub != None:
        for i in alienvaultSub:
            AllColSubDom.append(i)
    global done  
    done = True
    t.join()        
    print_color("\n\nAll Collected Subdomains:",colors.BOLD)
    
    for i in list(set(AllColSubDom)):
        print_color(i,colors.PURPLE)
    print_color("\n[+] Verifying each one of them....",colors.GREEN)  

    Finallst = VerifySubdomains(AllColSubDom,True)
    print_color("[+] verified Subdomains List: ",colors.BOLD)  

    c_max_len = 0
    for i in range(1, len(Finallst)):
        c_max_len = max(len(Finallst[i][0]), c_max_len)

    for i in range(1, len(Finallst)):
        print_color(f"{Finallst[i][0]}{' '*(c_max_len + 4 - len(Finallst[i][0]))}{Finallst[i][1]}", colors.PURPLE)    
    if args.csv != None:
        WriteInCSV(Finallst,args.csv)

    print()    
    revdnslookup = Reverse_IP_lookup(args.domain)
    ipranges = revdnslookup.GetIPRange()
    print_color(f"[+] {args.domain} IP address ranges:",colors.BOLD)
    if ipranges != None:
        for i in ipranges:
            print_color(i,colors.PURPLE)
        print()    
        print_color("[+] reversing it...",colors.GREEN)
        print()
        subdomrev = revdnslookup.execute()
        for i in subdomrev:
            if i != False:
                print_color(i, colors.PURPLE)

    query_whois(args.domain)

    namservers  = get_name_servers(args.domain)
    print_color("[+] Performing zone transfer",colors.BOLD)
    if namservers != None:
        for i in namservers:
            perform_zone_transfer(args.domain,i) 

    check_dns_records(args.domain)

    print_color("Now to finish up the recon phase check the following interesting google dorks:",colors.BOLD)
    Regex(args.domain)
    print_color("Finally do not forget to check github and gitlab. Ref: https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets",colors.BLUE)
    print_color("          Happy Hacking!           ",colors.GREEN)

# active module
def ActiveFunctionCall():
    print_color(logo,colors.RED)

    t = threading.Thread(target=animate)
    t.start()
    AllColSubDom = []
    rapiddnss = rapiddns(args.domain)
    rapiddnsSub = rapiddnss.GetData()
    if rapiddnsSub != None:
        for i in rapiddnsSub:
            AllColSubDom.append(i)  

    crt = Crt(args.domain)
    CrtSub = Crt.execute(self=crt)
    if CrtSub != None:
        for i in CrtSub:
            AllColSubDom.append(i)

    wayback = waybackmachine(args.domain)
    waybackSub = wayback.execute()
    if waybackSub != None:    
        for i in waybackSub:
            AllColSubDom.append(i)

    alienvault = alienvault_lookup(args.domain)
    alienvaultSub = alienvault.execute()
    if alienvaultSub != None:
        for i in alienvaultSub:
            AllColSubDom.append(i)

    global done  
    done = True
    t.join()        
    print_color("\n\nAll Collected Subdomains:",colors.BOLD)
    for i in list(set(AllColSubDom)):
        print_color(i,colors.PURPLE)
    print_color("\n\n[+] Verifying each one of them....",colors.GREEN)    
    Finallst = VerifySubdomains(AllColSubDom,True)
    print()
    print_color("[+] verified Subdomains List: ",colors.BOLD)  
    c_max_len = 0
    for i in range(1, len(Finallst)):
        c_max_len = max(len(Finallst[i][0]), c_max_len)

    for i in range(1, len(Finallst)):
        print_color(f"{Finallst[i][0]}{' '*(c_max_len + 4 - len(Finallst[i][0]))}{Finallst[i][1]}", colors.PURPLE)
            
    revdnslookup = Reverse_IP_lookup(args.domain)
    ipranges = revdnslookup.GetIPRange()
    print()
    print_color(f"{args.domain} IP address ranges:",colors.BOLD)
    if ipranges != None:
        for i in ipranges:
            print_color(i,colors.PURPLE)
        print_color("[+] reversing it...",colors.GREEN)
        print()
        subdomrev = revdnslookup.execute()
        for i in subdomrev:
            if i != False:
                print_color(i, colors.PURPLE)

    query_whois(args.domain)

    namservers  = get_name_servers(args.domain)
    print_color("[+] Performing zone transfer",colors.BOLD)
    if namservers != None:
        for i in namservers:
            perform_zone_transfer(args.domain,i) 

    check_dns_records(args.domain)


    
    if args.threads != None:
        aws_bucket=AWS_Buckets(args.domain, args.threads)
        Azure_blobs=azure_blobs(args.domain, args.threads)
        GCP_blobs=GCP_Buckets(args.domain,args.threads)
    else:
        aws_bucket=AWS_Buckets(args.domain)
        Azure_blobs=azure_blobs(args.domain)
        GCP_blobs=GCP_Buckets(args.domain)

  
     
    print_color("[+] Starting AWS Cloud Enumeration..",colors.BOLD)
    aws_bucket.execute()
    print()
    print_color("[+] Starting Azure Cloud Enumeration..",colors.BOLD)
    Azure_blobs.execute()
    print()
    print_color("[+] Starting GCP Cloud Enumeration..",colors.BOLD)
    GCP_blobs.execute()
    print()
    if args.extensive != True:
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
    temp=[]
    
    for j in range(len(Finallst)):    
        temp.append(Finallst[j][0])
    web=webCrawl(temp,args.domain,args.extensive)
    web.execute()     
    

    if args.csv != None:
        WriteInCSV(Finallst,args.csv)
    print_color("Now to finish up the recon phase check the following interesting google dorks:",colors.BOLD)
    Regex(args.domain)
    print_color("Finally do not forget to check github and gitlab. Ref: https://book.hacktricks.xyz/generic-methodologies-and-resources/external-recon-methodology/github-leaked-secrets",colors.BLUE)
    print_color("          Happy Hacking!           ",colors.GREEN)    
if __name__ == "__main__":

    
    parser = argparse.ArgumentParser(description="This tool will help you to finish the recon phase quickly XD")
    subparsers = parser.add_subparsers(dest="mode", help="Modes of reconnaissance")

 
    passive_parser = subparsers.add_parser("passive", help="Passive reconnaissance mode which include collecting subdomains, checking whois database, zonetransfer, DNSrecordcheck, reverseDNS lookup, getting ip address range")
    passive_parser.add_argument("-d", "--domain", required=True, help="Domain for active reconnaissance")
    passive_parser.add_argument("--pip","-p",action='store_true',help="To allow piping the subdomain output to another tool")
    passive_parser.add_argument("--csv",help="Specify the filename,to save the subdomains in csv")
 
    active_parser = subparsers.add_parser("active", help="Active reconnaissance mode which include collecting subdomains(passive and active), cloud enumeration , web crawling and analysis, taking screenshots, headers check, and the passive stuff")
    active_parser.add_argument("-d", "--domain", required=True, help="Domain for active reconnaissance")
    active_parser.add_argument("--csv",help="Specify the filename,to save the subdomains in csv")
    active_parser.add_argument("--threads","-t",help="Specify the number of threads for dns bruteforcing. DEFAULT=10")
    active_parser.add_argument("--wordlist","-w",help="Specify the wordlist for dns bruteforcing. DEFAULT=./wordlists/DNSlist.txt")
    active_parser.add_argument("--extensive","-e",action='store_false',help="To run DNS bruteforcing and to check known paths")
    apk_parser = subparsers.add_parser("apk", help="apk reconnaissance mode which include collecting URLs, root detection check, certificate check, SDK version check, decompiling APK to smali and java, extracting sensitive information, checking if the app is in debuggable mode, checking permissions, checking activities and (Exported Activites),  Check if backup is allowed, collecting strings.xml files")
    apk_parser.add_argument("--apk",required=True, help="apk for mobile reconnaissance")
    args = parser.parse_args()
    logo = """
  ______        _    _____              _____        
 |  ____|      | |  |  __ \            |  __ \       
 | |__   __  __| |_ | |__) |___  _ __  | |__) |_   _ 
 |  __|  \ \/ /| __||  ___// _ \| '_ \ |  ___/| | | |
 | |____  >  < | |_ | |   |  __/| | | || |    | |_| |
 |______|/_/\_\ \__||_|    \___||_| |_||_|     \__, |
                                                __/ |
                                               |___/                                                                                          
"""
    
    if len(sys.argv) == 1:
        print("Use -h or --help to see the options")
        exit()
    if args.mode == "passive":
        if args.pip:
            pass
        else:
            print_color(logo,colors.RED)
            print("\n")

        if args.pip:
            PipFunctionsCall()
        else:
            PassiveFunctionCall()

    elif args.mode == "active":
        ActiveFunctionCall()
    elif args.mode == "apk":
        print_color(logo,colors.RED)
        print("\n")
        MobileAn = Mobile.Mobile_analysis(args.apk)
        MobileAn.execute()
        print_color("          Happy Hacking!           ",colors.GREEN)
