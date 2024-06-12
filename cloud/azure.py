import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor


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


    
class azure_blobs:
    """Hunting publicly accessible blobs on Azure cloud"""
    baseurl = '.blob.core.windows.net'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
    def __init__(self,domain,numOfThreads=5):
        self.domain=domain
        self.threads=numOfThreads
        self.mutex = threading.Lock()
        self.accounts=[]
        self.containers_counter=0
        self.containers=[]
        self.containers_dict={}
        self.debug_counter=0


    def prepare_wordlist(self, wordlist, numOfChunks):
        for i in range(0, len(wordlist), numOfChunks):
            yield wordlist[i:i + numOfChunks]


    def prepare_domain(self):
        if len(self.domain.split(".")) >1:
            self.domain=self.domain.split(".")[0]
    
    def prep_storage_wordlist(self):
        storage_words=open("wordlists/wordlist.txt", 'r').read().splitlines()
        return storage_words
    
    def prep_containers_wordlist(self):
        containers_words=open("wordlists/containers.txt", 'r').read().splitlines()
        return containers_words

    def permutation(self): 
        Company=self.domain
    
        words=open("wordlists/Permutations.txt", "r").read().splitlines()

        file=open("wordlists/wordlist.txt", 'w') # first time we need to overwrite
        file.write(str(Company)+'\n')

        for w in words:    # first write $Company$word
            file.write(str(Company)+w+'\n')
        
        file.close()

        file=open("wordlists/wordlist.txt", 'a')

        for w in words:     #$word$company
            file.write(w + str(Company) + '\n')
        
        for w in words:     #$word$company$word
            file.write( w + str(Company) + w + '\n')

        for w in words:     #$word$word$company
            file.write(w+w+str(Company)+'\n')
        
        for w in words:     #$Company$word$word
            file.write(str(Company)+w+w + '\n')

        file.close()

    def accounts_requests(self,wordlist):
        temp_name=''
        
        for names in wordlist:
            url="https://"+names+self.baseurl
            try:
                req=requests.get(url,headers=self.headers, timeout=None)
                
           
            
                temp_name=str(url).replace("https://", "")
                print_color(f"Found Storage account: {temp_name}", colors.GREEN)
                self.accounts.append(temp_name)
                with self.mutex:
                    self.containers_counter=self.containers_counter + 1

           

                self.prepare_urls(temp_name)

            except Exception as e:
                pass

    def prepare_urls(self, account):

        with self.mutex:
            wordlist=self.prep_containers_wordlist()
            urls=[]
            self.containers_dict[account] = []

            for words in wordlist:
                urls.append(f"https://{account}/{words}?restype=container&comp=list")

        with ThreadPoolExecutor(max_workers=5) as executor:
            executor.map(self.send_requests, urls)


    def send_requests(self,url):
        account=url.split("/")[2]
        try:
            list_req= requests.get(url, headers=self.headers)
            with self.mutex:
                self.debug_counter+=1
            if list_req.status_code == 200:
                self.containers_dict[account].append(url)
        except:
            pass
    



    def bruteforce(self, numofthreads):
        wordlist1=self.prep_storage_wordlist()
        threads=[]
        numofthreads=int(numofthreads)

        if numofthreads>len(wordlist1) or numofthreads<0:
            print_color("\n[-] Too High Value for Threads with Respect to Input Word-list\n",colors.RED)
            exit()

        numOfChunks=len(wordlist1)//numofthreads
        listt = self.prepare_wordlist(wordlist1,numOfChunks)

        for l in listt:

            threads.append(threading.Thread(target=self.accounts_requests, args=(l,),daemon=True))
          
        for thread in threads:
            try:
                thread.start()

            except KeyboardInterrupt:
                print_color("\n[-] Received Keyboard Interrupt  , Terminating threads\n",colors.RED)
                exit()
        
        
        for thread in threads:
            try:
               
                thread.join()
            except KeyboardInterrupt:
                print_color("\n[-] Received Keyboard Interrupt  , Terminating threads\n",colors.RED)
                exit()

        
    def print_findings(self):
        if len(self.accounts) == 0:
            print_color("[-] No buckets were found",colors.RED)
        else:
            domains=self.containers_dict.keys()
            for domain in domains:
                if len(self.containers_dict[domain]) == 0:
                    continue
                else:
                    print_color(f"[+] URLs for containers found for account: {domain}",colors.BOLD)
                    for i in range(len(self.containers_dict[domain])):
                        print_color(f"\t{self.containers_dict[domain][i]}", colors.GREEN)
                    
    
    def execute(self):
        self.prepare_domain()
        self.permutation()
        self.bruteforce(self.threads)
        self.print_findings()
    
      


