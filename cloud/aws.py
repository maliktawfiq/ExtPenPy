import requests
import re
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


class AWS_Buckets:
    """Hunting publicly accessible S3 bucket on AWS cloud"""
    baseurl = '.s3.amazonaws.com'
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'}
    def __init__(self, domain, numOfThreads = 10):
        self.threads=numOfThreads
        self.domain=domain
        self.buckets=[]

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

        for w in words:     #$company-#word
            file.write(str(Company) + '-' + w + '\n')

        for w in words:     #$company-#word
            file.write(str(Company) + '_' + w + '\n')
        
        for w in words:     #$word$company$word
            file.write( w + str(Company) + w + '\n')

        for w in words:     #$word$word$company
            file.write(w+w+str(Company)+'\n')
        
        for w in words:     #$Company$word$word
            file.write(str(Company)+w+w + '\n')

        file.close()

    def bucket_parse(self, url):
        req=open('req.xml','r').read()
        key_regex = re.compile(r'<(?:Key)>(.*?)</(?:Key)>')

        keys=re.findall(key_regex, req)
        for key in keys:
            print_color(f"\t{key}", colors.GREEN)
        
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

        if len(self.buckets) == 0 :
            print_color("[-] No buckets were found", colors.RED)


    def accounts_requests(self,wordlist):
        temp_storage=[]
        temp_name=''
        for names in wordlist:
            try:
                url="http://"+names+self.baseurl
                req=requests.get(url,headers=self.headers, timeout=None)   
                if req.status_code == 200:
                    print_color(f'Found public bucket: {url}', colors.GREEN)
                    self.buckets.append(url)
              
                elif req.status_code == 403:
                    self.buckets.append(url)
                    print_color(f'Found protected bucket: {url}', colors.BLUE)
            except:
                pass
            
    def execute(self):
        self.prepare_domain()
        self.permutation()
        self.bruteforce(self.threads)

