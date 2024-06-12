import os 
from zipfile import ZipFile 
import shutil
from androguard.core.axml import AXMLPrinter
import androguard.util as test
import re
from androguard.core.apk import APK
import apk2java

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
test.set_log("CRITICAL")
class Mobile_analysis:
    def __init__(self,apk_path):
        self.apk = apk_path

    def Decompiler(self):
        if not os.path.exists(self.apk):
            print_color("[-] Error: couldn't find the apk!",colors.RED)
        else:
            if os.path.isdir("./JavaCode"):
                print_color("[+] Old Directory found, Deleting..." , colors.GREEN)
                print_color("[+] Extracting Data...",colors.GREEN)
                shutil.rmtree("./JavaCode")
            apk2java.decompile(self.apk, "./JavaCode")
    def extract_links(self,content):
        url_pattern = re.compile(rb'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        matches = url_pattern.findall(content)
        return matches
    def root_detection_check(self,content):
        root_detection_strings = [
                b"/system/app/Superuser.apk", b"/sbin/su",
                b"/system/bin/su", b"/system/xbin/su", b"/data/local/xbin/su",
                b"/data/local/bin/su", b"/system/sd/xbin/su", 
                b"/system/bin/failsafe/su", b"/data/local/su", b"/su/bin/su",
                b"test-keys", b'"/system/xbin/which", "su"', b"'/system/xbin/which', 'su'",
            ]
        found = []
        for i in root_detection_strings:
            if i in content:
                found.append(i.decode('utf-8'))    
                
        return found    
    def extract_passwords(self,content):
        sensitive_words = [
    b"Password",
    b"Passphrase",
    b"Secret",
    b"API key",
    b"Access key",
    b"Private key",
    b"Public key",
    b"Token",
    b"Credential",
    b"Auth token",
    b"Session key",
    b"Encryption key",
    b"Authentication code",
    b"Security code",
    b"API secret",
    b"API token",
    b"API passphrase",
    b"API password",
    b"API credential",
    b"API authentication",
    b"pwd",]
        found = []
        for i in sensitive_words:
            if i.lower()  in content.lower():
                found.append(i)
        return found
    
    def code_inspection(self,directory):
        urls = set()
        passwords = []
        for root, dirs, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
              
                if os.path.isfile(filepath):
                    with open(filepath, 'rb') as file:
                        content = file.read()
                        if "strings.xml" in filepath:
                            print_color("[+] strings.xml file found check for senstive data, PATH: "+filepath,colors.GREEN)
                        links = self.extract_links(content)
                        passw = self.extract_passwords(content)
                        root_detection = self.root_detection_check(content)
                        if len(root_detection) != 0:
                            print_color("[+] Possible root detection detected. Path: "+filepath+"  Strings detected: ",colors.GREEN)
                            for i in root_detection:
                                print_color(i,colors.PURPLE) 
                        urls.update(links)
                        passwords.append((passw,filepath))
                   
                       
        print_color("[+] Links Found:",colors.BOLD)
        for link in urls:
            print_color(link.decode('utf-8'),colors.PURPLE)
        print_color("[+] Senstive file to be checked:",colors.BOLD)
        f = open("Filestobechecked.txt", "w")
        f.write("Senstive file to be checked:\n")
        for password in passwords:
            if len(password[0]) == 0:
                continue
            else:
                f.write(password[1]+'\t'+' '.join(str(x) for x in password[0])+'\n')
        f.close()
        print_color("[+] Kindly check a file called 'Filestobechecked.txt' for senstive paths to be checked",colors.GREEN)



    def decompiling(self):
        if not os.path.exists(self.apk):
            print_color("[-] Error: couldn't find the apk!",colors.RED)
        if os.path.isdir("./apk_decomiled"):
            print_color("[+] Old Directory found, Deleting...",colors.GREEN)
            print_color("[+] Extracting Data...",colors.GREEN)
            shutil.rmtree("./apk_decomiled")
            with ZipFile(self.apk, 'r') as file:
                file.extractall(path="./apk_decomiled/")
        else:
             print_color("[+] Extracting Data...",colors.GREEN)
             with ZipFile(self.apk, 'r') as file:
                file.extractall(path="./apk_decomiled/")
        try:
            with open("./apk_decomiled/AndroidManifest.xml", 'rb') as f:
                axml_data = f.read()
                axml_printer = AXMLPrinter(axml_data)
                xml_content = axml_printer.get_xml()
                AndroidVersion = re.findall(rb'android:versionName="([^"]+)"',xml_content)
                Package = re.findall(rb'package="([^"]+)"', xml_content)
                MinSdk = re.findall(rb'minSdkVersion="(\d+)"', xml_content)
                TargetSDK = re.findall(rb'targetSdkVersion="(\d+)"', xml_content)
                Permissions = re.findall(rb'<uses-permission android:name="([^"]+)"', xml_content)
                Activites = re.findall(rb'<activity[^>]+android:name="([^"]+)"[^>]*>', xml_content)
                ExportedActivites = re.findall(rb'<activity[^>]+android:name="([^"]+)"[^>]*android:exported="true"', xml_content)
                allowbackup = re.findall(rb'allowBackup="([^"]+)"', xml_content)
                debuggable = re.findall(rb'debuggable="([^"]+)"', xml_content)
                print_color("[+] Package name: "+ Package[0].decode("utf-8"),colors.GREEN)
                print_color("[+] Android Version: "+AndroidVersion[0].decode("utf-8"),colors.GREEN)
                print_color("[+] Target SDK: "+ TargetSDK[0].decode("utf-8"),colors.GREEN)
                print_color("[+] Minimum SDK: "+ MinSdk[0].decode("utf-8"),colors.GREEN)
                if allowbackup:
                    print_color('[+] allowBackup value: '+ allowbackup[0].decode("utf-8"),colors.GREEN)
                else:
                    print_color('[+] allowBackup: False',colors.GREEN)
                if debuggable:
                    print_color('[+] debuggable value: '+ allowbackup[0].decode("utf-8"),colors.GREEN)
                else:
                    print_color('[+] debuggable: False',colors.GREEN)        
                print_color("Permissions: ",colors.BOLD)
                for i in Permissions:
                    print_color("[+] " + i.decode("utf-8"),colors.PURPLE)
                print_color("Activites:",colors.BOLD)
                for i in Activites:
                    print_color("[+] " + i.decode("utf-8"),colors.PURPLE)
                print_color("Exported Activites:",colors.BOLD)
                for i in ExportedActivites:
                    print_color("[+] " + i.decode("utf-8"),colors.PURPLE)
        except Exception as error:
            print("[-] Error parsing the AndroidManifest.xml file: ",error)
 
            
        
    def CheckCertificate(self):
        print_color("Certificate Check:",colors.BOLD)
        a = APK(self.apk)
        print_color("[+] APK is signed: {}".format(a.is_signed()),colors.GREEN)
        if a.is_signed():

            print_color("[+] APK is signed with: {}".format("both V1 & V2" if a.is_signed_v1() and
            a.is_signed_v2() else "v1" if a.is_signed_v1() else "v2"),colors.GREEN)    
        
        certificates = a.get_certificates_v2()
        for cert in certificates:
            print_color("[+] Subject: "+ str(cert.subject),colors.PURPLE)
            print_color("[+] Issuer: "+ str(cert.issuer),colors.PURPLE)
            print_color("[+] Serial number: "+ str(cert.serial_number),colors.PURPLE)
            print_color("[+] Not valid before: "+ str(cert.not_valid_before),colors.PURPLE)
            print_color("[+] Not valid after: "+ str(cert.not_valid_after),colors.PURPLE)
            print_color("[+] Signature algorithm: "+ str(cert.signature_algo),colors.PURPLE)
            print_color("[+] Public key algorithm: "+ str(cert.hash_algo),colors.PURPLE)
    def execute(self):
        self.Decompiler()
        self.decompiling()
        self.CheckCertificate()
        self.code_inspection("./JavaCode")
     
        
            