import os 
from zipfile import ZipFile 
import shutil
from androguard.core.axml import AXMLPrinter
import androguard.util as test
import re
from androguard.core.apk import APK
import apk2java
import sys

test.set_log("CRITICAL")
class Mobile_analysis:
    def __init__(self,apk_path):
        self.apk = apk_path

    def Decompiler(self):
        if not os.path.exists(self.apk):
            print("[-] Error: couldn't find the apk!")
        else:
            if os.path.isdir("./JavaCode"):
                print("[+] Old Directory found, Deleting...")
                print("[+] Extracting Data...")
                shutil.rmtree("./JavaCode")
            apk2java.decompile(self.apk, "./JavaCode")

    # def get_urls():


    def decompiling(self):
        if not os.path.exists(self.apk):
            print("[-] Error: couldn't find the apk!")
        if os.path.isdir("./apk_decomiled"):
            print("[+] Old Directory found, Deleting...")
            print("[+] Extracting Data...")
            shutil.rmtree("./apk_decomiled")
            with ZipFile(self.apk, 'r') as file:
                file.extractall(path="./apk_decomiled/")
        else:
             print("[+] Extracting Data...")
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
                print("[+] Package name: "+ Package[0].decode("utf-8"))
                print("[+] Android Version: "+AndroidVersion[0].decode("utf-8"))
                print("[+] Target SDK: "+ TargetSDK[0].decode("utf-8"))
                print("[+] Minimum SDK: "+ MinSdk[0].decode("utf-8"))
                if allowbackup:
                    print('[+] allowBackup value: '+ allowbackup[0].decode("utf-8"))
                else:
                    print('[+] allowBackup: False')   
                print("Permissions: ")
                for i in Permissions:
                    print("[+] " + i.decode("utf-8"))
                print("Activites:")
                for i in Activites:
                    print("[+] " + i.decode("utf-8"))
                print("Exported Activites:")
                for i in ExportedActivites:
                    print("[+] " + i.decode("utf-8"))
        except Exception as error:
            print("[-] Error parsing the AndroidManifest.xml file: ",error)
        
        try:
            with open("./apk_decomiled/res/values/strings.xml", 'rb') as f:
                    data = f.read()
            axml = AXMLPrinter(data)
            strings_xml = axml.get_xml() #TODO print strings.xml
        except Exception as error:
            print("[-] strings.xml Error: ",error)
        
            
        
    def CheckCertificate(self):
        print("Certificate Check:")
        a = APK(self.apk)
        print("APK is signed: {}".format(a.is_signed()))
        if a.is_signed():
    # Test if signed v1 or v2 or both
            print("[+] APK is signed with: {}".format("both V1 & V2" if a.is_signed_v1() and
            a.is_signed_v2() else "v1" if a.is_signed_v1() else "v2"))    
        
        certificates = a.get_certificates_v2()
        for cert in certificates:
            print("[+] Subject:", cert.subject)
            print("[+] Issuer:", cert.issuer)
            print("[+] Serial number:", cert.serial_number)
            print("[+] Not valid before:", cert.not_valid_before)
            print("[+] Not valid after:", cert.not_valid_after)
            print("[+] Signature algorithm:", cert.signature_algo)
            print("[+] Public key algorithm:", cert.hash_algo)
         
            
test = Mobile_analysis("./test.apk")
# test.decompiling()
# test.CheckCertificate()

test.Decompiler()