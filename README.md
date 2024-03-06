## ExtPenPy is A tool that will help you finishing your recon phase faster.

### Objectives:

### In three modes:

1. **Passive**:
    - Collecting Subdomains (without brute forcing)
    - Whois database check
    - Zone Transfer
    - DNS records check
    - Reverse DNS Lookup
    - IP addresses range
    - Regex to Google Dork
2. **Active:** 
    - Collecting  subdomains (with brute forcing)
    - All the passive stuff
    - Cloud enumeration
    - Web Crawling
    - Headers check
    - Taking screenshots
3. **APK:**
    - Collecting URL’s
    - Root Detection Check
    - SDK Version Check
    - Decompiling APK to smali and java
    - Extracting Sensitive information like API keys, passwords, etc..
    - Debuggable mode Check
    - Checking permissions
    - Checking activities and (Exported Activities)
    - Check if backup is allowed
    - collecting strings.xml files

### Installation:

```bash
git clone https://github.com/maliktawfiq/ExtPenPy.git
cd ExtPenPy
pip install -r requierments.txt
```

### how to use:

```bash
python3 ExtPenPy -h
```

![Untitled](imgs/Untitled.png)

```bash
python3 ExtPenPy passive -d uber.com
```

![Untitled](imgs/Untitled%201.png)

**you can add —csv to save the subdomains in csv file.**

```bash
python3 passive -d uber.com --csv ./subdomains
```

![Untitled](imgs/Untitled%202.png)
