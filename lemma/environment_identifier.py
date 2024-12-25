#!/usr/bin/env python3

import argparse
import subprocess
import re
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

class Runner:
    def __init__(self):
        super().__init__()
        self.run_list = []
    
    def add_list(self, func):
        self.run_list.append(func)
    
    def run(self, target):
        for func in self.run_list:
            func(target) 

    
runner_apache = Runner()
class Apache_Scanner:
    def __init__(self, host):
        self.host = host  
        
    @runner_apache.add_list        
    def directory_scan(self):
        dir_list = ["directory", ".htaccess", "server-status", "server-info", ""]
        try:
            print("[*] Apache directroy scanning....")########수정
            for directory in dir_list:
                response = requests.get(f"http://{self.host}/{directory}", timeout=10)
                result = re.search(r'Apache/[\d.]+ \([^)]+\)', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    break
        except requests.exceptions.Timeout:
            print("[!] Apache directory scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Apache directory scanning error occured: {e}") 
     
    @runner_apache.add_list
    def server_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]########수정
        try:
            print("[*] Apache server header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match = re.search(r'Apache/[\d.]+\s+\([^)]+\)', result.stdout)
                if match:
                    print(f"[+] Detected Apache Version : ")
                    print(match.group(0))
                    #return match.group(0)          
        except subprocess.TimeoutExpired:
            print(f"[!] Apache server header scanning timeout!!")
        except Exception as e:
            print(f"[!] Apache server header scanning error occurred: {e}") 

    @runner_apache.add_list
    def xampp_scan(self):
        try:
            print("[*] xampp existing scanning....")
            response = requests.get(f"http://{self.host}/dashboard/", timeout=10)
            if response.status_code == 200 and "Welcome to XAMPP" in response.text:
                print("[+] xampp using apache server detected!!")
        except requests.exceptions.Timeout:
            print("[!] xampp existing scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] xampp existing scanning error occured: {e}")

    @runner_apache.add_list
    def ofbiz_scan(self):
        try:
            print("[*] Apache OFBiz existing scanning....")
            response = requests.get(f"http://{self.host}", timeout=10) 
            body_find = any(keyword in response.text for keyword in ["Apache OFBiz.", "OFBiz.Visitor="])
            header_find = any(keyword in str(response.headers.values()) for keyword in ["Apache OFBiz.", "OFBiz.Visitor="])
            if body_find or header_find:
                print("[+] Apache OFBiz detected!!")
        except requests.exceptions.Timeout:
            print("[!] Apache OFBiz existing scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Apache OFBiz existing scanning error occured: {e}")        
    
    @runner_apache.add_list
    def default_page_scan(self):
        try:
            print("[*] Apache default page existing scanning....")
            response = requests.get(f"http://{self.host}", timeout=10)
            if any(keyword in response.text for keyword in ["Apache HTTP Server Test Page", "Apache2 Ubuntu Default Page: It works"]):
                print("[+] Apache Server detected!!")
        except requests.exceptions.Timeout:
            print("[!] Apache default page existing scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Apache default page existing scanning error occured: {e}")                   


runner_tomcat = Runner()
class Tomcat_Scanner:
    def __init__(self, host):
        self.host = host

    @runner_tomcat.add_list
    def server_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Tomcat server header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match1 = re.search(r"Apache-Coyote/\d+(\.\d+)*", result.stdout)
                if match1:
                    print(f"[+] Detected Tomcat server header :")
                    print(match1.group(0))
                else:
                    match2 = re.findall(r'Tomcat[^;]+(?=\()', result.stdout)
                    if match2:
                        match2_to_list = [re.sub(r'(Server: |Servlet-Engine: )', '', header) for header in match2]
                        print(f"[+] Detected Tomcat server header :")
                        print("\n".join(match2_to_list))                      
        except subprocess.TimeoutExpired:
            print(f"[!] Tomcat server header scanning timeout!!")
        except Exception as e:
            print(f"[!] Tomcat server header scanning error occurred: {e}")  

    @runner_tomcat.add_list
    def directory_scan(self):
        dir_list = ["directory", "../"]
        try:
            print("[*] Tomcat directory scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.host}/{directory}", timeout=10)
                result = re.search(r'Apache Tomcat(?:/\d+\.\d+(?:\.\d+)?)?', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    break
        except requests.exceptions.Timeout:
            print("[!] Tomcat directory scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Tomcat directory scanning error occured: {e}")

    @runner_tomcat.add_list
    def stack_trace_scan(self):
        try:
            print("[*] Tomcat stack trace scanning....")
            response = requests.get(f"http://{self.host}/?f=\[", timeout=10)
            if response.status_code == 400:
                result = re.findall(r'org\.apache|tomcat', response.text)
                if result:
                    print("[+] Tomcat server detected!!")
        except requests.exceptions.Timeout:
            print("[!] Tomcat stack trace scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Tomcat stack trace scanning error occured: {e}")
            
    @runner_tomcat.add_list
    def manager_page_scan(self):
        dir_list = ["/host-manager/html", "/manager/status", "/manager/html", "/docs/", "/examples/", "/..;/manager/html", "/..;/..;/manager/html;/", "/..;/host-manager/html", "/..;/..;/host-manager/html;/", "/1234/..;/manager/html", "/1234/..;/host-manager/html"]
        success_dirs = []
        extract_list = [r"(?i)(apache\s+tomcat|tomcat-users\.xml)", r"Version\s+([0-9.]+),", r"(?i)/lib/([a-z0-9.]+)/webapps", r"(?i)<h3>Apache\s+Tomcat/([0-9.]+)" ]
        base64_auth_headers = ["dG9tY2F0OnRvbWNhdA==", "dG9tY2F0OnMzY3JldA==", "YWRtaW46YWRtaW4="] #admin:admin, tomcat:s3cret, tomcat:tomcat

        
        find = False
        print("[*] Tomcat manager page scanning....")
        for directory in dir_list:
            try:
                response = requests.get(f"http://{self.host}{directory}", timeout=10)
                if response.status_code == 200:
                    for pattern in extract_list:
                        result = re.findall(pattern, response.text)
                        success_dirs.extend(result)
                elif response.status_code == 401:
                    find = True
                    for header in base64_auth_headers:
                        res = requests.get(f"http://{self.host}{directory}", headers={"Authorization" : f"Basic {header}"} , timeout=10)
                        if res.status_code == 200:
                            for pattern in extract_list:
                                result_auth = re.findall(pattern, res.text)
                                success_dirs.extend(result_auth)
                            break 
            except requests.exceptions.Timeout:
                print("[!] Tomcat manage page scanning timeout!!")
            except requests.RequestException as e:
                print(f"[!] Tomcat manage page scanning error occured: {e}")  
                              
        if success_dirs:
            success_dirs = list(set(success_dirs))
            print("[+] Tomcat manager page scan result : ")
            for directory in success_dirs:
                print(directory)
        elif find:
            print("[+] Tomcat server detected!!")

                    

runner_spring = Runner()
class Spring_Scanner:
    def __init__(self, host):
        self.host = host
    
    #Spring Boot, Spring framework detect
    @runner_spring.add_list
    def error_page_scan(self):
        try:
            print("[*] Spring error page scanning....")
            res_boot = requests.get(f"http://{self.host}/directory", timeout=10)
            res_framework = requests.get(f"http://{self.host}", timeout=10)
            
            result_boot = re.search(r'Whitelabel\s+Error\s+Page', res_boot.text)
            result_framework = re.search("org.springframework.web.servlet", res_framework.text)
            
            if result_boot:
                print("[+] Spring Boot detected!!")
            elif result_framework:
                print("[+] Spring framework detected!!")
        except requests.exceptions.Timeout:
            print("[!] Spring error page scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Spring error page scanning error occured: {e}")        

    #Spring Boot detect
    @runner_spring.add_list
    def actuator_scan(self):
        try:
            print("[*] Spring actuator directory scanning....")
            response = requests.get(f"http://{self.host}/actuator", timeout=10)
            if response.status_code == 200:
                print("[+] Spring Boot detected!!")
                #print(response.text)
        except requests.exceptions.Timeout:
            print("[!] Spring actuator scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Spring actuator scanning error occured: {e}")
        
    #Spring Framework detect
    @runner_spring.add_list
    def powered_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Spring powered header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match_boot = re.search(r"X-Powered-By:\s*(SpringBoot|Spring Boot)\s*(\d+\.\d+\.\d+)?", result.stdout)
                if match_boot:
                    print(f"[+] Spring Boot detected : ")
                    print(match_boot.group(0))
                else:
                    match_frame = re.search(r'X-Powered-By:\s*Spring\b', result.stdout)
                    if match_frame:
                        print(f"[+] Spring Framework detected!!")
        except subprocess.TimeoutExpired:
            print(f"[!] Spring powered header scanning timeout!!")
        except Exception as e:
            print(f"[!] Spring powered header scanning error occurred: {e}")    
    
    #Spring Security detect
    @runner_spring.add_list
    def auth_header_scan(self): 
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Spring authenticate header scanning....") ## 수정
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match1 = re.search(r'WWW-Authenticate:\s*Basic\s+realm="Spring"', result.stdout)
                match2 = re.search(r'WWW-Authenticate:\s*Bearer', result.stdout)              
                if match1 or match2:
                    print(f"[+] Spring Security detected!!")
                    #return match1 or match2
        except subprocess.TimeoutExpired:
            print(f"[!] Spring authenticate header scanning timeout!!")
        except Exception as e:
            print(f"[!] Spring authenticate header scanning error occurred: {e}")
    
    #Spring framework detect
    @runner_spring.add_list
    def cookie_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Spring cookie header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            print(result.stdout)
            if result.returncode == 0: 
                match = re.search("org.springframework.web.servlet", result.stdout)
                if match:
                    print(f"[+] Spring framework detected!!")
                    #return match
        except subprocess.TimeoutExpired:
            print(f"[!] Spring cookie header scanning timeout!!")
        except Exception as e:
            print(f"[!] Spring cookie header scanning error occurred: {e}")       
    
    #Spring Boot detect
    @runner_spring.add_list
    def xml_dir_scan(self):
        try:
            print("[*] Spring xml directory scanning....")
            res_web = requests.get(f"http://{self.host}/web.xml", timeout=10)
            res_pom = requests.get(f"http://{self.host}/POM.xml", timeout=10)
            
            result_web = re.search("SpringBoot", res_web.text)
            result_pom = re.searh("org.springframework.boot", res_pom.text)
            if result_pom or result_web:
                print(f"[+] Spring Boot detected!!")
        except subprocess.TimeoutExpired:
            print(f"[!] Spring Boot scanning timeout!!")
        except Exception as e:
            print(f"[!] Spring Boot scanning error occurred: {e}")    
    
    @runner_spring.add_list
    def body_script_scan(self):
        try:
            print("[*] Spring body script scanning....")
            response = requests.get(f"http://{self.host}", timeout=10)
            result = re.search("Spring Boot", response.text)
            if result:
                print(f"[+] Spring Boot detected!!")
        except subprocess.TimeoutExpired:
            print(f"[!] Spring Boot scanning timeout!!")
        except Exception as e:
            print(f"[!] Spring Boot scanning error occurred: {e}")                  

runner_php = Runner()
class PHP_Scanner:
    def __init__(self, host):
        self.host = host
    
    @runner_php.add_list
    def response_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] PHP response header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                matches = re.findall(r'PHP/\d+\.\d+\.\d+', result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    print("\n".join(matches))
        except subprocess.TimeoutExpired:
            print(f"[!] PHP response header scanning timeout!!")
        except Exception as e:
            print(f"[!] PHP response header scanning error occurred: {e}")
    
    @runner_php.add_list
    def warning_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] PHP warning header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: [^\n]*(?:\n\s+.*?)*", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    print("\n".join(matches))
        except subprocess.TimeoutExpired:
            print(f"[!] PHP warning header scanning timeout!!")
        except Exception as e:
            print(f"[!] PHP warning header scanning error occurred: {e}")
    
    @runner_php.add_list
    def warning_body_scan(self):
        command = ["curl", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] PHP warning body scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: [^\n]*(?:\n\s+.*?)*", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    print("\n".join(matches))
        except subprocess.TimeoutExpired:
            print(f"[!] PHP warning body scanning timeout!!")
        except Exception as e:
            print(f"[!] PHP warning body scanning error occurred: {e}")
    
    @runner_php.add_list
    def php_cookie_scan(self):     
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] PHP cookie header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match = re.search(r"PHPSESSID=([^;]+)", result.stdout)
                if match:
                    print(f"[+] PHP detected: ")
                    print(match.group(0))
                    #return match.group(0)
        except subprocess.TimeoutExpired:
            print(f"[!] PHP cookie header scanning timeout!!")
        except Exception as e:
            print(f"[!] PHP cookie header scanning error occurred: {e}")                                                                                                      
    
    @runner_php.add_list
    def robots_directory_scan(self):
        try:
            print("[*] PHP robots directory scanning....")
            response = requests.get(f"http://{self.host}/robots.txt", timeout=10)
            matches = re.findall(r"(/\S+\.php)", response.text) 
            if matches:
                print("[+] PHP detected: ")
                print("\n".join(matches))
        except requests.exceptions.Timeout:
            print("[!] PHP robots directory scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] PHP robots directory scanning error occurred: {e}") 

                    
def scan_result(host, fws):
    framework_map = {
        "apache": (Apache_Scanner, runner_apache),
        "tomcat": (Tomcat_Scanner, runner_tomcat),
        "spring": (Spring_Scanner, runner_spring),
        "php": (PHP_Scanner, runner_php),
    }
    
    if "all" in fws:
        fws = framework_map.keys()
          
    for fw in fws:
        fw = fw.lower()  
        if fw in framework_map:
            scanner_cls, runner = framework_map[fw]
            scanner = scanner_cls(host)
            runner.run(scanner)
            print("-" * 100)
        else:
            print(f"[!] Error: Unsupported framework '{fw}'")      

def port_scan(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception as e:
        print(f"[!] Error occured in scanning port {port}: {e}")

def available_port_scan(ip, port_range, fw):
    print(f"[+] Start port scanning : {ip}\n")
    futures = []
    with ThreadPoolExecutor(800) as executor:
        for port in range(10, int(port_range)):
            futures.append(executor.submit(port_scan, ip, port))
        
        for future in as_completed(futures):
            available_port = future.result()
            if available_port is not None:
                host = f"{ip}:{available_port}"
                print("-"*100)
                print(f"[+] Found host : {host}")
                scan_result(host, fw)

     
parser = argparse.ArgumentParser(usage="""environment_identifier.py --ip 12.34.56.789 --file /home/user/common.txt --port 1000 --framework spring php""")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--ip', '-i', help='Target server IP') 
group.add_argument('--file', '-f', help='Target server IPs with file')
parser.add_argument('--port', '-p', help='Port range to scan', required=False, default="10000")
parser.add_argument('--framework', '-fw', help='Choose frameworks for testing', nargs='+', choices=['apache', 'tomcat', 'spring', 'php'], required=False, default=['all'])
args = parser.parse_args()


if __name__ == "__main__":
    if args.ip:
        available_port_scan(args.ip, args.port, args.framework)
    elif args.file:
        try:
            with open(args.file, 'r') as file: 
                for line in file:
                    ip = line.strip()
                    available_port_scan(ip, args.port, args.framework)
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")
        except Exception as e:
            print(f"[!] Error occured: {e}")
    else:
        print("[!] Check your arguments!!")
