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
        dir_list = ["directory", ".htaccess", "server-status", ""]
        try:
            print("[*] Apache directroy scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.host}/{directory}", timeout=10)
                result = re.search(r'Apache/[\d.]+ \([^)]+\)', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    #return result.group(0)
        except requests.exceptions.Timeout:
            print("[!] Apache directory scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Error occured: {e}")
    
    @runner_apache.add_list
    def server_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Apache server header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match = re.search(r'Apache/[\d.]+\s+\([^)]+\)', result.stdout)
                if match:
                    print(f"[+] Detected Apache Version : ")
                    print(match.group(0))
                    #return match.group(0)
            else:
                print("[-] Apache server header scan failed.")            
        except subprocess.TimeoutExpired:
            print(f"[!] Apache server header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")       
    
    
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
                match = re.search(r"Apache-Coyote/\d+(\.\d+)*", result.stdout)
                if match:
                    print(f"[+] Detected Tomcat server header :")
                    print(match.group(0))
                    #return match.group(0)
            else:
                print("[-] Tomcat server header scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] Tomcat server header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")  

    @runner_tomcat.add_list
    def directory_scan(self):
        dir_list = ["directory", ""]
        try:
            print("[*] Tomcat directory scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.host}/{directory}", timeout=10)
                result = re.search(r'Apache Tomcat/\d+\.\d+(\.\d+)?', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    #return result.group(0)
        except requests.exceptions.Timeout:
            print("[!] Tomcat directory scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Error occured: {e}")

    
runner_spring = Runner()
class Spring_Scanner:
    def __init__(self, host):
        self.host = host
    
    #Spring Boot detect
    @runner_spring.add_list
    def error_page_scan(self):
        try:
            print("[*] Spring error page scanning....")
            response = requests.get(f"http://{self.host}/directory", timeout=10)
            result = re.search(r'Whitelabel\s+Error\s+Page', response.text)
            if result:
                print("[+] Spring Boot detected!!")
                #return result.group(0)
        except requests.exceptions.Timeout:
            print("[!] Spring error page scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Error occured: {e}")
        
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
            print(f"[!] Error occured: {e}")
        
    #Spring Framework detect
    @runner_spring.add_list
    def powered_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Spring powered header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match = re.search(r"X-Powered-By:\s*Spring", result.stdout)
                if match:
                    print(f"[+] Spring Framework detected!!")
                    #return match
            else:
                print("[-] Spring powered header scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] Spring powered header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")    
    
    #Spring Security detect
    @runner_spring.add_list
    def auth_header_scan(self): 
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] Spring authenticate header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                match1 = re.search(r'WWW-Authenticate:\s*Basic\s+realm="Spring"', result.stdout)
                match2 = re.search(r'WWW-Authenticate:\s*Bearer', result.stdout)              
                if match1 or match2:
                    print(f"[+] Spring Security detected!!")
                    #return match1 or match2
            else:
                print("[-] Spring authenticate header scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] Spring authenticate header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")
            
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
                    for match in matches:
                        print(match)
            else:
                print("[-] PHP response header scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] PHP response header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")
    
    @runner_php.add_list
    def warning_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] PHP warning header scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: .*?", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    for match in matches:
                        print(match)
            else:
                print("[-] PHP warning header scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] PHP warning header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")
    
    @runner_php.add_list
    def warning_body_scan(self):
        command = ["curl", "-A", "Mozilla/5.0", f"http://{self.host}"]
        try:
            print("[*] PHP warning body scanning....")
            result = subprocess.run(command, capture_output=True, timeout=10, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: .*?", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    for match in matches:
                        print(match)
            else:
                print("[-] PHP warning body scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] PHP warning body scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")
    
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
            else:
                print("[-] PHP cookie header scan failed.")
        except subprocess.TimeoutExpired:
            print(f"[!] PHP cookie header scanning timeout!!")
        except Exception as e:
            print(f"[!] Error occurred: {e}")                                                                                                      
    
    @runner_php.add_list
    def robots_directory_scan(self):
        try:
            print("[*] PHP robots directory scanning....")
            response = requests.get(f"http://{self.host}/robots.txt", timeout=10)
            matches = re.findall(r"(/\S+\.php)", response.text) 
            if matches:
                print("[+] PHP detected: ")
                for match in matches:
                    print(match)
        except requests.exceptions.Timeout:
            print("[!] PHP robots directory scanning timeout!!")
        except requests.RequestException as e:
            print(f"[!] Error occurred: {e}") 

                    
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
        
        
    

