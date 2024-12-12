#!/usr/bin/env python3

import argparse
import subprocess
import re
import requests


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
    def __init__(self, ip):
        self.ip = ip  
        
    @runner_apache.add_list        
    def directory_scan(self):
        dir_list = ["directory", ".htaccess", "server-status", ""]
        try:
            print("[*] Apache directroy scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.ip}/{directory}")
                result = re.search(r'Apache/[\d.]+ \([^)]+\)', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    return result.group(0)
        except requests.RequestException as e:
            return f"Request failed: {e}"
    
    @runner_apache.add_list
    def server_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", self.ip]
        try:
            print("[*] Apache server header scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r'Apache/[\d.]+\s+\([^)]+\)', result.stdout)
                if match:
                    print(f"[+] Detected Apache Version : ")
                    print(match.group(0))
            else:
                print("[-] Apache server header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}")       
    
runner_tomcat = Runner()
class Tomcat_Scanner:
    def __init__(self, ip):
        self.ip = ip

    @runner_tomcat.add_list
    def server_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        try:
            print("[*] Tomcat server header scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r"Apache-Coyote/\d+(\.\d+)*", result.stdout)
                if match:
                    print(f"[+] Detected Tomcat server header :")
                    print(match.group(0))
            else:
                print("[-] Tomcat server header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}") 

    @runner_tomcat.add_list
    def directory_scan(self):
        dir_list = ["directory", ""]
        try:
            print("[*] Tomcat directory scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.ip}/{directory}")
                result = re.search(r'Apache Tomcat/\d+\.\d+(\.\d+)?', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    return result.group(0)
        except requests.RequestException as e:
            print(f"Request failed: {e}")

    
runner_spring = Runner()
class Spring_Scanner:
    def __init__(self, ip):
        self.ip = ip  
    
    #Spring Boot detect
    @runner_spring.add_list
    def error_page_scan(self):
        try:
            print("[*] Spring error page scanning....")
            response = requests.get(f"http://{self.ip}/directory")
            result = re.search(r'Whitelabel\s+Error\s+Page', response.text)
            if result:
                print("[+] Spring Boot detected!!")
                return result.group(0)
        except requests.RequestException as e:
            return f"Request failed: {e}"
        
    #Spring Boot detect
    @runner_spring.add_list
    def actuator_scan(self):
        try:
            print("[*] Spring actuator directory scanning....")
            response = requests.get(f"http://{self.ip}/actuator")
            if response.status_code == 200:
                print("[+] Spring Boot detected!!")
                return result.group(0)
        except requests.RequestException as e:
            return f"Request failed: {e}"
        
    #Spring Framework detect
    @runner_spring.add_list
    def powered_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        try:
            print("[*] Spring powered header scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r"X-Powered-By:\s*Spring", result.stdout)
                if match:
                    print(f"[+] Spring Framework detected!!")
            else:
                print("[-] Spring powered header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}")     
    
    #Spring Security detect
    @runner_spring.add_list
    def auth_header_scan(self): 
        command_default = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        command_9080 = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}:9080"]
        try:
            print("[*] Spring authenticate header scanning....")
            result_default = subprocess.run(command_default, capture_output=True, text=True)
            result_9080 = subprocess.run(command_9080, capture_output=True, text=True)
            if result_default.returncode == 0 or result_9080.returncode == 0:
                match1 = re.search(r'WWW-Authenticate:\s*Basic\s+realm="Spring"', result_default.stdout)
                match2 = re.search(r'WWW-Authenticate:\s*Bearer', result_default.stdout)
                match3 = re.search(r'WWW-Authenticate:\s*Basic\s+realm="Spring"', result_9080.stdout)
                match4 = re.search(r'WWW-Authenticate:\s*Bearer', result_9080.stdout)               
                if match1 or match2 or match3 or match4:
                    print(f"[+] Spring Security detected!!")
            else:
                print("[-] Spring authenticate header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}")
            
runner_php = Runner()
class PHP_Scanner:
    def __init__(self, ip):
        self.ip = ip  
    
    @runner_php.add_list
    def response_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        try:
            print("[*] PHP response header scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                matches = re.findall(r'PHP/\d+\.\d+\.\d+', result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    for match in matches:
                        print(match)
            else:
                print("[-] PHP response header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}") 
    
    @runner_php.add_list
    def warning_header_scan(self):
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        try:
            print("[*] PHP warning header scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: .*?", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    for match in matches:
                        print(match)
            else:
                print("[-] PHP warning header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}")
    
    @runner_php.add_list
    def warning_body_scan(self):
        command = ["curl", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        try:
            print("[*] PHP warning body scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: .*?", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    for match in matches:
                        print(match)
            else:
                print("[-] PHP warning body scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}")
    
    @runner_php.add_list
    def php_cookie_scan(self):     
        command = ["curl", "-I", "-A", "Mozilla/5.0", f"http://{self.ip}"]
        try:
            print("[*] PHP cookie header scanning....")
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                match = re.search(r"PHPSESSID=([^;]+)", result.stdout)
                if match:
                    print(f"[+] PHP detected: ")
                    print(match.group(0))
            else:
                print("[-] PHP cookie header scan failed.")
                print("Error Output:")
                print(result.stderr)
        except Exception as e:
            print(f"[!] An error occurred: {e}")                                                                                                          
    
    @runner_php.add_list
    def robots_directory_scan(self):
        try:
            print("[*] PHP robots directory scanning....")
            response = requests.get(f"http://{self.ip}/robots.txt")
            matches = re.findall(r"(/\S+\.php)", response.text) 
            if matches:
                print("[+] PHP detected: ")
                for match in matches:
                    print(match)
                return result.group(0)
        except requests.RequestException as e:
            return f"Request failed: {e}"
        

   
parser = argparse.ArgumentParser(usage="""framework_classification.py --ip 12.34.56.789""")
parser.add_argument('--ip', '-i', help='Target server IP', required=True)
args = parser.parse_args()


if __name__ == "__main__":
    print(f"[O] Target IP: {args.ip}\n")
    apache_ = Apache_Scanner(args.ip)
    tomcat_ = Tomcat_Scanner(args.ip)
    spring_ = Spring_Scanner(args.ip)
    php_ = PHP_Scanner(args.ip)
    
    runner_apache.run(apache_)
    print("-"*100)
    runner_tomcat.run(tomcat_)
    print("-"*100)
    runner_spring.run(spring_)
    print("-"*100)
    runner_php.run(php_)
    
    
    
    
    
    



