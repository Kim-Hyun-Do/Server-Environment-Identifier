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


def command_line(target, method):
    def command_header(target):
        c = ["curl", "-I", "-A", "Mozilla/5.0"]
        cmd = c + [f"{target}"]
        return cmd 
    
    def command_body(target):
        c = ["curl", "-A", "Mozilla/5.0"]
        cmd = c + [f"{target}"]
        return cmd 
    
    m = method.lower()
    if m == "header":
        return command_header(target)
    elif m == "body":
        return command_body(target)
    else:
        raise ValueError("Invalid method. Use 'header' or 'body'.")
    
    
runner_apache = Runner()
class Apache_Scanner:
    def __init__(self, host):
        self.host = host
        print("[Apache Scan Proccess]")    
        
    @runner_apache.add_list        
    def directory_scan(self):
        dir_list = ["directory", ".htaccess", "server-status", "server-info", ""]
        try:
            print("[*] directroy scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.host}/{directory}", timeout=5)
                result = re.search(r'Apache/[\d.]+ \([^)]+\)', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    break
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass
     
    @runner_apache.add_list
    def server_header_scan(self):
        try:
            print("[*] server header scanning....")
            cmd = command_line(f"http://{self.host}", "header")
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                match = re.search(r'Apache/[\d.]+\s+\([^)]+\)', result.stdout)
                if match:
                    print(f"[+] Detected Apache Version : ")
                    print(match.group(0))         
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

    @runner_apache.add_list
    def xampp_scan(self):
        try:
            print("[*] xampp existing scanning....")
            response = requests.get(f"http://{self.host}/dashboard/", timeout=5)
            if response.status_code == 200 and "Welcome to XAMPP" in response.text:
                print("[+] xampp using apache server detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass

    @runner_apache.add_list
    def ofbiz_scan(self):
        try:
            print("[*] Apache OFBiz existing scanning....")
            response = requests.get(f"http://{self.host}", timeout=5) 
            body_find = any(keyword in response.text for keyword in ["Apache OFBiz.", "OFBiz.Visitor="])
            header_find = any(keyword in str(response.headers.values()) for keyword in ["Apache OFBiz.", "OFBiz.Visitor="])
            if body_find or header_find:
                print("[+] Apache OFBiz detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass      
    
    @runner_apache.add_list
    def default_page_scan(self):
        try:
            print("[*] default page existing scanning....")
            response = requests.get(f"http://{self.host}", timeout=5)
            if any(keyword in response.text for keyword in ["Apache HTTP Server Test Page", "Apache2 Ubuntu Default Page: It works"]):
                print("[+] Apache Server detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass                 

runner_tomcat = Runner()
class Tomcat_Scanner:
    def __init__(self, host):
        self.host = host
        print("[Tomcat Scan Proccess]")

    
    @runner_tomcat.add_list
    def server_header_scan(self):
        try:
            print("[*] server header scanning....")
            cmd = command_line(f"http://{self.host}", "header")
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
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
            pass
        except Exception:
            pass

    @runner_tomcat.add_list
    def directory_scan(self):
        dir_list = ["directory", "../"]
        try:
            print("[*] directory scanning....")
            for directory in dir_list:
                response = requests.get(f"http://{self.host}/{directory}", timeout=5)
                result = re.search(r'Apache Tomcat(?:/\d+\.\d+(?:\.\d+)?)?', response.text)
                if result:
                    print("[+] Directory scan result : ")
                    print(result.group(0))
                    break
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass

    @runner_tomcat.add_list
    def stack_trace_scan(self):
        try:
            print("[*] stack trace scanning....")
            response = requests.get(rf"http://{self.host}/?f=\[", timeout=5)
            if response.status_code == 400:
                result = re.findall(r'org\.apache|tomcat', response.text)
                if result:
                    print("[+] Tomcat server detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass
            
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
                response = requests.get(f"http://{self.host}{directory}", timeout=5)
                if response.status_code == 200:
                    for pattern in extract_list:
                        result = re.findall(pattern, response.text)
                        success_dirs.extend(result)
                elif response.status_code == 401:
                    find = True
                    for header in base64_auth_headers:
                        res = requests.get(f"http://{self.host}{directory}", headers={"Authorization" : f"Basic {header}"} , timeout=5)
                        if res.status_code == 200:
                            for pattern in extract_list:
                                result_auth = re.findall(pattern, res.text)
                                success_dirs.extend(result_auth)
                            break 
            except requests.exceptions.Timeout:
                pass
            except requests.RequestException:
                pass
                              
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
        print("[Spring Scan Proccess]")
    
    #Spring Boot, Spring framework detect
    @runner_spring.add_list
    def error_page_scan(self):
        try:
            print("[*] error page scanning....")
            res_boot = requests.get(f"http://{self.host}/directory", timeout=5)
            res_framework = requests.get(f"http://{self.host}", timeout=5)
            
            result_boot = re.search(r'Whitelabel\s+Error\s+Page', res_boot.text)
            result_framework = re.search("org.springframework.web.servlet", res_framework.text)
            
            if result_boot:
                print("[+] Spring Boot detected!!")
            elif result_framework:
                print("[+] Spring framework detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass       

    #Spring Boot detect
    @runner_spring.add_list
    def actuator_scan(self):
        try:
            print("[*] actuator directory scanning....")
            response = requests.get(f"http://{self.host}/actuator", timeout=5)
            if response.status_code == 200:
                print("[+] Spring Boot detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass
    
    #Spring framework, Spring Security, Spring Boot detect
    @runner_spring.add_list
    def response_header_scan(self):
        try:
            print("[*] response header scanning....")
            cmd = command_line(f"http://{self.host}", "header")
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                #Spring Boot 
                match_boot = re.search(r"X-Powered-By:\s*(SpringBoot|Spring Boot)\s*(\d+\.\d+\.\d+)?", result.stdout)
                if match_boot:
                    print(f"[+] Spring Boot detected : ")
                    print(match_boot.group(0))
                
                #Spring Security 
                match_security1 = re.search(r'WWW-Authenticate:\s*Basic\s+realm="Spring"', result.stdout)
                match_security2 = re.search(r'WWW-Authenticate:\s*Bearer', result.stdout)              
                if match_security1 or match_security2:
                    print(f"[+] Spring Security detected!!")
                
                #Spring framework 
                match_framework1 = re.search("org.springframework.web.servlet", result.stdout)
                match_framework2 = re.search(r'X-Powered-By:\s*Spring\b', result.stdout)
                if match_framework1 or match_framework2:
                    print(f"[+] Spring framework detected!!")                   
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass                       
    
    #Spring Boot detect
    @runner_spring.add_list
    def xml_dir_scan(self):
        try:
            print("[*] xml directory scanning....")
            res_web = requests.get(f"http://{self.host}/web.xml", timeout=5)
            res_pom = requests.get(f"http://{self.host}/POM.xml", timeout=5)
            
            result_web = re.search("SpringBoot", res_web.text)
            result_pom = re.search("org.springframework.boot", res_pom.text)
            if result_pom or result_web:
                print(f"[+] Spring Boot detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass 
    
    #Spring Boot detect
    @runner_spring.add_list
    def body_script_scan(self):
        try:
            print("[*] response body script scanning....")
            response = requests.get(f"http://{self.host}", timeout=5)
            result = re.search("Spring Boot", response.text)
            if result:
                print(f"[+] Spring Boot detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass               

    # Spring Data, Spring Data REST detect
    @runner_spring.add_list
    def req_res_scan(self):
        try:
            print("[*] entities directory scanning....")
            response = requests.get(f"http://{self.host}/entities", timeout=5)
            if response.status_code == 200 and response.headers.get("Content-Type") == "application/json":
                print(f"[+] Spring DATA and Spring DATA REST detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass      
    
    # Spring Data REST detect
    @runner_spring.add_list
    def api_res_scan(self):
        try:
            print("[*] api response scanning....")
            response = requests.get(f"http://{self.host}/api", timeout=5)
            if response.status_code // 100 == 2:  
                content_type = response.headers.get("Content-Type", "")
                if content_type.startswith("application/json") and "_links" in response.json():
                    print("[+] Spring DATA REST detected!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass  
            

            
runner_php = Runner()
class PHP_Scanner:
    def __init__(self, host):
        self.host = host
        print("[PHP Scan Proccess]")
    
    @runner_php.add_list
    def warning_body_scan(self):
        try:
            print("[*] PHP warning body scanning....")
            cmd = command_line(f"http://{self.host}", "body")
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                matches = re.findall(r"PHP Warning: [^\n]*(?:\n\s+.*?)*", result.stdout)
                if matches:
                    print(f"[+] PHP detected: ")
                    print("\n".join(matches))
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass                                                                                            
    
    @runner_php.add_list
    def response_header_scan(self):
        try:
            print("[*] response header scanning....")
            cmd = command_line(f"http://{self.host}", "header")
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                #PHP version detect
                matches_version = re.findall(r'PHP/\d+\.\d+\.\d+', result.stdout)
                if matches_version:
                    print(f"[+] PHP version detected: ")
                    print("\n".join(matches_version))   
                
                #PHP warning header detect     
                matches_warning = re.findall(r"PHP Warning: [^\n]*(?:\n\s+.*?)*", result.stdout)
                if matches_warning:
                    print(f"[+] PHP warning header detected: ")
                    print("\n".join(matches_warning))  
                    
                #cookie header detect
                match_cookie = re.search(r"PHPSESSID=([^;]+)", result.stdout)
                if match_cookie:
                    print(f"[+] PHP cookie header detected: ")
                    print(match_cookie.group(0))                             
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass                                       
    
    
    @runner_php.add_list
    def robots_directory_scan(self):
        try:
            print("[*] robots directory scanning....")
            response = requests.get(f"http://{self.host}/robots.txt", timeout=5)
            matches = re.findall(r"(/\S+\.php)", response.text) 
            if matches:
                print("[+] PHP detected: ")
                print("\n".join(matches))
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass

    @runner_php.add_list
    def phpmyadmin_scan(self):
        try:
            print("[*] phpMyAdmin existing scanning....")
            cmd = command_line(f"http://{self.host}", "header")
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True)
            if result.returncode == 0:
                match1 = re.search(r"phpMyAdmin=([^;]+)", result.stdout)
                match2 = re.search(r"phpMyAdmin_https=([^;]+)", result.stdout)
                if match1 or match2:
                    print(f"[+] phpMyAdmin detected!!")
        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass                    
            
    @runner_php.add_list
    def directory_scan(self):
        try:
            directories = ["/phpinfo.php", "/test.php", "/info.php", "/php.ini"]
            success = []
            print("[*] directory exposure scanning....")
            for directory in directories:
                response = requests.get(f"http://{self.host}{directory}", timeout=5)
                if response.status_code == 200:
                    success.append(directory)
            if success:
                print(f"[+] PHP directory detected : ")
                print("\n".join(success))
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass           
    
    @runner_php.add_list
    def response_exposure_scan(self):
        try:
            print("[*] response exposure scanning....")
            response = requests.get(f"http://{self.host}", timeout=5)
            match1 = re.search(r"\.php", response.text)
            match2 = re.search(r"<!--.*?PHP.*?-->", response.text)
            if match1 or match2:
                print(f"[+] PHP detected in response exposure!!")
        except requests.exceptions.Timeout:
            pass
        except requests.RequestException:
            pass
                
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
                print(f"[+] Found host : {host}\n")
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
