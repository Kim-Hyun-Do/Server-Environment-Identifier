import subprocess
import sys

lemma_url = "Your lemma url\n"

print("[+] Setting Lambda URL to start Lemma\n")
start_lemma = subprocess.Popen(
    ["lemma", "-l"], 
    stdin=subprocess.PIPE,  
    stdout=subprocess.PIPE,  
    stderr=subprocess.PIPE,  
    text=True   
)
stdout, stderr = start_lemma.communicate(input=lemma_url)

print("[+] Executing Server Environment Identifier on lemma......")

command = ["lemma", "--", "environment_identifier.py"]
for arg in sys.argv[1:]:
    command.append(arg)
    
start_script = subprocess.Popen(
    command,  
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
result_stdout, result_stderr = start_script.communicate()


if start_script.returncode == 0:
    print("\n[+] Server Environment Identifier executing complete\n")
    print("Result")
    print("*"*100)
    print(result_stdout)
else:
    print("Error occured in Lemma executing:", result_stderr)
    sys.exit()
print("*"*100)
