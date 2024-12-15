import subprocess

lemma_url = "Your lemma url"

print("[+] Setting Lamda URL to start Lemma\n")
start_lemma = subprocess.Popen(
    ["lemma", "-l"], 
    stdin=subprocess.PIPE,  
    stdout=subprocess.PIPE,  
    stderr=subprocess.PIPE,  
    text=True   
)
stdout, stderr = start_lemma.communicate(input=lemma_url)

ip = input("IP to check framework(port available) : ")
print("\n[+] Framework classifying......")
start_script = subprocess.Popen(
    f"lemma -- Framework_classification_lemma.py --ip {ip}",
    shell=True,  
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)
result_stdout, result_stderr = start_script.communicate()


if start_script.returncode == 0:
    print("\n[+] Framework classifying success!!\n")
    print("-"*100)
    print(result_stdout)
else:
    print("Error occured in Lemma executing:", result_stderr)

print("Checking framework finish!!")
