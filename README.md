# Server Environment Identifier
It checks target ip whether to use which framework and software. The purpose of this tool is to check the target ip in a local environment, so it was created based on local standards(It is also available remote environment? Maybe?). Also, it can only check Apache, Tomcat, Spring, PHP. 


## Pipeline
![화면 캡처 2024-12-22 235603](https://github.com/user-attachments/assets/05bf6786-e23f-4cee-bbb7-d5084526ac65)




The environment_identifier.py is on lemma(https://github.com/sleepyeinstein/lemma) and starter.py executes the lemma and streams the result.

## Usage
1. Make your lemma url there is environment_identifier.py as lemma usage(https://github.com/sleepyeinstein/lemma)
![lemma result_up](https://github.com/user-attachments/assets/ec6631b4-cfa6-4202-acb7-001fea61ae21)
2. Input your lemma url in starter.py source code.
3. Start starter.py!!

```
options:
  -i, --ip            Target server IP (ip or file)
  -f, --file          Target server IPs with file (ip or file)
  -p, --port          Port range to scan, default="10000"
  -fw, --framework    Choose frameworks for testing, choices=['apache', 'tomcat', 'spring', 'php'], default=['all']
  ```

## Result
![ip only result_up](https://github.com/user-attachments/assets/40d998eb-fd5d-4678-a4ea-34f0174ba77c)
![choose framework_up](https://github.com/user-attachments/assets/8ddc8b28-ac5d-4c32-a4f4-d199224bf25d)





