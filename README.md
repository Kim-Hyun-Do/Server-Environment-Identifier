# Server Environment Identifier
It checks target ip whether to use which framework and software. The purpose of this tool is to check the target ip in a local environment, so it was created based on local standards(It is also available remote environment? Maybe?). Also, it can only check Apache, Tomcat, Spring, PHP. 


## Pipeline
![화면 캡처 2024-12-22 235603](https://github.com/user-attachments/assets/05bf6786-e23f-4cee-bbb7-d5084526ac65)




The environment_identifier.py is on lemma(https://github.com/sleepyeinstein/lemma) and starter.py executes the lemma and streams the result.

## Usage
1. Make your lemma url there is environment_identifier.py as lemma usage(https://github.com/sleepyeinstein/lemma)
![web cli](https://github.com/user-attachments/assets/99671c22-b6f4-4d8b-adf6-213f126f2eec)
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
![terminal1](https://github.com/user-attachments/assets/eb539818-9950-4950-ac9f-8c7cc793786b)
![terminal2](https://github.com/user-attachments/assets/8c89aa18-f15c-4460-82c3-2fa0716f1884)







